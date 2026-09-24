import {
  BadRequestException,
  Injectable,
  Logger,
  Optional,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ProofStatus } from "@prisma/client";
import { createHmac } from "crypto";
import { z } from "zod";
import { canonicalize } from "../common/crypto/canonicalize";
import {
  CredentialSigningKeyringService,
  versionFromKeyId,
} from "../common/crypto/credential-signing-keyring.service";
import { sha256 } from "../common/crypto/hash";
import { safeEqual } from "../common/crypto/timing-safe";
import { PrismaService } from "../database/prisma.service";
import { ContractAnchoringService } from "../proofs/contract-anchoring.service";

const MAX_PAYLOAD_BYTES = 32 * 1024; // 32 KB
const MAX_DEPTH = 5;
const SUPPORTED_SCHEMA_VERSION = "earnproof.minimum-income.v1";
const SUPPORTED_TYPE = "EarnProofMinimumIncomeCredential";

// ---------------------------------------------------------------------------
// Response type
// ---------------------------------------------------------------------------

export type VerifyCredentialResult =
  | "valid"
  | "invalid_signature"
  | "unsupported_schema"
  | "unsupported_key"
  | "unknown_anchor"
  | "revoked"
  | "expired"
  | "unverified_issuer";

export interface VerifyCredentialResponse {
  result: VerifyCredentialResult;
}

// ---------------------------------------------------------------------------
// Zod schema for minimum-income credential shape
// ---------------------------------------------------------------------------

const MinimumIncomeCredentialSchema = z.object({
  id: z.string().min(1),
  type: z.literal(SUPPORTED_TYPE),
  schemaVersion: z.literal(SUPPORTED_SCHEMA_VERSION),
  issuer: z.literal("earnproof-backend"),
  subject: z.object({
    walletHash: z.string().min(1),
  }).strict(),
  claim: z.object({
    operator: z.string().min(1),
    thresholdAmount: z.string().min(1),
    assetCode: z.string().min(1),
    assetIssuer: z.string().nullable(),
    periodStart: z.string().min(1),
    periodEnd: z.string().min(1),
    qualifyingPaymentCount: z.number().int().nonnegative(),
  }).strict(),
  privacy: z.object({
    exactIncomeHidden: z.literal(true),
    sourceTransactionsHidden: z.literal(true),
  }).strict(),
  issuedAt: z.string().datetime({ offset: true }),
  expiresAt: z.string().datetime({ offset: true }),
  // The signature proof block appended when a credential is issued.
  // `keyId` is optional for backward compatibility: a credential issued
  // before key rotation existed has no keyId and is treated as signed by
  // key version 0.
  proof: z.object({
    type: z.literal("HMAC-SHA256"),
    keyId: z.string().min(1).optional(),
    credentialHash: z.string().min(1),
    signature: z.string().min(1),
  }).strict(),
}).strict();

type MinimumIncomeCredential = z.infer<typeof MinimumIncomeCredentialSchema>;

// ---------------------------------------------------------------------------
// Depth helper (mirrors the one in the DTO for symmetry)
// ---------------------------------------------------------------------------

function objectDepth(value: unknown, current = 0): number {
  if (value === null || typeof value !== "object") {
    return current;
  }
  const children = Array.isArray(value)
    ? value
    : Object.values(value as Record<string, unknown>);
  if (children.length === 0) return current + 1;
  return Math.max(...children.map((child) => objectDepth(child, current + 1)));
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

@Injectable()
export class CredentialsService {
  private readonly logger = new Logger(CredentialsService.name);
  private readonly signingKeyring: CredentialSigningKeyringService;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
    @Optional()
    private readonly anchoring?: ContractAnchoringService,
  ) {
    this.signingKeyring = new CredentialSigningKeyringService(configService);
  }

  async verifyCredential(
    raw: Record<string, unknown>,
  ): Promise<VerifyCredentialResponse> {
    // ------------------------------------------------------------------
    // 1. Size / depth guard
    // ------------------------------------------------------------------
    const payloadBytes = Buffer.byteLength(JSON.stringify(raw), "utf8");
    if (payloadBytes > MAX_PAYLOAD_BYTES) {
      throw new BadRequestException(
        `Credential payload must not exceed ${MAX_PAYLOAD_BYTES / 1024} KB`,
      );
    }

    if (objectDepth(raw) > MAX_DEPTH) {
      throw new BadRequestException(
        `Credential payload must not be nested deeper than ${MAX_DEPTH} levels`,
      );
    }

    // ------------------------------------------------------------------
    // 2. Schema / type check (fast early-exit, before any heavy work)
    // ------------------------------------------------------------------
    if (
      raw["schemaVersion"] !== SUPPORTED_SCHEMA_VERSION ||
      raw["type"] !== SUPPORTED_TYPE
    ) {
      return { result: "unsupported_schema" };
    }

    const submittedProof = raw["proof"];
    if (
      submittedProof !== null &&
      typeof submittedProof === "object" &&
      (submittedProof as Record<string, unknown>)["type"] !== "HMAC-SHA256"
    ) {
      return { result: "unsupported_key" };
    }

    // ------------------------------------------------------------------
    // 3. Shape validation via Zod
    // ------------------------------------------------------------------
    const parsed = MinimumIncomeCredentialSchema.safeParse(raw);
    if (!parsed.success) {
      throw new BadRequestException(
        `Credential is malformed: ${parsed.error.issues
          .map((i) => `${i.path.join(".")}: ${i.message}`)
          .join("; ")}`,
      );
    }

    const credential: MinimumIncomeCredential = parsed.data;

    // ------------------------------------------------------------------
    // 4. Canonicalize the credential body (exclude the proof block) and
    //    compute credentialHash
    // ------------------------------------------------------------------
    const { proof, ...credentialBody } = credential;
    const canonicalPayload = canonicalize(credentialBody);
    const credentialHash = `sha256:${sha256(canonicalPayload)}`;

    if (!safeEqual(credentialHash, proof.credentialHash)) {
      return { result: "invalid_signature" };
    }

    // ------------------------------------------------------------------
    // 5. Resolve the signing key by keyId (absent keyId => legacy version 0,
    //    pre-dating key rotation), then verify it is still usable and
    //    recompute the HMAC to compare timing-safely.
    // ------------------------------------------------------------------
    const keyVersion = proof.keyId ? versionFromKeyId(proof.keyId) : 0;

    if (keyVersion === null || !this.signingKeyring.isUsableForVerification(keyVersion)) {
      this.logger.log({
        event: "credential_verify",
        result: "unsupported_key",
        credentialHash,
        keyId: proof.keyId ?? "(legacy, no keyId)",
      });
      return { result: "unsupported_key" };
    }

    const signingSecret = this.signingKeyring.secretFor(keyVersion);
    if (!signingSecret) {
      // isUsableForVerification already checked the key is loaded, so this
      // only guards a race with a config reload; treat it the same way.
      return { result: "unsupported_key" };
    }

    const expectedSignature = `hmac-sha256:${createHmac("sha256", signingSecret)
      .update(canonicalPayload)
      .digest("base64url")}`;

    if (!safeEqual(expectedSignature, proof.signature)) {
      this.logger.log({
        event: "credential_verify",
        result: "invalid_signature",
        credentialHash,
      });
      return { result: "invalid_signature" };
    }

    // ------------------------------------------------------------------
    // 6. Database reconciliation
    // ------------------------------------------------------------------
    const record = await this.prisma.proof.findUnique({
      where: { credentialHash },
      select: {
        id: true,
        status: true,
        expiresAt: true,
        schemaVersion: true,
        contractTransactionHash: true,
      },
    });

    if (!record) {
      this.logger.log({
        event: "credential_verify",
        result: "unknown_anchor",
        credentialHash,
      });
      return { result: "unknown_anchor" };
    }

    if (record.status === ProofStatus.REVOKED) {
      this.logger.log({
        event: "credential_verify",
        result: "revoked",
        credentialHash,
      });
      return { result: "revoked" };
    }

    if (
      record.expiresAt <= new Date() ||
      new Date(credential.expiresAt) <= new Date()
    ) {
      this.logger.log({
        event: "credential_verify",
        result: "expired",
        credentialHash,
      });
      return { result: "expired" };
    }

    if (record.status !== ProofStatus.ACTIVE) {
      this.logger.log({
        event: "credential_verify",
        result: "unverified_issuer",
        credentialHash,
      });
      return { result: "unverified_issuer" };
    }

    if (record.contractTransactionHash && this.anchoring) {
      try {
        const anchor = await this.anchoring.getProofStatus(record.id);
        if (!anchor.checked) return { result: "unknown_anchor" };
        if (anchor.revoked) return { result: "revoked" };
        if (!anchor.valid) return { result: "unverified_issuer" };
      } catch {
        return { result: "unknown_anchor" };
      }
    }

    // ------------------------------------------------------------------
    // 7. All checks passed
    // ------------------------------------------------------------------
    this.logger.log({
      event: "credential_verify",
      result: "valid",
      credentialHash,
    });
    return { result: "valid" };
  }
}
