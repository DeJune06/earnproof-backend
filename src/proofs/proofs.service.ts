import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  Optional,
  UnprocessableEntityException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import {
  AnchoringOperation,
  AnchoringStatus,
  AttestationType,
  PaymentClassification,
  Proof,
  ProofClaim,
  Prisma,
  ProofStatus,
  ProofType,
  QuarantineDecision,
  RevocationActorType,
  RevocationReasonCode,
  ResourceStatus,
  VerificationResult,
  VerificationOutcome,
} from "@prisma/client";
import { createHmac, randomUUID } from "crypto";
import { VerificationEventService } from "../audit/verification-event.service";
import { AuthenticatedUser } from "../auth/auth.types";
import { canonicalAssetId } from "../common/assets/asset-identifier";
import { canonicalize } from "../common/crypto/canonicalize";
import { CredentialSigningKeyringService } from "../common/crypto/credential-signing-keyring.service";
import { CredentialVerificationKeyService } from "../common/crypto/credential-verification-key.service";
import { sha256 } from "../common/crypto/hash";
import { PaymentEncryptionKeyringService } from "../common/crypto/payment-encryption-keyring.service";
import { ApiErrorCode } from "../common/dto/api-error.dto";
import { PrismaService } from "../database/prisma.service";
import { OrganizationQuotaService } from "../quotas/organization-quota.service";
import { WebhookDeliveryService } from "../webhooks/webhook-delivery.service";
import { WebhookEventSource } from "../webhooks/webhook-event.types";
import { AttestationsService } from "../attestations/attestations.service";
import { WebhookDeliveryService } from "../webhooks/webhook-delivery.service";
import {
  AggregateEarningsCalculator,
} from "./aggregate-earnings.calculator";
import {
  AGGREGATE_EARNINGS_POLICY_VERSION,
  AggregationPolicyError,
  DEFAULT_ROUNDING_INCREMENT,
  ROUNDING_INCREMENTS,
  RoundingIncrement,
  SOURCE_SCOPES,
  SourceScope,
} from "./aggregate-earnings.policy";
  ProofVerificationAbuseService,
  VerificationClientContext,
} from "../common/rate-limit/proof-verification-abuse.service";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { CreateInvoiceSettlementProofDto } from "./dto/create-invoice-settlement-proof.dto";
import { CreateIncomeRangeProofDto } from "./dto/create-income-range-proof.dto";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";
import { CreatePaymentReceiptProofDto } from "./dto/create-payment-receipt-proof.dto";
import {
  CreateRecurringIncomeProofDto,
  IntervalUnit,
} from "./dto/create-recurring-income-proof.dto";
import { ListProofsDto } from "./dto/list-proofs.dto";
import { RevokeProofDto } from "./dto/revoke-proof.dto";
import { RenewProofDto } from "./dto/renew-proof.dto";
import {
  evaluateRenewalEligibility,
  evaluateSupersessionCompatibility,
  MAX_IDEMPOTENCY_KEY_LENGTH,
  RENEWAL_GRACE_PERIOD_DAYS,
  renewalRequestHash,
  SupersessionIncompatibility,
  wouldCreateCycle,
} from "./proof-renewal.policy";

const SCHEMA_VERSION = "earnproof.minimum-income.v1";
const PAYMENT_RECEIPT_SCHEMA_VERSION = "earnproof.payment-receipt.v1";
const RECURRING_INCOME_SCHEMA_VERSION = "earnproof.recurring-income.v1";
const INVOICE_SETTLEMENT_SCHEMA_VERSION = "earnproof.invoice-settlement.v1";
const INCOME_RANGE_SCHEMA_VERSION = "earnproof.income-range.v1";
const DEFAULT_EXPIRY_DAYS = 30;

const EMPLOYER_PERIOD_MESSAGES: Record<EmployerPaymentPeriodViolation, string> =
  {
    invalid_date: "periodStart and periodEnd must be valid dates",
    empty_or_inverted: "periodStart must be before periodEnd",
    too_long: `The period must not exceed ${MAX_EMPLOYER_PAYMENT_PERIOD_DAYS} days`,
    ends_in_future: "periodEnd must not be in the future",
  };

const CONTINUITY_WINDOW_MESSAGES: Record<ContinuityWindowViolation, string> = {
  invalid_date: "periodStart must be a valid date",
  not_period_aligned:
    "periodStart must be the first instant of a UTC calendar month",
  invalid_period_count: `observedPeriods must be an integer between ${MIN_CONTINUITY_PERIODS} and ${MAX_CONTINUITY_PERIODS}`,
  window_not_complete: "The observed window must have ended",
};

type MinimumIncomeCredential = {
  id: string;
  type: "EarnProofMinimumIncomeCredential";
  schemaVersion: string;
  issuer: "earnproof-backend";
  subject: {
    walletHash: string;
  };
  claim: {
    operator: "gte";
    thresholdAmount: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: string;
    periodEnd: string;
    qualifyingPaymentCount: number;
  };
  privacy: {
    exactIncomeHidden: true;
    sourceTransactionsHidden: true;
  };
  issuedAt: string;
  expiresAt: string;
};

type PaymentReceiptCredential = {
  id: string;
  type: "EarnProofPaymentReceiptCredential";
  schemaVersion: "earnproof.payment-receipt.v1";
  issuer: "earnproof-backend";
  subject: { walletHash: string };
  claim: {
    assetCode: string;
    assetIssuer: string | null;
    occurredAt: string;
    paymentReferenceHash: string;
    sourceAddress?: string;
    amount?: string;
  };
  privacy: { senderHidden: boolean; amountHidden: boolean };
  issuedAt: string;
  expiresAt: string;
};

type RecurringIncomeCredential = {
  id: string;
  type: "EarnProofRecurringIncomeCredential";
  schemaVersion: "earnproof.recurring-income.v1";
  issuer: "earnproof-backend";
  subject: { walletHash: string };
  claim: {
    cadence: string;
    intervalUnit: IntervalUnit;
    intervalCount: number;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: string;
    periodEnd: string;
    qualifyingPaymentCount: number;
  };
  privacy: {
    exactIncomeHidden: true;
    sourceTransactionsHidden: true;
  };
  issuedAt: string;
  expiresAt: string;
};

type InvoiceSettlementCredential = {
  id: string;
  type: "EarnProofInvoiceSettlementCredential";
  schemaVersion: "earnproof.invoice-settlement.v1";
  issuer: "earnproof-backend";
  subject: { walletHash: string };
  claim: {
    issuerId: string;
    assetCode: string;
    assetIssuer: string | null;
    occurredAt: string;
    invoiceReferenceHash: string;
    amount?: string;
  };
  privacy: { amountHidden: boolean };
type IncomeRangeCredential = {
  id: string;
  type: "EarnProofIncomeRangeCredential";
  schemaVersion: string;
  issuer: "earnproof-backend";
  subject: {
    walletHash: string;
  };
  claim: {
    operator: "range";
    lowerBound: string;
    upperBound: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: string;
    periodEnd: string;
    qualifyingPaymentCount: number;
  };
  privacy: {
    exactIncomeHidden: true;
    sourceTransactionsHidden: true;
  };
  issuedAt: string;
  expiresAt: string;
};

type EarnProofCredential =
  | MinimumIncomeCredential
  | PaymentReceiptCredential
  | RecurringIncomeCredential
  | InvoiceSettlementCredential;
  | IncomeRangeCredential;

type OwnedRenewableProof = Proof & {
  claim: ProofClaim | null;
  user: { walletHash: string };
  supersededBy: { id: string } | null;
};

function isUniqueViolation(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === "P2002"
  );
}

@Injectable()
export class ProofsService {
  private readonly signingKeyring: CredentialSigningKeyringService;
  private readonly paymentEncryptionKeyring: PaymentEncryptionKeyringService;
  private readonly stellarNetwork: string;
  private readonly anchoringEnabled: boolean;
  private readonly anchoringRequired: boolean;
  private readonly aggregateEarnings: AggregateEarningsCalculator;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
    private readonly verificationEventService: VerificationEventService,
    private readonly quotas: OrganizationQuotaService,
    private readonly attestationsService: AttestationsService,
    @Optional()
    private readonly contractAnchoringService?: ContractAnchoringService,
    @Optional()
    private readonly webhookDeliveryService?: WebhookDeliveryService,
    @Optional()
    private readonly credentialVerificationKeyService?: CredentialVerificationKeyService,
    private readonly verificationAbuseService?: ProofVerificationAbuseService,
  ) {
    this.signingKeyring = new CredentialSigningKeyringService(configService);
    this.paymentEncryptionKeyring = new PaymentEncryptionKeyringService(
      configService,
    );
    this.stellarNetwork = configService.getOrThrow<string>("stellar.network");
    this.anchoringEnabled =
      configService.get<boolean>("contractAnchoring.enabled") ?? false;
    this.anchoringRequired =
      configService.get<boolean>("contractAnchoring.required") ?? false;
    this.aggregateEarnings = new AggregateEarningsCalculator(
      prisma,
      (amountEncrypted) => this.paymentEncryptionKeyring.decrypt(amountEncrypted),
      this.signingSecret,
    );
  }

  /**
   * Re-validates asset eligibility against the LIVE SupportedAsset registry,
   * inside the same transaction that writes the Proof.
   *
   * `Payment.isEligible` is a cache populated by the last `syncPayments` run
   * and is only checked as a fast-path rejection before this method runs.
   * Between that cache being written and this transaction committing, a
   * concurrent sync or an admin action could deactivate the asset - so the
   * write path itself must be authoritative against the registry, not the
   * cached flag. If the asset is no longer active for this network, the
   * transaction is aborted and no Proof is written.
   *
   * On success, returns a durable snapshot of the policy that was found
   * active at this moment, to be stored on the Proof itself. Verification of
   * an already-issued proof must consult only this snapshot, never the live
   * registry, so that deactivating an asset later cannot retroactively
   * invalidate historical proofs.
   */
  private async requireActiveAssetPolicy(
    tx: Prisma.TransactionClient,
    asset: { code: string; issuer: string | null },
  ): Promise<{ assetPolicyId: string; assetPolicySnapshot: Prisma.InputJsonValue }> {
    const activeAsset = await tx.supportedAsset.findFirst({
      where: {
        code: asset.code,
        issuer: asset.issuer,
        network: this.stellarNetwork,
        status: ResourceStatus.ACTIVE,
      },
    });

    if (!activeAsset) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.ASSET_NOT_SUPPORTED,
        message:
          "Asset is not an active supported asset on this network and is not eligible for proof issuance",
      });
    }

    return {
      assetPolicyId: activeAsset.id,
      assetPolicySnapshot: {
        supportedAssetId: activeAsset.id,
        assetKey: activeAsset.assetKey,
        code: activeAsset.code,
        issuer: activeAsset.issuer,
        network: activeAsset.network,
        status: activeAsset.status,
        canonicalAssetId: canonicalAssetId({
          network: activeAsset.network,
          code: activeAsset.code,
          issuer: activeAsset.issuer,
        }),
        checkedAt: new Date().toISOString(),
      },
    };
  }

  async createPaymentReceiptProof(
    user: AuthenticatedUser,
    input: CreatePaymentReceiptProofDto,
  ) {
    const payment = await this.prisma.payment.findFirst({
      where: { id: input.paymentId, userId: user.id },
      select: {
        operationId: true,
        sourceAddress: true,
        sourceAddressEncrypted: true,
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        classification: true,
        isEligible: true,
        finalityHoldAt: true,
        occurredAt: true,
      },
    });

    if (!payment) {
      throw new NotFoundException({
        code: ApiErrorCode.PAYMENT_NOT_FOUND,
        message: "Payment not found",
      });
    }
    if (!payment.isEligible) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
        message: "Payment is not eligible for proof issuance",
      });
    }
    if (payment.finalityHoldAt) {
      // The ledger view this payment came from is unreconciled; issuing now
      // could commit to a payment the canonical ledger does not contain.
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
        message: "Payment is pending ledger reconciliation",
      });
    }
    if (payment.classification === PaymentClassification.EXCLUDED) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_EXCLUDED,
        message: "Payment is excluded from proof issuance",
      });
    }

    const senderHidden = input.discloseSender !== true;
    const amountHidden = input.discloseAmount !== true;
    // Decrypted only when the owner asked to disclose the sender.
    const sourceAddress = senderHidden
      ? undefined
      : this.revealPaymentSender(payment);
    const amount = amountHidden
      ? undefined
      : this.revealPaymentAmount(payment.amountEncrypted);
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );
    const proofId = randomUUID();
    const paymentReferenceHash = `sha256:${sha256(payment.operationId)}`;
    const credential = this.buildPaymentReceiptCredential({
      id: proofId,
      walletHash: user.walletHash,
      assetCode: payment.assetCode,
      assetIssuer: payment.assetIssuer,
      occurredAt: payment.occurredAt,
      paymentReferenceHash,
      senderHidden,
      amountHidden,
      sourceAddress,
      amount,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(credential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    const proof = await this.prisma.$transaction(async (tx) => {
      // Charged inside the issuing transaction: a rejected or failed issuance
      // consumes nothing, and concurrent requests cannot overshoot the quota.
      await this.quotas.consumeForUser(tx, user.id, "proof_requests");
      const assetPolicy = await this.requireActiveAssetPolicy(tx, {
        code: payment.assetCode,
        issuer: payment.assetIssuer,
      });

      const created = await tx.proof.create({
        data: {
          id: proofId,
          userId: user.id,
          proofType: ProofType.PAYMENT_RECEIPT,
          schemaVersion: PAYMENT_RECEIPT_SCHEMA_VERSION,
          status: ProofStatus.ACTIVE,
          network: this.stellarNetwork,
          assetCode: payment.assetCode,
          assetIssuer: payment.assetIssuer,
          assetPolicyId: assetPolicy.assetPolicyId,
          assetPolicySnapshot: assetPolicy.assetPolicySnapshot,
          periodStart: payment.occurredAt,
          periodEnd: payment.occurredAt,
          expiresAt,
          createdAt: now,
          credentialHash,
          commitment,
          claim: {
            create: {
              operator: "receipt",
              thresholdEncrypted: amountHidden
                ? null
                : payment.amountEncrypted,
              result: true,
              disclosurePolicy: {
                senderHidden,
                amountHidden,
                paymentReferenceHash,
                occurredAt: payment.occurredAt.toISOString(),
                ...(senderHidden ? undefined : { sourceAddress }),
              },
            },
          },
        },
        include: { claim: true },
      });

      if (this.anchoringEnabled) {
        await tx.anchoringIntent.create({
          data: {
            proofId: created.id,
            operation: AnchoringOperation.REGISTER,
            status: AnchoringStatus.PENDING,
          },
        });
      }

      return created;
    });

    const anchoringResult = this.anchoringEnabled
      ? { anchored: false as const, reason: "pending" as const }
      : { anchored: false as const, reason: "disabled" as const };

    this.emitProofCreated(user.id, proof);
    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchoringResult,
    };
  }

  /**
   * Issues an INVOICE_SETTLEMENT proof binding an external invoice reference
   * to exactly one confirmed (indexed, eligible, non-excluded) Stellar payment.
   *
   * Matching policy:
   *   - The payment must have arrived from a sourceAddress the caller has
   *     registered as an ACTIVE TrustedSource pointing at `input.issuerId`
   *     (this is the "issuer policy" check — see TrustedSourcesService).
   *   - assetCode/assetIssuer must match exactly.
   *   - If periodStart/periodEnd are given, occurredAt must fall inside them.
   *   - The payment must not already be bound to a different invoice-settlement
   *     proof (checked here as a fast-path; the hard guarantee is the DB unique
   *     constraint on ProofInvoiceSettlement.paymentId, enforced below).
   *   - Of the remaining candidates, the decrypted payment amount must equal
   *     `expectedAmount` EXACTLY. A lesser (partial) or greater (overpayment)
   *     amount is treated as a mismatch and excluded, not just a lesser one —
   *     this proof asserts a specific invoice was settled for a specific
   *     amount, so any deviation is not that invoice being settled.
   *   - Zero remaining candidates is rejected as "not found / unconfirmed".
   *   - More than one remaining candidate is rejected as "ambiguous" rather
   *     than silently picking one.
   *
   * The raw `invoiceReference` is normalized (trim, collapse whitespace,
   * case-fold) and immediately reduced to a SHA-256 commitment; the raw and
   * normalized values are never persisted, logged, or returned.
   */
  async createInvoiceSettlementProof(
    user: AuthenticatedUser,
    input: CreateInvoiceSettlementProofDto,
  ) {
    const normalizedReference = this.normalizeInvoiceReference(
      input.invoiceReference,
    );
    if (!normalizedReference) {
      throw new BadRequestException(
        "invoiceReference must not be empty after normalization",
      );
    }
    const invoiceReferenceHash = `sha256:${sha256(normalizedReference)}`;

    const periodStart = input.periodStart
      ? new Date(input.periodStart)
      : undefined;
    const periodEnd = input.periodEnd ? new Date(input.periodEnd) : undefined;
    if (periodStart && periodEnd && periodStart > periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    const issuer = await this.prisma.issuer.findUnique({
      where: { id: input.issuerId },
      select: { id: true, status: true },
    });
    if (!issuer || issuer.status !== ResourceStatus.ACTIVE) {
      throw new BadRequestException(
        "The specified issuer does not exist or is not active.",
      );
    }

    const existingSettlement =
      await this.prisma.proofInvoiceSettlement.findUnique({
        where: {
          issuerId_invoiceReferenceHash: {
            issuerId: input.issuerId,
            invoiceReferenceHash,
          },
        },
        select: { id: true },
      });
    if (existingSettlement) {
      throw new ConflictException({
        code: ApiErrorCode.INVOICE_REFERENCE_CONFLICT,
        message:
          "This invoice reference has already been settled for this issuer.",
      });
    }

    const trustedSources = await this.prisma.trustedSource.findMany({
      where: {
        userId: user.id,
        issuerId: input.issuerId,
        status: ResourceStatus.ACTIVE,
      },
      select: { sourceAddress: true },
    });

    if (trustedSources.length === 0) {
      throw new NotFoundException({
        code: ApiErrorCode.PAYMENT_NOT_FOUND,
        message:
          "No confirmed payment matches the requested issuer, asset, and amount.",
      });
    }

    const candidates = await this.prisma.payment.findMany({
      where: {
        userId: user.id,
        sourceAddress: { in: trustedSources.map((ts) => ts.sourceAddress) },
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer ?? null,
        isEligible: true,
        classification: { not: PaymentClassification.EXCLUDED },
        invoiceSettlement: null,
        occurredAt: {
          gte: periodStart,
          lte: periodEnd,
        },
      },
      select: {
        id: true,
        operationId: true,
        sourceAddress: true,
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        occurredAt: true,
      },
    });

    const expectedAmount = this.parseAmount(input.expectedAmount);
    const matches = candidates.filter((candidate) => {
      const amount = this.tryRevealProtectedAmount(candidate.amountEncrypted);
      return amount !== null && amount === expectedAmount;
    });

    if (matches.length === 0) {
      throw new NotFoundException({
        code: ApiErrorCode.PAYMENT_NOT_FOUND,
        message:
          "No confirmed payment matches the requested issuer, asset, and amount.",
      });
    }
    if (matches.length > 1) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_AMBIGUOUS_MATCH,
        message:
          "Multiple confirmed payments match the requested criteria; narrow the period window or amount.",
      });
    }

    const payment = matches[0];
    const amountHidden = input.discloseAmount !== true;
    const amount = amountHidden
      ? undefined
      : this.revealPaymentAmount(payment.amountEncrypted);
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );
    const proofId = randomUUID();
    const credential = this.buildInvoiceSettlementCredential({
      id: proofId,
      walletHash: user.walletHash,
      issuerId: input.issuerId,
      assetCode: payment.assetCode,
      assetIssuer: payment.assetIssuer,
      occurredAt: payment.occurredAt,
      invoiceReferenceHash,
      amountHidden,
      amount,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(credential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    let proof: Proof & { claim: ProofClaim | null };
    try {
      proof = await this.prisma.$transaction(async (tx) => {
        const created = await tx.proof.create({
          data: {
            id: proofId,
            userId: user.id,
            proofType: ProofType.INVOICE_SETTLEMENT,
            schemaVersion: INVOICE_SETTLEMENT_SCHEMA_VERSION,
            status: ProofStatus.ACTIVE,
            network: this.stellarNetwork,
            assetCode: payment.assetCode,
            assetIssuer: payment.assetIssuer,
            periodStart: payment.occurredAt,
            periodEnd: payment.occurredAt,
            expiresAt,
            createdAt: now,
            credentialHash,
            commitment,
            claim: {
              create: {
                operator: "settlement",
                thresholdEncrypted: amountHidden
                  ? null
                  : payment.amountEncrypted,
                result: true,
                disclosurePolicy: {
                  amountHidden,
                  invoiceReferenceHash,
                  issuerId: input.issuerId,
                  occurredAt: payment.occurredAt.toISOString(),
                },
              },
            },
          },
          include: { claim: true },
        });

        await tx.proofInvoiceSettlement.create({
          data: {
            proofId: created.id,
            paymentId: payment.id,
            issuerId: input.issuerId,
            invoiceReferenceHash,
          },
        });

        if (this.anchoringEnabled) {
          await tx.anchoringIntent.create({
            data: {
              proofId: created.id,
              operation: AnchoringOperation.REGISTER,
              status: AnchoringStatus.PENDING,
            },
          });
        }

        return created;
      });
    } catch (err) {
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === "P2002"
      ) {
        const target = Array.isArray(err.meta?.target)
          ? (err.meta?.target as string[])
          : [];
        if (target.includes("paymentId")) {
          throw new ConflictException({
            code: ApiErrorCode.PAYMENT_ALREADY_SETTLED,
            message:
              "This payment has already been used to settle a different invoice.",
          });
        }
        throw new ConflictException({
          code: ApiErrorCode.INVOICE_REFERENCE_CONFLICT,
          message:
            "This invoice reference has already been settled for this issuer.",
        });
      }
      throw err;
    }

    const anchoringResult = this.anchoringEnabled
      ? { anchored: false as const, reason: "pending" as const }
      : { anchored: false as const, reason: "disabled" as const };

    this.emitProofCreated(user.id, proof);
    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchoringResult,
    };
  }

  async listProofs(userId: string, input: ListProofsDto) {
    const issuedFrom = input.issuedFrom
      ? new Date(input.issuedFrom)
      : undefined;
    const issuedTo = input.issuedTo ? new Date(input.issuedTo) : undefined;
    if (issuedFrom && issuedTo && issuedFrom > issuedTo) {
      throw new BadRequestException("issuedFrom must be before issuedTo");
    }

    if (input.cursor) {
      const cursor = await this.prisma.proof.findFirst({
        where: { id: input.cursor, userId },
        select: { id: true },
      });
      if (!cursor) {
        throw new BadRequestException("Invalid proof cursor");
      }
    }

    const limit = input.limit ?? 20;
    const where: Prisma.ProofWhereInput = {
      userId,
      proofType: input.type,
      status: input.status,
      assetCode: input.assetCode,
      createdAt:
        issuedFrom || issuedTo ? { gte: issuedFrom, lte: issuedTo } : undefined,
    };
    const proofs = await this.prisma.proof.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(input.cursor ? { cursor: { id: input.cursor }, skip: 1 } : undefined),
    });
    const hasMore = proofs.length > limit;
    const page = hasMore ? proofs.slice(0, limit) : proofs;

    return {
      data: page.map((proof) => this.toHistoryItem(proof)),
      pageInfo: {
        hasMore,
        nextCursor: hasMore ? (page.at(-1)?.id ?? null) : null,
      },
    };
  }

  async getProofDetail(user: AuthenticatedUser, proofId: string) {
    const proof = await this.prisma.proof.findFirst({
      where:
        user.role === "ADMIN"
          ? { id: proofId }
          : { id: proofId, userId: user.id },
      include: { claim: true },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    return {
      ...this.toHistoryItem(proof),
      anchoring: await this.proofAnchoringDetail(proof),
      claim: this.claimSummary(proof.claim),
    };
  }

  async createMinimumIncomeProof(
    user: AuthenticatedUser,
    input: CreateMinimumIncomeProofDto,
  ) {
    const periodStart = new Date(input.periodStart);
    const periodEnd = new Date(input.periodEnd);

    if (periodStart > periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    const selectedPaymentIds = [...new Set(input.selectedPaymentIds)];
    const payments = await this.prisma.payment.findMany({
      where: {
        id: {
          in: selectedPaymentIds,
        },
        userId: user.id,
      },
      select: {
        id: true,
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        classification: true,
        isEligible: true,
        finalityHoldAt: true,
        occurredAt: true,
      },
    });

    if (payments.length !== selectedPaymentIds.length) {
      throw new BadRequestException(
        "One or more selected payments are invalid",
      );
    }

    for (const payment of payments) {
      if (
        payment.classification !== PaymentClassification.INCOME ||
        !payment.isEligible
      ) {
        throw new BadRequestException(
          "Selected payments must be eligible income payments",
        );
      }
      if (payment.finalityHoldAt) {
        throw new BadRequestException(
          "Selected payments are pending ledger reconciliation",
        );
      }

      if (
        payment.assetCode !== input.assetCode ||
        (payment.assetIssuer ?? null) !== (input.assetIssuer ?? null)
      ) {
        throw new BadRequestException(
          "Selected payments must use the requested asset",
        );
      }

      if (payment.occurredAt < periodStart || payment.occurredAt > periodEnd) {
        throw new BadRequestException(
          "Selected payments must fall inside the requested period",
        );
      }
    }

    const total = payments.reduce(
      (sum, payment) =>
        sum + this.revealProtectedAmount(payment.amountEncrypted),
      0n,
    );
    const threshold = this.parseAmount(input.thresholdAmount);

    if (total < threshold) {
      throw new BadRequestException(
        "Selected payments do not satisfy the minimum income threshold",
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );

    const proofId = randomUUID();
    const draftCredential = this.buildCredential({
      id: proofId,
      walletHash: user.walletHash,
      thresholdAmount: input.thresholdAmount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(draftCredential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    // Write Proof + ProofClaim + AnchoringIntent in a single transaction.
    // The intent is enqueued here (PENDING) even before any external call so
    // that a crash after this point is recoverable by the worker.
    const proof = await this.prisma.$transaction(async (tx) => {
      // Charged inside the issuing transaction: a rejected or failed issuance
      // consumes nothing, and concurrent requests cannot overshoot the quota.
      await this.quotas.consumeForUser(tx, user.id, "proof_requests");
      const assetPolicy = await this.requireActiveAssetPolicy(tx, {
        code: input.assetCode,
        issuer: input.assetIssuer ?? null,
      });

      const created = await tx.proof.create({
        data: {
          id: proofId,
          userId: user.id,
          proofType: ProofType.MINIMUM_INCOME,
          schemaVersion: SCHEMA_VERSION,
          status: ProofStatus.ACTIVE,
          network: this.stellarNetwork,
          assetCode: input.assetCode,
          assetIssuer: input.assetIssuer ?? null,
          assetPolicyId: assetPolicy.assetPolicyId,
          assetPolicySnapshot: assetPolicy.assetPolicySnapshot,
          periodStart,
          periodEnd,
          expiresAt,
          createdAt: now,
          credentialHash,
          commitment,
          claim: {
            create: {
              operator: "gte",
              thresholdEncrypted: this.protectAmount(input.thresholdAmount),
              result: true,
              disclosurePolicy: {
                exactIncomeHidden: true,
                sourceTransactionsHidden: true,
                qualifyingPaymentCount: payments.length,
              },
            },
          },
        },
        include: {
          claim: true,
        },
      });

      // Only enqueue an anchoring intent when anchoring is configured.
      if (this.anchoringEnabled) {
        await tx.anchoringIntent.create({
          data: {
            proofId: created.id,
            operation: AnchoringOperation.REGISTER,
            status: AnchoringStatus.PENDING,
          },
        });
      }

      return created;
    });

    const credential = this.buildCredential({
      id: proof.id,
      walletHash: user.walletHash,
      thresholdAmount: input.thresholdAmount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });

    // Anchoring is now async (handled by AnchoringWorkerService).
    // Return a "pending" anchoring status so callers know to poll verify later.
    const anchoringResult = this.anchoringEnabled
      ? { anchored: false as const, reason: "pending" as const }
      : { anchored: false as const, reason: "disabled" as const };

    this.emitProofCreated(user.id, proof);
    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchoringResult,
    };
  }

  async createIncomeRangeProof(
    user: AuthenticatedUser,
    input: CreateIncomeRangeProofDto,
  ) {
    const periodStart = new Date(input.periodStart);
    const periodEnd = new Date(input.periodEnd);

    if (periodStart > periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    const lowerBound = this.parseAmount(input.lowerBound);
    const upperBound = this.parseAmount(input.upperBound);

    if (lowerBound >= upperBound) {
      throw new BadRequestException(
        "lowerBound must be strictly less than upperBound",
      );
    }

    const selectedPaymentIds = [...new Set(input.selectedPaymentIds)];
    const payments = await this.prisma.payment.findMany({
      where: {
        id: {
          in: selectedPaymentIds,
        },
        userId: user.id,
      },
      select: {
        id: true,
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        classification: true,
        isEligible: true,
        occurredAt: true,
      },
    });

    if (payments.length !== selectedPaymentIds.length) {
      throw new BadRequestException(
        "One or more selected payments are invalid",
      );
    }

    for (const payment of payments) {
      if (
        payment.classification !== PaymentClassification.INCOME ||
        !payment.isEligible
      ) {
        throw new BadRequestException(
          "Selected payments must be eligible income payments",
        );
      }

      if (
        payment.assetCode !== input.assetCode ||
        (payment.assetIssuer ?? null) !== (input.assetIssuer ?? null)
      ) {
        throw new BadRequestException(
          "Selected payments must use the requested asset",
        );
      }

      if (payment.occurredAt < periodStart || payment.occurredAt > periodEnd) {
        throw new BadRequestException(
          "Selected payments must fall inside the requested period",
        );
      }
    }

    // Deterministic inclusion rule: the sum of the selected payments must
    // fall inside [lowerBound, upperBound], inclusive on both ends.
    const total = payments.reduce(
      (sum, payment) =>
        sum + this.revealProtectedAmount(payment.amountEncrypted),
      0n,
    );

    if (total < lowerBound || total > upperBound) {
      throw new BadRequestException(
        "Selected payments do not fall within the requested income range",
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );

    const proofId = randomUUID();
    const draftCredential = this.buildIncomeRangeCredential({
      id: proofId,
      walletHash: user.walletHash,
      lowerBound: input.lowerBound,
      upperBound: input.upperBound,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(draftCredential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    // Write Proof + ProofClaim + AnchoringIntent in a single transaction,
    // mirroring createMinimumIncomeProof's shared issuance pipeline. Only the
    // committed bounds are persisted — the summed total is never written.
    const proof = await this.prisma.$transaction(async (tx) => {
      const created = await tx.proof.create({
        data: {
          id: proofId,
          userId: user.id,
          proofType: ProofType.INCOME_RANGE,
          schemaVersion: INCOME_RANGE_SCHEMA_VERSION,
          status: ProofStatus.ACTIVE,
          network: this.stellarNetwork,
          assetCode: input.assetCode,
          assetIssuer: input.assetIssuer ?? null,
          periodStart,
          periodEnd,
          expiresAt,
          createdAt: now,
          credentialHash,
          commitment,
          claim: {
            create: {
              operator: "range",
              result: true,
              disclosurePolicy: {
                exactIncomeHidden: true,
                sourceTransactionsHidden: true,
                qualifyingPaymentCount: payments.length,
                lowerBound: input.lowerBound,
                upperBound: input.upperBound,
              },
            },
          },
        },
        include: {
          claim: true,
        },
      });

      if (this.anchoringEnabled) {
        await tx.anchoringIntent.create({
          data: {
            proofId: created.id,
            operation: AnchoringOperation.REGISTER,
            status: AnchoringStatus.PENDING,
          },
        });
      }

      return created;
    });

    const credential = this.buildIncomeRangeCredential({
      id: proof.id,
      walletHash: user.walletHash,
      lowerBound: input.lowerBound,
      upperBound: input.upperBound,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });

    const anchoringResult = this.anchoringEnabled
      ? { anchored: false as const, reason: "pending" as const }
      : { anchored: false as const, reason: "disabled" as const };

    this.emitProofCreated(user.id, proof);
    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchoringResult,
    };
  }

  async createRecurringIncomeProof(
    user: AuthenticatedUser,
    input: CreateRecurringIncomeProofDto,
  ) {
    const periodStart = new Date(input.periodStart);
    const periodEnd = new Date(input.periodEnd);
    if (periodStart >= periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    const intervals = this.buildRecurringIntervals(
      periodStart,
      periodEnd,
      input.intervalUnit,
      input.intervalCount,
    );
    const selectedPaymentIds = [...new Set(input.selectedPaymentIds)];
    const payments = await this.prisma.payment.findMany({
      where: { id: { in: selectedPaymentIds }, userId: user.id },
      select: {
        id: true,
        assetCode: true,
        assetIssuer: true,
        classification: true,
        isEligible: true,
        finalityHoldAt: true,
        occurredAt: true,
      },
    });

    if (payments.length !== selectedPaymentIds.length) {
      throw new BadRequestException(
        "One or more selected payments are invalid",
      );
    }

    for (const payment of payments) {
      if (
        payment.classification !== PaymentClassification.INCOME ||
        !payment.isEligible
      ) {
        throw new BadRequestException(
          "Selected payments must be eligible income payments",
        );
      }
      if (payment.finalityHoldAt) {
        throw new BadRequestException(
          "Selected payments are pending ledger reconciliation",
        );
      }
      if (
        payment.assetCode !== input.assetCode ||
        (payment.assetIssuer ?? null) !== (input.assetIssuer ?? null)
      ) {
        throw new BadRequestException(
          "Selected payments must use the requested asset",
        );
      }
      if (payment.occurredAt < periodStart || payment.occurredAt > periodEnd) {
        throw new BadRequestException(
          "Selected payments must fall inside the requested period",
        );
      }
    }

    const missingIntervals = intervals.filter(
      ([start, end]) =>
        !payments.some(
          (payment) =>
            payment.occurredAt >= start && payment.occurredAt <= end,
        ),
    );
    if (missingIntervals.length > 0) {
      throw new BadRequestException(
        `Recurring income proof unsatisfied: ${missingIntervals.length} of ${intervals.length} interval(s) contain no qualifying payment`,
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );
    const proofId = randomUUID();
    const cadence = `${input.intervalUnit}:${input.intervalCount}`;
    const draftCredential = this.buildRecurringIncomeCredential({
      id: proofId,
      walletHash: user.walletHash,
      cadence,
      intervalUnit: input.intervalUnit,
      intervalCount: input.intervalCount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(draftCredential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    const proof = await this.prisma.$transaction(async (tx) => {
      // Charged inside the issuing transaction: a rejected or failed issuance
      // consumes nothing, and concurrent requests cannot overshoot the quota.
      await this.quotas.consumeForUser(tx, user.id, "proof_requests");
      const assetPolicy = await this.requireActiveAssetPolicy(tx, {
        code: input.assetCode,
        issuer: input.assetIssuer ?? null,
      });

      const created = await tx.proof.create({
        data: {
          id: proofId,
          userId: user.id,
          proofType: ProofType.RECURRING_INCOME,
          schemaVersion: RECURRING_INCOME_SCHEMA_VERSION,
          status: ProofStatus.ACTIVE,
          network: this.stellarNetwork,
          assetCode: input.assetCode,
          assetIssuer: input.assetIssuer ?? null,
          assetPolicyId: assetPolicy.assetPolicyId,
          assetPolicySnapshot: assetPolicy.assetPolicySnapshot,
          periodStart,
          periodEnd,
          expiresAt,
          createdAt: now,
          credentialHash,
          commitment,
          claim: {
            create: {
              operator: "recurring",
              frequency: cadence,
              result: true,
              disclosurePolicy: {
                exactIncomeHidden: true,
                sourceTransactionsHidden: true,
                qualifyingPaymentCount: payments.length,
                intervalUnit: input.intervalUnit,
                intervalCount: input.intervalCount,
              },
            },
          },
        },
        include: { claim: true },
      });

      if (this.anchoringEnabled) {
        await tx.anchoringIntent.create({
          data: {
            proofId: created.id,
            operation: AnchoringOperation.REGISTER,
            status: AnchoringStatus.PENDING,
          },
        });
      }
      return created;
    });

    const credential = this.buildRecurringIncomeCredential({
      id: proof.id,
      walletHash: user.walletHash,
      cadence,
      intervalUnit: input.intervalUnit,
      intervalCount: input.intervalCount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });

    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: this.anchoringEnabled
        ? { anchored: false as const, reason: "pending" as const }
        : { anchored: false as const, reason: "disabled" as const },
    };
  }

  /**
   * Issues an aggregate-earnings proof through the shared proof pipeline.
   *
   * The aggregate is computed server-side from the caller's own eligible
   * income under the versioned policy in aggregate-earnings.policy.ts. Only
   * the floored aggregate, the payment count and the policy parameters are
   * committed; component payments, exact amounts and source identities are
   * not disclosed.
   */
  async createAggregateEarningsProof(
    user: AuthenticatedUser,
    input: CreateAggregateEarningsProofDto,
  ) {
    const sourceScope = input.sourceScope ?? "income";
    if (input.issuerIds && sourceScope !== "verified_issuers") {
      throw new BadRequestException({
        code: ApiErrorCode.INVALID_INPUT,
        message: "issuerIds is only allowed with sourceScope verified_issuers",
      });
    }
    const roundingIncrement = input.roundingIncrement ?? DEFAULT_ROUNDING_INCREMENT;

    const now = new Date();
    let computation;
    try {
      computation = await this.aggregateEarnings.compute(
        user.id,
        {
          assets: input.assets.map((asset) => ({
            code: asset.code,
            issuer: asset.issuer ?? null,
          })),
          periodStart: input.periodStart,
          periodEnd: input.periodEnd,
          sourceScope,
          issuerIds: input.issuerIds,
          roundingIncrement,
        },
        now,
      );
    } catch (error) {
      throw this.aggregationException(error);
    }

    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );
    const proofId = randomUUID();
    const credentialInput = {
      walletHash: user.walletHash,
      aggregateAmount: computation.disclosedAmount,
      roundingIncrement,
      assetCode: computation.asset.code,
      assetIssuer: computation.asset.issuer,
      periodStart: computation.period.start,
      periodEnd: computation.period.end,
      sourceScope,
      qualifyingPaymentCount: computation.paymentCount,
      policyVersion: computation.policyVersion,
    };
    const draftCredential = this.buildAggregateEarningsCredential({
      ...credentialInput,
      id: proofId,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(draftCredential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    const proof = await this.prisma.$transaction(async (tx) => {
      const created = await tx.proof.create({
        data: {
          id: proofId,
          userId: user.id,
          proofType: ProofType.AGGREGATE_EARNINGS,
          schemaVersion: AGGREGATE_EARNINGS_SCHEMA_VERSION,
          status: ProofStatus.ACTIVE,
          network: this.stellarNetwork,
          assetCode: computation.asset.code,
          assetIssuer: computation.asset.issuer,
          periodStart: computation.period.start,
          periodEnd: computation.period.end,
          expiresAt,
          createdAt: now,
          credentialHash,
          commitment,
          claim: {
            create: {
              operator: "sum",
              // The disclosed (floored) aggregate, which the credential
              // already makes public; the exact total is never stored.
              thresholdEncrypted: this.protectAmount(computation.disclosedAmount),
              result: true,
              disclosurePolicy: {
                exactIncomeHidden: true,
                sourceTransactionsHidden: true,
                sourceIdentitiesHidden: true,
                qualifyingPaymentCount: computation.paymentCount,
                policyVersion: computation.policyVersion,
                roundingIncrement,
                sourceScope,
                inputsDigest: computation.inputsDigest,
              },
            },
          },
        },
        include: { claim: true },
      });

      if (this.anchoringEnabled) {
        await tx.anchoringIntent.create({
          data: {
            proofId: created.id,
            operation: AnchoringOperation.REGISTER,
            status: AnchoringStatus.PENDING,
          },
        });
      }
      return created;
    });

    const credential = this.buildAggregateEarningsCredential({
      ...credentialInput,
      id: proof.id,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });

    this.emitProofCreated(user.id, proof);
    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: this.anchoringEnabled
        ? { anchored: false as const, reason: "pending" as const }
        : { anchored: false as const, reason: "disabled" as const },
    };
  }

  async revokeProof(user: AuthenticatedUser, proofId: string, body?: RevokeProofDto) {
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      select: {
        id: true,
        userId: true,
        status: true,
        contractTransactionHash: true,
        revokedAt: true,
        revokedByType: true,
        revocationReasonCode: true,
        revocationReasonPrivate: true,
        revocationEvidenceHash: true,
      },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    const isOwner = proof.userId === user.id;
    const isAdmin = user.role === "ADMIN";

    if (!isOwner && !isAdmin) {
      throw new ForbiddenException("Proof does not belong to this user");
    }

    // Idempotent: a proof already revoked keeps its original actor, reason,
    // and evidence. Re-issuing the same request must not let a second call
    // (racing worker, retried client) overwrite that record.
    if (proof.status === ProofStatus.REVOKED) {
      return {
        id: proof.id,
        status: proof.status,
        revokedAt: proof.revokedAt?.toISOString() ?? new Date().toISOString(),
        revokedByType: proof.revokedByType ?? RevocationActorType.OWNER,
        revocationReasonCode: proof.revocationReasonCode ?? RevocationReasonCode.OTHER,
        revocationReasonPrivate: proof.revocationReasonPrivate ?? null,
        revocationEvidenceHash: proof.revocationEvidenceHash ?? null,
        anchoring: { anchored: false as const, reason: "disabled" as const },
      };
    }

    const revokedByType = isAdmin && !isOwner ? RevocationActorType.ADMIN : RevocationActorType.OWNER;
    const reasonCode = body?.reasonCode ?? RevocationReasonCode.OWNER_REQUESTED;
    const revokedAt = new Date();

    // Write local revocation, the audit record, and the optional REVOKE
    // anchoring intent atomically: an untraceable revocation (state changed,
    // no audit row) is worse than a failed one.
    const updated = await this.prisma.$transaction(async (tx) => {
      const result = await tx.proof.update({
        where: { id: proof.id },
        data: {
          status: ProofStatus.REVOKED,
          revokedAt,
          revokedByType,
          revokedById: user.id,
          revocationReasonCode: reasonCode,
          revocationReasonPrivate: body?.reasonPrivate ?? null,
          revocationEvidenceHash: body?.evidenceHash ?? null,
        },
        select: {
          id: true,
          status: true,
          revokedAt: true,
          revokedByType: true,
          revocationReasonCode: true,
          revocationReasonPrivate: true,
          revocationEvidenceHash: true,
        },
      });

      await tx.auditLog.create({
        data: {
          actorType: "user",
          actorId: user.id,
          action: "proof.revoked",
          resourceType: "proof",
          resourceId: proof.id,
          metadata: {
            revokedByType,
            reasonCode,
            revokedAt: revokedAt.toISOString(),
          },
        },
      });

      // Only enqueue a REVOKE intent if the proof was previously anchored
      // on-chain — no on-chain registration means nothing to revoke.
      if (this.anchoringEnabled && proof.contractTransactionHash) {
        await tx.anchoringIntent.create({
          data: {
            proofId: proof.id,
            operation: AnchoringOperation.REVOKE,
            status: AnchoringStatus.PENDING,
          },
        });
      }

      return result;
    });

    const anchoringResult =
      this.anchoringEnabled && proof.contractTransactionHash
        ? { anchored: false as const, reason: "pending" as const }
        : { anchored: false as const, reason: "disabled" as const };

    this.emitWebhook(proof.userId, "proof.revoked", {
      proofId: updated.id,
      status: updated.status,
      revokedAt: updated.revokedAt?.toISOString() ?? revokedAt.toISOString(),
    this.emitWebhook(userId, {
      event: "proof.revoked",
      source: {
        proofId: updated.id,
        status: updated.status,
        revokedAt: updated.revokedAt ?? new Date(),
      },
    });

    return {
      ...updated,
      revokedAt: updated.revokedAt?.toISOString() ?? revokedAt.toISOString(),
      anchoring: anchoringResult,
    };
  }

  /**
   * Verify a proof.
   *
   * `context.shareTokenId` is set when the verification arrived through a
   * share link; it is recorded on the privacy-safe verification event so the
   * owner can see link usage. It does not change the verification outcome.
   */
  async verifyProof(proofId: string, context: { shareTokenId?: string } = {}) {
  async verifyProof(
    proofId: string,
    clientContext?: VerificationClientContext,
  ) {
    this.verificationAbuseService?.checkClientCardinality(clientContext, proofId);
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      include: {
        user: {
          select: {
            walletHash: true,
          },
        },
        claim: true,
      },
    });

    this.verificationAbuseService?.checkVerification(
      clientContext,
      proofId,
      Boolean(proof?.claim),
    );

    if (!proof || !proof.claim) {
      // Unknown probes deliberately do not create audit rows: the identifier
      // is untrusted and could otherwise create an unbounded data sink.
      return {
        result: VerificationResult.UNKNOWN_PROOF,
        status: "unknown",
      };
    }

    const credential = this.rebuildCredential({ ...proof, claim: proof.claim });
    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const cadence = this.revealCadence(proof.claim.frequency);
    const credential =
      proof.proofType === ProofType.AGGREGATE_EARNINGS
        ? this.rebuildAggregateEarningsCredential({
            ...proof,
            claim: proof.claim!,
          })
        : proof.proofType === ProofType.RECURRING_INCOME
        ? this.buildRecurringIncomeCredential({
            id: proof.id,
            walletHash: proof.user.walletHash,
            cadence: proof.claim.frequency ?? "invalid",
            intervalUnit: cadence?.intervalUnit ?? "month",
            intervalCount: cadence?.intervalCount ?? 0,
            assetCode: proof.assetCode,
            assetIssuer: proof.assetIssuer,
            periodStart: proof.periodStart ?? proof.createdAt,
            periodEnd: proof.periodEnd ?? proof.createdAt,
            qualifyingPaymentCount:
              typeof policy["qualifyingPaymentCount"] === "number"
                ? policy["qualifyingPaymentCount"]
                : 0,
            issuedAt: proof.createdAt,
            expiresAt: proof.expiresAt,
          })
        : proof.proofType === ProofType.PAYMENT_RECEIPT
          ? this.rebuildPaymentReceiptCredential({
              ...proof,
              claim: proof.claim!,
            })
          : proof.proofType === ProofType.INVOICE_SETTLEMENT
            ? this.rebuildInvoiceSettlementCredential({
                ...proof,
                claim: proof.claim!,
              })
            : this.buildCredential({
                id: proof.id,
                walletHash: proof.user.walletHash,
                thresholdAmount: this.revealThreshold(
                  proof.claim.thresholdEncrypted,
                ),
          : proof.proofType === ProofType.INCOME_RANGE
            ? this.buildIncomeRangeCredential({
                id: proof.id,
                walletHash: proof.user.walletHash,
                lowerBound:
                  typeof policy["lowerBound"] === "string"
                    ? policy["lowerBound"]
                    : "0",
                upperBound:
                  typeof policy["upperBound"] === "string"
                    ? policy["upperBound"]
                    : "0",
                assetCode: proof.assetCode,
                assetIssuer: proof.assetIssuer,
                periodStart: proof.periodStart ?? proof.createdAt,
                periodEnd: proof.periodEnd ?? proof.createdAt,
                qualifyingPaymentCount: this.qualifyingPaymentCount(
                  proof.claim,
                ),
                issuedAt: proof.createdAt,
                expiresAt: proof.expiresAt,
              });
              })
            : this.buildCredential({
            id: proof.id,
            walletHash: proof.user.walletHash,
            thresholdAmount: this.revealThreshold(
              proof.claim.thresholdEncrypted,
            ),
            assetCode: proof.assetCode,
            assetIssuer: proof.assetIssuer,
            periodStart: proof.periodStart ?? proof.createdAt,
            periodEnd: proof.periodEnd ?? proof.createdAt,
            qualifyingPaymentCount: this.qualifyingPaymentCount(proof.claim),
            issuedAt: proof.createdAt,
            expiresAt: proof.expiresAt,
          });
    const signedCredential = this.signCredential(credential);
    const expectedHash = `sha256:${sha256(canonicalize(credential))}`;

    let result: VerificationResult = VerificationResult.VALID;
    if (proof.credentialHash !== expectedHash) {
      result = VerificationResult.INVALID_SIGNATURE;
    } else if (proof.status === ProofStatus.REVOKED) {
      result = VerificationResult.REVOKED;
    } else if (proof.expiresAt <= new Date()) {
      result = VerificationResult.EXPIRED;
    } else if (proof.status !== ProofStatus.ACTIVE) {
      result = VerificationResult.INVALID_SIGNATURE;
    }

    const contractStatus = proof.contractTransactionHash
      ? await this.contractAnchoringService?.getProofStatus(proof.id)
      : undefined;

    // Fail closed: authoritative on-chain invalidity overrides stale local state
    if (contractStatus?.checked) {
      if (contractStatus.revoked) {
        result = VerificationResult.REVOKED;
      } else if (result === VerificationResult.VALID && !contractStatus.valid) {
        result = VerificationResult.INVALID_SIGNATURE;
      }
    }

    // If required anchoring is enabled and this proof has not yet been
    // confirmed on-chain, return UNVERIFIED_ISSUER to signal that the proof
    // is not yet verifiable via the contract. Optional anchoring (or no
    // anchoring at all) does not block verification.
    if (
      result === VerificationResult.VALID &&
      this.anchoringRequired &&
      !proof.contractTransactionHash
    ) {
      result = VerificationResult.UNVERIFIED_ISSUER;
    }

    // Convert VerificationResult to VerificationOutcome for event recording
    const outcome = this.mapResultToOutcome(result);

    // Fail-open policy: record verification event asynchronously
    // If event recording fails, the verification response is still returned.
    // This ensures verification availability over audit completeness.
    // Event recording errors are caught and logged by the service.
    this.verificationEventService
      .recordEvent(
        outcome,
        proof.id,
        {
          outcome: outcome,
          timestamp: new Date(),
        },
        context,
      )
      .catch(() => {
        // Error already logged by the service
        // Verification continues unblocked
      });
    const verificationEventService = this.verificationEventService as VerificationEventService & {
      tryConsumePrivacyBudget?: (proofId: string) => boolean;
    };
    if (verificationEventService.tryConsumePrivacyBudget?.(proof.id) ?? true) {
      this.verificationEventService
        .recordEvent(outcome, proof.id, {
          outcome: outcome,
          timestamp: new Date(),
        })
        .catch(() => {
          // Error already logged by the service
          // Verification continues unblocked
        });

      await this.prisma.verificationEvent.create({
        data: {
          proofId: proof.id,
          result,
        },
      });
    }

    this.emitWebhook(proof.userId, {
      event: "proof.verified",
      source: { proofId: proof.id, result, verifiedAt: new Date() },
    });

    return {
      result,
      status: this.publicStatus(result),
      credential: signedCredential,
      proof: {
        id: proof.id,
        type: proof.proofType,
        schemaVersion: proof.schemaVersion,
        network: proof.network,
        issuedAt: proof.createdAt.toISOString(),
        expiresAt: proof.expiresAt.toISOString(),
        revokedAt: proof.revokedAt?.toISOString() ?? null,
        revocationReasonCode: proof.revocationReasonCode ?? null,
        contractStatus: contractStatus ?? {
          checked: false,
          reason: "disabled",
        },
      },
    };
  }

  /**
   * Verify a bounded batch of proof IDs, returning one ordered result per
   * submitted ID.
   *
   * Each distinct ID runs through the exact single-proof {@link verifyProof}
   * path — same public (unauthenticated) access, same privacy envelope, same
   * event recording — so a batch reveals nothing a sequence of single calls
   * would not. Duplicate IDs are coalesced: the proof is looked up once (one
   * storage read, one anchoring check) and its verdict is returned at every
   * position it occupies, so a caller cannot multiply the fan-out by repeating
   * an ID. The four outcomes a relying party must distinguish — missing,
   * revoked, expired, and dependency-unavailable — are preserved per item via
   * `result` and `contractStatus`.
   */
  async verifyProofsBatch(proofIds: string[]) {
    const distinct = [...new Set(proofIds)];
    const byId = new Map<
      string,
      Awaited<ReturnType<ProofsService["verifyProof"]>>
    >();
    await Promise.all(
      distinct.map(async (id) => {
        byId.set(id, await this.verifyProof(id));
      }),
    );

    return {
      results: proofIds.map((id) => {
        const verified = byId.get(id)!;
        return {
          id,
          result: verified.result,
          status: verified.status,
          contractStatus: verified.proof?.contractStatus ?? {
            checked: false,
            reason: "unknown" as const,
          },
        };
      }),
    };
  }

  private emitProofCreated(
    userId: string,
    proof: {
      id: string;
      proofType: ProofType;
      schemaVersion: string;
      status: ProofStatus;
      network: string;
      assetCode: string;
      assetIssuer: string | null;
      periodStart: Date | null;
      periodEnd: Date | null;
      expiresAt: Date;
      credentialHash: string;
      contractTransactionHash?: string | null;
      createdAt: Date;
    },
  ) {
    this.emitWebhook(userId, {
      event: "proof.created",
      source: {
        proofId: proof.id,
        proofType: proof.proofType,
        credentialSchemaVersion: proof.schemaVersion,
        status: proof.status,
        network: proof.network,
        assetCode: proof.assetCode,
        assetIssuer: proof.assetIssuer,
        periodStart: proof.periodStart,
        periodEnd: proof.periodEnd,
        expiresAt: proof.expiresAt,
        credentialHash: proof.credentialHash,
        contractTransactionHash: proof.contractTransactionHash ?? null,
        issuedAt: proof.createdAt,
      },
    });
  }

  private emitWebhook(userId: string, domainEvent: WebhookEventSource) {
    this.webhookDeliveryService
      ?.enqueueForUser(userId, domainEvent)
      .catch(() => undefined);
  }

  private buildCredential(input: {
    id: string;
    walletHash: string;
    thresholdAmount: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    qualifyingPaymentCount: number;
    issuedAt: Date;
    expiresAt: Date;
  }): MinimumIncomeCredential {
    return {
      id: input.id,
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: {
        walletHash: input.walletHash,
      },
      claim: {
        operator: "gte",
        thresholdAmount: input.thresholdAmount,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        periodStart: input.periodStart.toISOString(),
        periodEnd: input.periodEnd.toISOString(),
        qualifyingPaymentCount: input.qualifyingPaymentCount,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private buildAggregateEarningsCredential(input: {
    id: string;
    walletHash: string;
    aggregateAmount: string;
    roundingIncrement: RoundingIncrement;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    sourceScope: SourceScope;
    qualifyingPaymentCount: number;
    policyVersion: string;
    issuedAt: Date;
    expiresAt: Date;
  }): AggregateEarningsCredential {
    return {
      id: input.id,
      type: "EarnProofAggregateEarningsCredential",
      schemaVersion: AGGREGATE_EARNINGS_SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: { walletHash: input.walletHash },
      claim: {
        operator: "sum",
        aggregateAmount: input.aggregateAmount,
        rounding: { mode: "floor", increment: input.roundingIncrement },
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        periodStart: input.periodStart.toISOString(),
        periodEnd: input.periodEnd.toISOString(),
        periodBoundary: "start-inclusive-end-exclusive",
        sourceScope: input.sourceScope,
        qualifyingPaymentCount: input.qualifyingPaymentCount,
        policyVersion: input.policyVersion,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
        sourceIdentitiesHidden: true,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  /**
   * Rebuilds an aggregate credential from stored state for verification.
   * Unrecognised stored parameters fall back to values that cannot reproduce
   * the committed hash, so tampering surfaces as INVALID_SIGNATURE.
   */
  private rebuildAggregateEarningsCredential(proof: {
    id: string;
    assetCode: string;
    assetIssuer: string | null;
    createdAt: Date;
    expiresAt: Date;
    periodStart: Date | null;
    periodEnd: Date | null;
    user: { walletHash: string };
    claim: {
      thresholdEncrypted: string | null;
      disclosurePolicy: Prisma.JsonValue;
    };
  }) {
    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const rounding = policy["roundingIncrement"];
    const scope = policy["sourceScope"];
    return this.buildAggregateEarningsCredential({
      id: proof.id,
      walletHash: proof.user.walletHash,
      aggregateAmount: this.revealThreshold(proof.claim.thresholdEncrypted),
      roundingIncrement: (ROUNDING_INCREMENTS as readonly unknown[]).includes(rounding)
        ? (rounding as RoundingIncrement)
        : ("invalid" as RoundingIncrement),
      assetCode: proof.assetCode,
      assetIssuer: proof.assetIssuer,
      periodStart: proof.periodStart ?? proof.createdAt,
      periodEnd: proof.periodEnd ?? proof.createdAt,
      sourceScope: (SOURCE_SCOPES as readonly unknown[]).includes(scope)
        ? (scope as SourceScope)
        : ("invalid" as SourceScope),
      qualifyingPaymentCount:
        typeof policy["qualifyingPaymentCount"] === "number"
          ? policy["qualifyingPaymentCount"]
          : 0,
      policyVersion:
        typeof policy["policyVersion"] === "string"
          ? policy["policyVersion"]
          : AGGREGATE_EARNINGS_POLICY_VERSION,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });
  }

  /** Maps a policy refusal to a stable, data-free API error. */
  private aggregationException(error: unknown) {
    if (!(error instanceof AggregationPolicyError)) return error;
    switch (error.reason) {
      case "invalid_period":
      case "future_period":
      case "period_too_long":
      case "invalid_source":
        return new BadRequestException({
          code: ApiErrorCode.INVALID_INPUT,
          message: error.message,
        });
      case "cross_asset_unsupported":
        return new UnprocessableEntityException({
          code: ApiErrorCode.AGGREGATION_CROSS_ASSET_UNSUPPORTED,
          message: error.message,
        });
      case "limit_exceeded":
        return new UnprocessableEntityException({
          code: ApiErrorCode.AGGREGATION_LIMIT_EXCEEDED,
          message: error.message,
        });
      case "amount_unavailable":
        return new UnprocessableEntityException({
          code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
          message: error.message,
        });
      case "insufficient_payments":
      case "below_rounding_increment":
        return new UnprocessableEntityException({
          code: ApiErrorCode.AGGREGATION_INSUFFICIENT_PAYMENTS,
          message: error.message,
        });
    }
  }

  private buildPaymentReceiptCredential(input: {
    id: string;
    walletHash: string;
    assetCode: string;
    assetIssuer: string | null;
    occurredAt: Date;
    paymentReferenceHash: string;
    senderHidden: boolean;
    amountHidden: boolean;
    sourceAddress?: string;
    amount?: string;
    issuedAt: Date;
    expiresAt: Date;
  }): PaymentReceiptCredential {
    return {
      id: input.id,
      type: "EarnProofPaymentReceiptCredential",
      schemaVersion: PAYMENT_RECEIPT_SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: { walletHash: input.walletHash },
      claim: {
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        occurredAt: input.occurredAt.toISOString(),
        paymentReferenceHash: input.paymentReferenceHash,
        ...(input.senderHidden
          ? undefined
          : { sourceAddress: input.sourceAddress }),
        ...(input.amountHidden ? undefined : { amount: input.amount }),
      },
      privacy: {
        senderHidden: input.senderHidden,
        amountHidden: input.amountHidden,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private buildInvoiceSettlementCredential(input: {
    id: string;
    walletHash: string;
    issuerId: string;
    assetCode: string;
    assetIssuer: string | null;
    occurredAt: Date;
    invoiceReferenceHash: string;
    amountHidden: boolean;
    amount?: string;
    issuedAt: Date;
    expiresAt: Date;
  }): InvoiceSettlementCredential {
    return {
      id: input.id,
      type: "EarnProofInvoiceSettlementCredential",
      schemaVersion: INVOICE_SETTLEMENT_SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: { walletHash: input.walletHash },
      claim: {
        issuerId: input.issuerId,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        occurredAt: input.occurredAt.toISOString(),
        invoiceReferenceHash: input.invoiceReferenceHash,
        ...(input.amountHidden ? undefined : { amount: input.amount }),
      },
      privacy: { amountHidden: input.amountHidden },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private buildRecurringIncomeCredential(input: {
    id: string;
    walletHash: string;
    cadence: string;
    intervalUnit: IntervalUnit;
    intervalCount: number;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    qualifyingPaymentCount: number;
    issuedAt: Date;
    expiresAt: Date;
  }): RecurringIncomeCredential {
    return {
      id: input.id,
      type: "EarnProofRecurringIncomeCredential",
      schemaVersion: RECURRING_INCOME_SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: { walletHash: input.walletHash },
      claim: {
        cadence: input.cadence,
        intervalUnit: input.intervalUnit,
        intervalCount: input.intervalCount,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        periodStart: input.periodStart.toISOString(),
        periodEnd: input.periodEnd.toISOString(),
        qualifyingPaymentCount: input.qualifyingPaymentCount,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private buildIncomeRangeCredential(input: {
    id: string;
    walletHash: string;
    lowerBound: string;
    upperBound: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    qualifyingPaymentCount: number;
    issuedAt: Date;
    expiresAt: Date;
  }): IncomeRangeCredential {
    return {
      id: input.id,
      type: "EarnProofIncomeRangeCredential",
      schemaVersion: INCOME_RANGE_SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: {
        walletHash: input.walletHash,
      },
      claim: {
        operator: "range",
        lowerBound: input.lowerBound,
        upperBound: input.upperBound,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        periodStart: input.periodStart.toISOString(),
        periodEnd: input.periodEnd.toISOString(),
        qualifyingPaymentCount: input.qualifyingPaymentCount,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private buildRecurringIntervals(
    periodStart: Date,
    periodEnd: Date,
    unit: IntervalUnit,
    count: number,
  ): Array<[Date, Date]> {
    const finalIntervalStart = this.addIntervalUnit(
      periodStart,
      unit,
      count - 1,
    );
    const cadenceEnd = this.addIntervalUnit(periodStart, unit, count);
    if (periodEnd < finalIntervalStart || periodEnd >= cadenceEnd) {
      throw new BadRequestException(
        "The overall period must contain exactly the requested number of cadence intervals",
      );
    }

    return Array.from({ length: count }, (_, index) => {
      const start = this.addIntervalUnit(periodStart, unit, index);
      const nextStart = this.addIntervalUnit(periodStart, unit, index + 1);
      const naturalEnd = new Date(nextStart.getTime() - 1);
      return [start, naturalEnd < periodEnd ? naturalEnd : periodEnd];
    });
  }

  private addIntervalUnit(date: Date, unit: IntervalUnit, amount: number) {
    const result = new Date(date);
    if (unit === "day") {
      result.setUTCDate(result.getUTCDate() + amount);
    } else if (unit === "week") {
      result.setUTCDate(result.getUTCDate() + amount * 7);
    } else {
      result.setUTCMonth(result.getUTCMonth() + amount);
    }
    return result;
  }

  private revealCadence(frequency: string | null) {
    const match = /^(day|week|month):([1-9]\d*)$/.exec(frequency ?? "");
    if (!match) return null;

    const intervalCount = Number(match[2]);
    if (!Number.isSafeInteger(intervalCount) || intervalCount > 120) {
      return null;
    }
    return {
      intervalUnit: match[1] as IntervalUnit,
      intervalCount,
    };
  }

  /**
   * Reconstruct a stored proof's credential body from its row and claim.
   * Shared by verification and renewal so a renewed successor is rebuilt by
   * exactly the code that will later verify it.
   */
  private rebuildCredential(proof: {
    id: string;
    proofType: ProofType;
    assetCode: string;
    assetIssuer: string | null;
    createdAt: Date;
    expiresAt: Date;
    periodStart: Date | null;
    periodEnd: Date | null;
    user: { walletHash: string };
    claim: {
      thresholdEncrypted: string | null;
      frequency: string | null;
      disclosurePolicy: Prisma.JsonValue;
    };
  }): EarnProofCredential {
    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const cadence = this.revealCadence(proof.claim.frequency);
    return proof.proofType === ProofType.RECURRING_INCOME
      ? this.buildRecurringIncomeCredential({
          id: proof.id,
          walletHash: proof.user.walletHash,
          cadence: proof.claim.frequency ?? "invalid",
          intervalUnit: cadence?.intervalUnit ?? "month",
          intervalCount: cadence?.intervalCount ?? 0,
          assetCode: proof.assetCode,
          assetIssuer: proof.assetIssuer,
          periodStart: proof.periodStart ?? proof.createdAt,
          periodEnd: proof.periodEnd ?? proof.createdAt,
          qualifyingPaymentCount:
            typeof policy["qualifyingPaymentCount"] === "number"
              ? policy["qualifyingPaymentCount"]
              : 0,
          issuedAt: proof.createdAt,
          expiresAt: proof.expiresAt,
        })
      : proof.proofType === ProofType.PAYMENT_RECEIPT
        ? this.rebuildPaymentReceiptCredential(proof)
        : this.buildCredential({
            id: proof.id,
            walletHash: proof.user.walletHash,
            thresholdAmount: this.revealThreshold(
              proof.claim.thresholdEncrypted,
            ),
            assetCode: proof.assetCode,
            assetIssuer: proof.assetIssuer,
            periodStart: proof.periodStart ?? proof.createdAt,
            periodEnd: proof.periodEnd ?? proof.createdAt,
            qualifyingPaymentCount: this.qualifyingPaymentCount(proof.claim),
            issuedAt: proof.createdAt,
            expiresAt: proof.expiresAt,
          });
  }

  private rebuildPaymentReceiptCredential(proof: {
    id: string;
    assetCode: string;
    assetIssuer: string | null;
    createdAt: Date;
    expiresAt: Date;
    periodStart: Date | null;
    user: { walletHash: string };
    claim: {
      thresholdEncrypted: string | null;
      disclosurePolicy: Prisma.JsonValue;
    };
  }) {
    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const senderHidden = policy["senderHidden"] !== false;
    const amountHidden = policy["amountHidden"] !== false;
    const occurredAtValue = policy["occurredAt"];
    const occurredAt =
      typeof occurredAtValue === "string" &&
      !Number.isNaN(new Date(occurredAtValue).getTime())
        ? new Date(occurredAtValue)
        : (proof.periodStart ?? proof.createdAt);

    return this.buildPaymentReceiptCredential({
      id: proof.id,
      walletHash: proof.user.walletHash,
      assetCode: proof.assetCode,
      assetIssuer: proof.assetIssuer,
      occurredAt,
      paymentReferenceHash:
        typeof policy["paymentReferenceHash"] === "string"
          ? policy["paymentReferenceHash"]
          : "",
      senderHidden,
      amountHidden,
      sourceAddress:
        typeof policy["sourceAddress"] === "string"
          ? policy["sourceAddress"]
          : undefined,
      amount: amountHidden
        ? undefined
        : this.revealPaymentAmountForVerification(
            proof.claim.thresholdEncrypted,
          ),
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });
  }

  private rebuildInvoiceSettlementCredential(proof: {
    id: string;
    assetCode: string;
    assetIssuer: string | null;
    createdAt: Date;
    expiresAt: Date;
    periodStart: Date | null;
    user: { walletHash: string };
    claim: {
      thresholdEncrypted: string | null;
      disclosurePolicy: Prisma.JsonValue;
    };
  }) {
    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const amountHidden = policy["amountHidden"] !== false;
    const occurredAtValue = policy["occurredAt"];
    const occurredAt =
      typeof occurredAtValue === "string" &&
      !Number.isNaN(new Date(occurredAtValue).getTime())
        ? new Date(occurredAtValue)
        : (proof.periodStart ?? proof.createdAt);

    return this.buildInvoiceSettlementCredential({
      id: proof.id,
      walletHash: proof.user.walletHash,
      issuerId:
        typeof policy["issuerId"] === "string" ? policy["issuerId"] : "",
      assetCode: proof.assetCode,
      assetIssuer: proof.assetIssuer,
      occurredAt,
      invoiceReferenceHash:
        typeof policy["invoiceReferenceHash"] === "string"
          ? policy["invoiceReferenceHash"]
          : "",
      amountHidden,
      amount: amountHidden
        ? undefined
        : this.revealPaymentAmountForVerification(
            proof.claim.thresholdEncrypted,
          ),
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });
  }

  private signCredential<T extends EarnProofCredential>(credential: T) {
    if (this.credentialVerificationKeyService) {
      return {
        ...credential,
        proof: this.credentialVerificationKeyService.signCredential(credential),
      };
    }

    const canonicalPayload = canonicalize(credential);
    return {
      ...credential,
      proof: {
        type: "HMAC-SHA256",
        keyId: this.signingKeyring.activeKeyId,
        credentialHash: `sha256:${sha256(canonicalPayload)}`,
        signature: `hmac-sha256:${createHmac(
          "sha256",
          this.signingKeyring.activeSecret,
        )
          .update(canonicalPayload)
          .digest("base64url")}`,
      },
    };
  }

  /**
   * Normalizes a raw invoice reference so that equivalent references (differing
   * only in surrounding/internal whitespace or letter case) commit to the same
   * hash. Never persisted or logged — callers must hash the result immediately.
   */
  private normalizeInvoiceReference(raw: string): string {
    return raw.trim().replace(/\s+/g, " ").toLowerCase();
  }

  /**
   * Like `revealProtectedAmount`, but returns null instead of throwing when the
   * amount is missing or undecryptable. Used while filtering payment candidates
   * so that one payment with unreadable amount data doesn't abort matching for
   * the whole request — it's just excluded as a non-match.
   */
  private tryRevealProtectedAmount(
    amountEncrypted: string | null,
  ): bigint | null {
    if (!amountEncrypted) return null;
    try {
      return this.parseAmount(
        decryptProtectedAmount(amountEncrypted, this.paymentEncryptionKey),
      );
    } catch {
      return null;
    }
  }

  private revealProtectedAmount(amountEncrypted: string | null) {
    if (!amountEncrypted) {
      throw new BadRequestException("Selected payment amount is unavailable");
    }

    try {
      return this.parseAmount(
        this.paymentEncryptionKeyring.decrypt(amountEncrypted),
      );
    } catch {
      throw new BadRequestException("Selected payment amount is unavailable");
    }
  }

  private revealPaymentAmount(amountEncrypted: string | null) {
    if (!amountEncrypted) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
        message: "Payment amount is unavailable for disclosure",
      });
    }
    try {
      return this.paymentEncryptionKeyring.decrypt(amountEncrypted);
    } catch {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
        message: "Payment amount is unavailable for disclosure",
      });
    }
  }

  private revealPaymentSender(payment: {
    sourceAddress: string | null;
    sourceAddressEncrypted: string | null;
  }) {
    try {
      return this.paymentEncryptionKeyring.addressCipher().reveal(
        { encrypted: payment.sourceAddressEncrypted, plaintext: payment.sourceAddress },
        "source",
      );
    } catch {
      // Never echo the stored value or the failure detail.
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
        message: "Payment sender is unavailable for disclosure",
      });
    }
  }

  private revealPaymentAmountForVerification(amountEncrypted: string | null) {
    try {
      return amountEncrypted
        ? this.paymentEncryptionKeyring.decrypt(amountEncrypted)
        : "";
    } catch {
      return "";
    }
  }

  private jsonPolicy(value: Prisma.JsonValue): Record<string, unknown> {
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  }

  private revealThreshold(thresholdEncrypted: string | null) {
    if (!thresholdEncrypted?.startsWith("redacted:")) {
      return "0";
    }

    return Buffer.from(
      thresholdEncrypted.slice("redacted:".length),
      "base64url",
    ).toString("utf8");
  }

  private protectAmount(amount: string) {
    return `redacted:${Buffer.from(amount).toString("base64url")}`;
  }

  private parseAmount(amount: string) {
    const [whole, decimal = ""] = amount.split(".");
    const paddedDecimal = decimal.padEnd(7, "0");
    return BigInt(whole) * 10_000_000n + BigInt(paddedDecimal);
  }

  private qualifyingPaymentCount(claim: {
    disclosurePolicy: Prisma.JsonValue;
  }) {
    const policy = claim.disclosurePolicy;
    if (
      policy &&
      typeof policy === "object" &&
      !Array.isArray(policy) &&
      "qualifyingPaymentCount" in policy
    ) {
      const count = policy.qualifyingPaymentCount;
      return typeof count === "number" ? count : 1;
    }

    return 1;
  }

  private publicStatus(result: VerificationResult) {
    switch (result) {
      case VerificationResult.VALID:
        return "valid";
      case VerificationResult.EXPIRED:
        return "expired";
      case VerificationResult.REVOKED:
        return "revoked";
      case VerificationResult.UNKNOWN_PROOF:
        return "unknown";
      default:
        return "invalid";
    }
  }

  private mapResultToOutcome(result: VerificationResult): VerificationOutcome {
    switch (result) {
      case VerificationResult.VALID:
        return VerificationOutcome.VALID;
      case VerificationResult.EXPIRED:
        return VerificationOutcome.EXPIRED;
      case VerificationResult.REVOKED:
        return VerificationOutcome.REVOKED;
      case VerificationResult.INVALID_SIGNATURE:
        return VerificationOutcome.INVALID_SIGNATURE;
      case VerificationResult.UNKNOWN_PROOF:
        return VerificationOutcome.UNKNOWN;
      case VerificationResult.UNVERIFIED_ISSUER:
        return VerificationOutcome.ISSUER_WARNING;
      default:
        return VerificationOutcome.UNKNOWN;
    }
  }

  async getVerificationStats(userId: string, proofId: string) {
    // Verify proof ownership: only the owner or admin can view stats
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      select: {
        id: true,
        userId: true,
      },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    if (proof.userId !== userId) {
      throw new ForbiddenException(
        "You do not have permission to view statistics for this proof",
      );
    }

    return this.verificationEventService.getAggregateStats(proofId);
  }

  private toHistoryItem(proof: Proof) {
    const expired = proof.expiresAt <= new Date();
    return {
      id: proof.id,
      type: proof.proofType,
      schemaVersion: proof.schemaVersion,
      localStatus: proof.status,
      credentialValidity: this.credentialValidity(proof, expired),
      expired,
      asset: { code: proof.assetCode, issuer: proof.assetIssuer },
      periodStart: proof.periodStart?.toISOString() ?? null,
      periodEnd: proof.periodEnd?.toISOString() ?? null,
      issuedAt: proof.createdAt.toISOString(),
      expiresAt: proof.expiresAt.toISOString(),
      revokedAt: proof.revokedAt?.toISOString() ?? null,
      revokedByType: proof.revokedByType ?? null,
      revocationReasonCode: proof.revocationReasonCode ?? null,
      revocationReasonPrivate: proof.revocationReasonPrivate ?? null,
      revocationEvidenceHash: proof.revocationEvidenceHash ?? null,
      anchoring: {
        anchored: Boolean(proof.contractTransactionHash),
        status: proof.contractTransactionHash ? "recorded" : "not_anchored",
        ...(proof.contractTransactionHash
          ? { transactionHash: proof.contractTransactionHash }
          : undefined),
        checked: false,
      },
    };
  }

  private credentialValidity(proof: Proof, expired: boolean) {
    if (proof.status === ProofStatus.REVOKED) return "revoked";
    if (proof.status === ProofStatus.INVALID) return "invalid";
    if (proof.status === ProofStatus.EXPIRED || expired) return "expired";
    return "valid";
  }

  private claimSummary(claim: ProofClaim | null) {
    if (!claim) return undefined;
    const policy = claim.disclosurePolicy as Prisma.JsonObject;
    const count = policy["qualifyingPaymentCount"];

    return {
      operator: claim.operator,
      result: claim.result,
      ...(typeof count === "number"
        ? { qualifyingPaymentCount: count }
        : undefined),
    };
  }

  private async proofAnchoringDetail(proof: Proof) {
    if (!proof.contractTransactionHash) {
      return { anchored: false, status: "not_anchored", checked: false };
    }

    if (!this.contractAnchoringService) {
      return {
        anchored: true,
        status: "recorded",
        transactionHash: proof.contractTransactionHash,
        checked: false,
      };
    }

    try {
      const contract = await this.contractAnchoringService.getProofStatus(
        proof.id,
      );
      return {
        anchored: true,
        status: contract.checked
          ? contract.revoked
            ? "revoked"
            : contract.valid
              ? "valid"
              : "invalid"
          : "unavailable",
        transactionHash: proof.contractTransactionHash,
        checked: contract.checked,
      };
    } catch {
      return {
        anchored: true,
        status: "unavailable",
        transactionHash: proof.contractTransactionHash,
        checked: false,
      };
    }
  }

  /**
   * Proof-scoped anchoring status: the current AnchoringIntent state (at most
   * one REGISTER and one REVOKE row, per the (proofId, operation) unique
   * constraint). This is a live snapshot, not a per-attempt history — the
   * schema keeps one mutable row per operation, overwritten on each attempt.
   */
  async getProofAnchoringStatus(user: AuthenticatedUser, proofId: string) {
    const proof = await this.prisma.proof.findFirst({
      where:
        user.role === "ADMIN" ? { id: proofId } : { id: proofId, userId: user.id },
      select: { id: true },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    const intents = await this.prisma.anchoringIntent.findMany({
      where: { proofId: proof.id },
      orderBy: { createdAt: "asc" },
    });

    return {
      proofId: proof.id,
      intents: intents.map((intent) => ({
        id: intent.id,
        operation: intent.operation,
        status: intent.status,
        attemptCount: intent.attemptCount,
        lastAttemptAt: intent.lastAttemptAt?.toISOString() ?? null,
        nextRetryAt: intent.nextRetryAt?.toISOString() ?? null,
        lastErrorSafe: intent.lastErrorSafe,
        permanentError: intent.permanentError,
        transactionHash: intent.transactionHash,
        quarantinedAt: intent.quarantinedAt?.toISOString() ?? null,
        quarantineReasonCode: intent.quarantineReasonCode,
        quarantineDecision: intent.quarantineDecision,
        decidedAt: intent.decidedAt?.toISOString() ?? null,
      })),
    };
  }

  /**
   * Redrive a quarantined anchoring intent: requeue it for the worker to
   * retry.
   *
   * Deliberately does not invoke the CLI synchronously: the worker's poll
   * loop already owns claiming (`FOR UPDATE SKIP LOCKED`) and backoff, so
   * this only flips QUARANTINED -> PENDING with nextRetryAt = now and lets
   * that machinery pick it up. attemptCount is preserved (not reset), so
   * MAX_ATTEMPTS and the backoff curve still apply to a redriven intent.
   * Recording `quarantineDecision: REDRIVEN` keeps the prior quarantine
   * reason and timestamp on the row rather than clearing them, so the
   * intent's prior-attempt and quarantine history survives the redrive.
   */
  async retryProofAnchoring(user: AuthenticatedUser, proofId: string, intentId: string) {
    const proof = await this.prisma.proof.findFirst({
      where:
        user.role === "ADMIN" ? { id: proofId } : { id: proofId, userId: user.id },
      select: { id: true },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    const intent = await this.prisma.anchoringIntent.findFirst({
      where: { id: intentId, proofId: proof.id },
    });

    if (!intent) {
      throw new NotFoundException("Anchoring intent not found for this proof");
    }

    // Processing or confirmed intents cannot be duplicated: only a
    // quarantined intent is eligible for a manual redrive. A PENDING intent
    // is already going to retry on its own schedule, and an ABANDONED
    // decision is meant to be terminal.
    if (
      intent.status !== AnchoringStatus.QUARANTINED ||
      intent.quarantineDecision === QuarantineDecision.ABANDONED
    ) {
      throw new UnprocessableEntityException(
        `Anchoring intent ${intentId} is not eligible for retry (status: ${intent.status}, quarantineDecision: ${intent.quarantineDecision})`,
      );
    }

    const requeuedAt = new Date();
    const updated = await this.prisma.$transaction(async (tx) => {
      const result = await tx.anchoringIntent.update({
        where: { id: intentId },
        data: {
          status: AnchoringStatus.PENDING,
          permanentError: false,
          nextRetryAt: requeuedAt,
          quarantineDecision: QuarantineDecision.REDRIVEN,
          decidedById: user.id,
          decidedAt: requeuedAt,
        },
        select: { id: true, status: true, attemptCount: true },
      });

      await tx.auditLog.create({
        data: {
          actorType: "user",
          actorId: user.id,
          action: "anchoring_intent.retried",
          resourceType: "proof",
          resourceId: proof.id,
          metadata: { intentId, requeuedAt: requeuedAt.toISOString() },
        },
      });

      return result;
    });

    return {
      intentId: updated.id,
      status: updated.status,
      attemptCount: updated.attemptCount,
    };
  }

  /**
   * Abandon a quarantined anchoring intent: a terminal operator decision
   * that the worker will never retry and no further redrive is expected.
   *
   * Deliberately touches only the AnchoringIntent row. Abandoning a
   * REGISTER intent must never be able to make an unanchored proof look
   * confirmed: Proof.status and Proof.contractTransactionHash are untouched
   * here, so a proof whose only REGISTER intent was abandoned stays exactly
   * as unanchored as it was before the abandonment.
   */
  async abandonProofAnchoring(user: AuthenticatedUser, proofId: string, intentId: string) {
    const proof = await this.prisma.proof.findFirst({
      where:
        user.role === "ADMIN" ? { id: proofId } : { id: proofId, userId: user.id },
      select: { id: true },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    const intent = await this.prisma.anchoringIntent.findFirst({
      where: { id: intentId, proofId: proof.id },
    });

    if (!intent) {
      throw new NotFoundException("Anchoring intent not found for this proof");
    }

    if (intent.status !== AnchoringStatus.QUARANTINED) {
      throw new UnprocessableEntityException(
        `Anchoring intent ${intentId} is not eligible for abandonment (status: ${intent.status})`,
      );
    }

    if (intent.quarantineDecision === QuarantineDecision.ABANDONED) {
      // Idempotent: already abandoned, return the existing decision as-is
      // rather than overwriting decidedById/decidedAt on a retry.
      return {
        intentId: intent.id,
        status: intent.status,
        quarantineDecision: intent.quarantineDecision,
      };
    }

    const decidedAt = new Date();
    const updated = await this.prisma.$transaction(async (tx) => {
      const result = await tx.anchoringIntent.update({
        where: { id: intentId },
        data: {
          quarantineDecision: QuarantineDecision.ABANDONED,
          decidedById: user.id,
          decidedAt,
        },
        select: { id: true, status: true, quarantineDecision: true },
      });

      await tx.auditLog.create({
        data: {
          actorType: "user",
          actorId: user.id,
          action: "anchoring_intent.abandoned",
          resourceType: "proof",
          resourceId: proof.id,
          metadata: { intentId, decidedAt: decidedAt.toISOString() },
        },
      });

      return result;
    });

    return {
      intentId: updated.id,
      status: updated.status,
      quarantineDecision: updated.quarantineDecision,
    };
   * Validate that all active attestations for a subject wallet are still valid
   * (not expired, not revoked) for proof issuance.
   *
   * This is called during proof creation to ensure attestation lifecycle requirements
   * are met before issuing credentials.
   *
   * @param subjectWalletHash Subject wallet hash
   * @returns true if all attestations are valid or no attestations exist
   */
  async validateSubjectAttestations(subjectWalletHash: string): Promise<boolean> {
    const attestations = await this.attestationsService.getValidAttestationsForSubject(
      subjectWalletHash,
    );

    // If no attestations exist, validation passes
    if (attestations.length === 0) {
      return true;
    }

    // All attestations must be valid (checked via getValidAttestationsForSubject)
    // which already filters for active status and non-expired/non-revoked states
    return attestations.length > 0;
  }

  /**
   * Check if an issuer's attestations for a subject are still valid.
   *
   * Used to gate proof issuance on issuer attestation status.
   *
   * @param issuerId Issuer ID
   * @param subjectWalletHash Subject wallet hash
   * @returns true if issuer has at least one valid attestation for subject
   */
  async hasValidAttestationsFromIssuer(
    issuerId: string,
    subjectWalletHash: string,
  ): Promise<boolean> {
    const attestations = await this.attestationsService.getValidAttestationsForSubject(
      subjectWalletHash,
      issuerId,
    );
    return attestations.length > 0;
  }
}
