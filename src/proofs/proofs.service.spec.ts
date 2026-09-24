import {
  AnchoringOperation,
  AnchoringStatus,
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { sha256 } from "../common/crypto/hash";
import { ProofsService } from "./proofs.service";
import { VerificationEventService } from "../audit/verification-event.service";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function canonicalize(value: unknown): string {
  return JSON.stringify(sortObject(value));
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortObject(item));
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.keys(record)
      .sort()
      .reduce<Record<string, unknown>>((sorted, key) => {
        sorted[key] = sortObject(record[key]);
        return sorted;
      }, {});
  }

  return value;
}

/**
 * Config factory.
 * @param anchoringEnabled - CONTRACT_ANCHORING_ENABLED
 * @param anchoringRequired - CONTRACT_ANCHORING_REQUIRED
 */
function makeConfig(anchoringEnabled = false, anchoringRequired = false) {
  return {
    getOrThrow: jest.fn((key: string) => {
      const values: Record<string, string> = {
        credentialSigningSecret: "test-signing-secret",
        paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "stellar.network": "testnet",
      };
      return values[key];
    }),
    get: jest.fn((key: string) => {
      if (key === "contractAnchoring.enabled") return anchoringEnabled;
      if (key === "contractAnchoring.required") return anchoringRequired;
      return undefined;
    }),
  };
}

const mockVerificationEventService = {
  recordEvent: jest.fn().mockResolvedValue(undefined),
  getAggregateStats: jest.fn().mockResolvedValue({}),
  cleanupExpiredEvents: jest.fn().mockResolvedValue(0),
} as unknown as VerificationEventService;

const user = {
  id: "user_1",
  walletAddress: "GB_TEST",
  walletHash: "sha256:wallet",
  role: "WORKER",
};

const config = makeConfig();

const singlePayment = [
  {
    id: "payment_1",
    assetCode: "XLM",
    assetIssuer: null,
    amountEncrypted: `redacted:${Buffer.from("100").toString("base64url")}`,
    classification: PaymentClassification.INCOME,
    isEligible: true,
    occurredAt: new Date("2026-08-01T00:00:00.000Z"),
  },
];

function makeCreatePrisma(captureIntent?: (data: unknown) => void) {
  return {
    payment: {
      findMany: jest.fn().mockResolvedValue(singlePayment),
    },
    $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) => {
      const tx = {
        proof: {
          create: jest.fn().mockImplementation(({ data }) => ({
            id: data.id,
            userId: data.userId,
            proofType: data.proofType,
            schemaVersion: data.schemaVersion,
            status: data.status,
            network: data.network,
            assetCode: data.assetCode,
            assetIssuer: data.assetIssuer,
            periodStart: data.periodStart,
            periodEnd: data.periodEnd,
            expiresAt: data.expiresAt,
            credentialHash: data.credentialHash,
            commitment: data.commitment,
            createdAt: data.createdAt,
            claim: data.claim.create,
          })),
        },
        anchoringIntent: {
          create: jest.fn().mockImplementation(({ data }) => {
            captureIntent?.(data);
            return { id: "intent_1", ...data };
          }),
        },
      };
      return fn(tx);
    }),
  };
}

describe("ProofsService", () => {
  it("rejects selected payments below the requested threshold", async () => {
    const prisma = {
      payment: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: "payment_1",
            assetCode: "XLM",
            assetIssuer: null,
            amountEncrypted: `redacted:${Buffer.from("25").toString("base64url")}`,
            classification: PaymentClassification.INCOME,
            isEligible: true,
            occurredAt: new Date("2026-08-01T00:00:00.000Z"),
          },
        ]),
      },
      $transaction: jest.fn(),
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    await expect(
      service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      }),
    ).rejects.toThrow("minimum income threshold");
  });

  it("returns an unknown public verification state for missing proofs", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue(null),
      },
      verificationEventLog: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    await expect(service.verifyProof("missing")).resolves.toEqual({
      result: VerificationResult.UNKNOWN_PROOF,
      status: "unknown",
    });
  });

  it("returns a revoked public verification state", async () => {
    const credential = {
      id: "proof_1",
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: "earnproof.minimum-income.v1",
      issuer: "earnproof-backend",
      subject: { walletHash: "sha256:wallet" },
      claim: {
        operator: "gte",
        thresholdAmount: "100",
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
        qualifyingPaymentCount: 1,
      },
      privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true },
      issuedAt: "2026-08-02T00:00:00.000Z",
      expiresAt: "2027-09-01T00:00:00.000Z",
    };
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          proofType: ProofType.MINIMUM_INCOME,
          schemaVersion: "earnproof.minimum-income.v1",
          status: ProofStatus.REVOKED,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: new Date("2026-08-01T00:00:00.000Z"),
          periodEnd: new Date("2026-08-31T23:59:59.000Z"),
          expiresAt: new Date("2027-09-01T00:00:00.000Z"),
          revokedAt: new Date("2026-08-03T00:00:00.000Z"),
          createdAt: new Date("2026-08-02T00:00:00.000Z"),
          credentialHash: `sha256:${sha256(canonicalize(credential))}`,
          contractTransactionHash: null,
          user: { walletHash: "sha256:wallet" },
          claim: {
            thresholdEncrypted: `redacted:${Buffer.from("100").toString("base64url")}`,
            disclosurePolicy: { qualifyingPaymentCount: 1 },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    const result = await service.verifyProof("proof_1");

    expect(JSON.stringify(result)).not.toMatch(/memo(Context)?/i);

    expect(result.result).toBe(VerificationResult.REVOKED);
    expect(result.status).toBe("revoked");
    expect(prisma.verificationEvent.create).toHaveBeenCalledWith({
      data: { proofId: "proof_1", result: VerificationResult.REVOKED },
    });
  });

  it("revokes anchored proofs by enqueuing REVOKE intent in same transaction", async () => {
    const capturedIntents: unknown[] = [];
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_anchored",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: "tx_register",
        }),
      },
      $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) => {
        const tx = {
          proof: {
            update: jest.fn().mockResolvedValue({
              id: "proof_anchored",
              status: ProofStatus.REVOKED,
              revokedAt: new Date("2026-08-04T00:00:00.000Z"),
              revokedByType: "OWNER",
              revocationReasonCode: "OWNER_REQUESTED",
              revocationReasonPrivate: null,
              revocationEvidenceHash: null,
            }),
          },
          auditLog: {
            create: jest.fn().mockResolvedValue({}),
          },
          anchoringIntent: {
            create: jest.fn().mockImplementation(({ data }) => {
              capturedIntents.push(data);
              return { id: "intent_revoke", ...data };
            }),
          },
        };
        return fn(tx);
      }),
    };
    const service = new ProofsService(
      prisma as never,
      makeConfig(true) as never, // anchoring enabled
      mockVerificationEventService,
    );

    const result = await service.revokeProof(user, "proof_anchored");

    expect(result.id).toBe("proof_anchored");
    expect(result.anchoring).toEqual({ anchored: false, reason: "pending" });
    // Revoke intent must have been created inside the transaction.
    expect(capturedIntents).toHaveLength(1);
    expect(capturedIntents[0]).toMatchObject({
      proofId: "proof_anchored",
      operation: AnchoringOperation.REVOKE,
      status: AnchoringStatus.PENDING,
    });
  });

  it("allows an administrator to revoke a proof owned by someone else", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: null,
        }),
      },
      $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) => {
        const tx = {
          proof: {
            update: jest.fn().mockImplementation(({ data }) =>
              Promise.resolve({
                id: "proof_1",
                status: ProofStatus.REVOKED,
                revokedAt: new Date("2026-08-04T00:00:00.000Z"),
                revokedByType: data.revokedByType,
                revocationReasonCode: data.revocationReasonCode,
                revocationReasonPrivate: data.revocationReasonPrivate,
                revocationEvidenceHash: data.revocationEvidenceHash,
              }),
            ),
          },
          auditLog: { create: jest.fn().mockResolvedValue({}) },
          anchoringIntent: { create: jest.fn() },
        };
        return fn(tx);
      }),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
    );

    const admin = { ...user, id: "admin_1", role: "ADMIN" };
    const result = await service.revokeProof(admin, "proof_1", {
      reasonCode: "COMPLIANCE_HOLD",
    });

    expect(result.status).toBe(ProofStatus.REVOKED);
    expect(result.revokedByType).toBe("ADMIN");
    expect(result.revocationReasonCode).toBe("COMPLIANCE_HOLD");
  });

  it("refuses a non-owner, non-administrator revocation attempt", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: null,
        }),
      },
      $transaction: jest.fn(),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
    );

    const stranger = { ...user, id: "user_2", role: "WORKER" };

    await expect(service.revokeProof(stranger, "proof_1")).rejects.toThrow(
      "Proof does not belong to this user",
    );
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it("throws NotFoundException for a proof that does not exist", async () => {
    const prisma = {
      proof: { findUnique: jest.fn().mockResolvedValue(null) },
      $transaction: jest.fn(),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
    );

    await expect(service.revokeProof(user, "missing_proof")).rejects.toThrow(
      "Proof not found",
    );
  });

  it("is idempotent: a second revocation returns the original metadata unchanged and does not open a new transaction", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          userId: "user_1",
          status: ProofStatus.REVOKED,
          contractTransactionHash: null,
          revokedAt: new Date("2026-08-01T00:00:00.000Z"),
          revokedByType: "OWNER",
          revocationReasonCode: "DUPLICATE_PROOF",
          revocationReasonPrivate: "original note",
          revocationEvidenceHash: null,
        }),
      },
      $transaction: jest.fn(),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
    );

    const result = await service.revokeProof(user, "proof_1", {
      reasonCode: "FRAUD_SUSPECTED",
      reasonPrivate: "an attempt to overwrite the original reason",
    });

    expect(result.revocationReasonCode).toBe("DUPLICATE_PROOF");
    expect(result.revocationReasonPrivate).toBe("original note");
    expect(result.revokedAt).toBe("2026-08-01T00:00:00.000Z");
    // No write is attempted at all for an already-revoked proof.
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it("does not enqueue a REVOKE intent when the proof was never anchored", async () => {
    const capturedIntentCreate = jest.fn();
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: null,
        }),
      },
      $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) =>
        fn({
          proof: {
            update: jest.fn().mockResolvedValue({
              id: "proof_1",
              status: ProofStatus.REVOKED,
              revokedAt: new Date("2026-08-04T00:00:00.000Z"),
              revokedByType: "OWNER",
              revocationReasonCode: "OWNER_REQUESTED",
              revocationReasonPrivate: null,
              revocationEvidenceHash: null,
            }),
          },
          auditLog: { create: jest.fn().mockResolvedValue({}) },
          anchoringIntent: { create: capturedIntentCreate },
        }),
      ),
    };
    const service = new ProofsService(
      prisma as never,
      makeConfig(true) as never, // anchoring enabled, but proof was never anchored
      mockVerificationEventService,
    );

    const result = await service.revokeProof(user, "proof_1");

    expect(result.anchoring).toEqual({ anchored: false, reason: "disabled" });
    expect(capturedIntentCreate).not.toHaveBeenCalled();
  });

  it("fails the whole revocation when the audit write fails, leaving no partial state observable to the caller", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: null,
        }),
      },
      $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) =>
        fn({
          proof: {
            update: jest.fn().mockResolvedValue({
              id: "proof_1",
              status: ProofStatus.REVOKED,
              revokedAt: new Date("2026-08-04T00:00:00.000Z"),
            }),
          },
          auditLog: {
            create: jest.fn().mockRejectedValue(new Error("audit store unavailable")),
          },
          anchoringIntent: { create: jest.fn() },
        }),
      ),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
    );

    await expect(service.revokeProof(user, "proof_1")).rejects.toThrow(
      "audit store unavailable",
    );
  });

  it("uses revoked on-chain status during public verification", async () => {
    const credential = {
      id: "proof_onchain_revoked",
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: "earnproof.minimum-income.v1",
      issuer: "earnproof-backend",
      subject: { walletHash: "sha256:wallet" },
      claim: {
        operator: "gte",
        thresholdAmount: "100",
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
        qualifyingPaymentCount: 1,
      },
      privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true },
      issuedAt: "2026-08-02T00:00:00.000Z",
      expiresAt: "2027-09-01T00:00:00.000Z",
    };
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_onchain_revoked",
          proofType: ProofType.MINIMUM_INCOME,
          schemaVersion: "earnproof.minimum-income.v1",
          status: ProofStatus.ACTIVE,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: new Date("2026-08-01T00:00:00.000Z"),
          periodEnd: new Date("2026-08-31T23:59:59.000Z"),
          expiresAt: new Date("2027-09-01T00:00:00.000Z"),
          revokedAt: null,
          createdAt: new Date("2026-08-02T00:00:00.000Z"),
          credentialHash: `sha256:${sha256(canonicalize(credential))}`,
          contractTransactionHash: "tx_register",
          user: { walletHash: "sha256:wallet" },
          claim: {
            thresholdEncrypted: `redacted:${Buffer.from("100").toString("base64url")}`,
            disclosurePolicy: { qualifyingPaymentCount: 1 },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const anchoring = {
      getProofStatus: jest.fn().mockResolvedValue({
        checked: true,
        revoked: true,
        valid: false,
      }),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
      anchoring as never,
    );

    const result = await service.verifyProof("proof_onchain_revoked");

    expect(result.result).toBe(VerificationResult.REVOKED);
    expect(result.status).toBe("revoked");
    expect(result.proof?.contractStatus).toEqual({
      checked: true,
      revoked: true,
      valid: false,
    });
  });

  // ---------------------------------------------------------------------------
  // Outbox / anchoring policy tests
  // ---------------------------------------------------------------------------

  describe("anchoring outbox — same-transaction intent creation", () => {
    it("writes REGISTER AnchoringIntent inside the proof creation transaction when anchoring is enabled", async () => {
      const capturedIntents: unknown[] = [];
      const prisma = makeCreatePrisma((data) => capturedIntents.push(data));
      const service = new ProofsService(
        prisma as never,
        makeConfig(true) as never, // anchoring enabled
        mockVerificationEventService,
      );

      await service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      });

      expect(capturedIntents).toHaveLength(1);
      expect(capturedIntents[0]).toMatchObject({
        operation: AnchoringOperation.REGISTER,
        status: AnchoringStatus.PENDING,
      });
    });

    it("does NOT write an AnchoringIntent when anchoring is disabled", async () => {
      const capturedIntents: unknown[] = [];
      const prisma = makeCreatePrisma((data) => capturedIntents.push(data));
      const service = new ProofsService(
        prisma as never,
        makeConfig(false) as never, // anchoring disabled
        mockVerificationEventService,
      );

      await service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      });

      expect(capturedIntents).toHaveLength(0);
    });

    it("returns anchoring: pending when anchoring is enabled (not waiting for CLI)", async () => {
      const prisma = makeCreatePrisma();
      const service = new ProofsService(
        prisma as never,
        makeConfig(true) as never,
        mockVerificationEventService,
      );

      const result = await service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      });

      expect(result.anchoring).toEqual({ anchored: false, reason: "pending" });
    });

    it("returns anchoring: disabled when anchoring is not enabled", async () => {
      const prisma = makeCreatePrisma();
      const service = new ProofsService(
        prisma as never,
        makeConfig(false) as never,
        mockVerificationEventService,
      );

      const result = await service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      });

      expect(result.anchoring).toEqual({ anchored: false, reason: "disabled" });
    });
  });

  describe("required anchoring policy — verify endpoint", () => {
    function makeVerifyProof(contractTransactionHash: string | null, credOverrides: Record<string, unknown> = {}) {
      const credential = {
        id: "proof_req",
        type: "EarnProofMinimumIncomeCredential",
        schemaVersion: "earnproof.minimum-income.v1",
        issuer: "earnproof-backend",
        subject: { walletHash: "sha256:wallet" },
        claim: {
          operator: "gte",
          thresholdAmount: "100",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: "2026-08-01T00:00:00.000Z",
          periodEnd: "2026-08-31T23:59:59.000Z",
          qualifyingPaymentCount: 1,
        },
        privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true },
        issuedAt: "2026-08-02T00:00:00.000Z",
        expiresAt: "2027-09-01T00:00:00.000Z",
        ...credOverrides,
      };
      return {
        proof: {
          findUnique: jest.fn().mockResolvedValue({
            id: "proof_req",
            proofType: ProofType.MINIMUM_INCOME,
            schemaVersion: "earnproof.minimum-income.v1",
            status: ProofStatus.ACTIVE,
            network: "testnet",
            assetCode: "XLM",
            assetIssuer: null,
            periodStart: new Date("2026-08-01T00:00:00.000Z"),
            periodEnd: new Date("2026-08-31T23:59:59.000Z"),
            expiresAt: new Date("2027-09-01T00:00:00.000Z"),
            revokedAt: null,
            createdAt: new Date("2026-08-02T00:00:00.000Z"),
            credentialHash: `sha256:${sha256(canonicalize(credential))}`,
            contractTransactionHash,
            user: { walletHash: "sha256:wallet" },
            claim: {
              thresholdEncrypted: `redacted:${Buffer.from("100").toString("base64url")}`,
              disclosurePolicy: { qualifyingPaymentCount: 1 },
            },
          }),
        },
        verificationEvent: {
          create: jest.fn().mockResolvedValue({ id: "event_1" }),
        },
      };
    }


    it("returns UNVERIFIED_ISSUER when anchoring is required and proof has no contractTransactionHash (anchoring still pending)", async () => {
      const prisma = makeVerifyProof(null); // no tx hash yet
      const service = new ProofsService(
        prisma as never,
        makeConfig(true, true) as never, // enabled + required
        mockVerificationEventService,
      );

      const result = await service.verifyProof("proof_req");

      expect(result.result).toBe(VerificationResult.UNVERIFIED_ISSUER);
    });

    it("returns VALID when anchoring is required and proof has a contractTransactionHash (anchored)", async () => {
      const prisma = makeVerifyProof("tx_confirmed");
      const service = new ProofsService(
        prisma as never,
        makeConfig(true, true) as never,
        mockVerificationEventService,
      );

      const result = await service.verifyProof("proof_req");

      expect(result.result).toBe(VerificationResult.VALID);
    });

    it("returns VALID (not UNVERIFIED_ISSUER) when anchoring is optional even without contractTransactionHash", async () => {
      const prisma = makeVerifyProof(null);
      // optional: enabled=true, required=false
      const service = new ProofsService(
        prisma as never,
        makeConfig(true, false) as never,
        mockVerificationEventService,
      );

      const result = await service.verifyProof("proof_req");

      expect(result.result).toBe(VerificationResult.VALID);
    });

    it("returns VALID when anchoring is fully disabled even without contractTransactionHash", async () => {
      const prisma = makeVerifyProof(null);
      const service = new ProofsService(
        prisma as never,
        makeConfig(false, false) as never,
        mockVerificationEventService,
      );

      const result = await service.verifyProof("proof_req");

      expect(result.result).toBe(VerificationResult.VALID);
    });
  });
});

