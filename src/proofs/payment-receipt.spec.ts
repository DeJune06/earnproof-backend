import {
  NotFoundException,
  UnprocessableEntityException,
} from "@nestjs/common";
import {
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { ApiErrorCode } from "../common/dto/api-error.dto";
import { ProofsService } from "./proofs.service";

describe("ProofsService payment-receipt proofs", () => {
  const user = {
    id: "user_1",
    walletAddress: "GB_OWNER",
    walletHash: "sha256:owner",
    role: "WORKER",
  };
  const payment: {
    operationId: string;
    sourceAddress: string;
    assetCode: string;
    assetIssuer: string | null;
    amountEncrypted: string | null;
    classification: PaymentClassification;
    isEligible: boolean;
    occurredAt: Date;
  } = {
    operationId: "public-operation-id",
    sourceAddress: "GB_SECRET_SENDER",
    assetCode: "USDC",
    assetIssuer: "GB_ASSET_ISSUER",
    amountEncrypted: `redacted:${Buffer.from("125.5000000").toString("base64url")}`,
    classification: PaymentClassification.INCOME,
    isEligible: true,
    occurredAt: new Date("2026-08-01T12:00:00.000Z"),
  };
  const configValues: Record<string, unknown> = {
    credentialSigningSecret: "test-signing-secret",
    paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    "stellar.network": "testnet",
  };
  const config = {
    get: jest.fn((key: string) => (key in configValues ? configValues[key] : false)),
    getOrThrow: jest.fn((key: string) => configValues[key]),
  };
  const events = {
    recordEvent: jest.fn().mockResolvedValue(undefined),
    getAggregateStats: jest.fn(),
  };

  function harness(
    selectedPayment: typeof payment | null = payment,
    contract?: Record<string, jest.Mock>,
  ) {
    let storedProof: any;
    const prisma: any = {
      payment: {
        findFirst: jest.fn().mockResolvedValue(selectedPayment),
      },
      proof: {
        create: jest.fn().mockImplementation(({ data }) => {
          storedProof = {
            ...data,
            updatedAt: data.createdAt,
            contractTransactionHash: null,
            revokedAt: null,
            user: { walletHash: user.walletHash },
            claim: {
              id: "claim_1",
              proofId: data.id,
              createdAt: data.createdAt,
              frequency: null,
              ...data.claim.create,
            },
          };
          return storedProof;
        }),
        findUnique: jest.fn().mockImplementation(() => storedProof),
        update: jest.fn().mockImplementation(({ data }) => {
          storedProof = { ...storedProof, ...data };
          return {
            id: storedProof.id,
            status: storedProof.status,
            revokedAt: storedProof.revokedAt,
          };
        }),
      },
      verificationEvent: { create: jest.fn().mockResolvedValue({}) },
      anchoringIntent: { create: jest.fn().mockResolvedValue({}) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    prisma.$transaction = jest.fn(async (callback) => callback(prisma));
    const harnessConfig = {
      ...config,
      get: jest.fn((key: string) =>
        key === "contractAnchoring.enabled" ? Boolean(contract) : config.get(key),
      ),
    };
    const service = new ProofsService(
      prisma as never,
      harnessConfig as never,
      events as never,
      contract as never,
    );
    return { service, prisma, getStoredProof: () => storedProof };
  }

  it("uses an owner-scoped lookup and hides sender and amount by default", async () => {
    const { service, prisma, getStoredProof } = harness();

    const result = await service.createPaymentReceiptProof(user, {
      paymentId: "payment_1",
    });
    const serialized = JSON.stringify(result);

    expect(prisma.payment.findFirst).toHaveBeenCalledWith({
      where: { id: "payment_1", userId: "user_1" },
      select: expect.any(Object),
    });
    expect(result.credential).toMatchObject({
      type: "EarnProofPaymentReceiptCredential",
      schemaVersion: "earnproof.payment-receipt.v1",
      privacy: { senderHidden: true, amountHidden: true },
    });
    expect(result.credential.claim).not.toHaveProperty("sourceAddress");
    expect(result.credential.claim).not.toHaveProperty("amount");
    expect(serialized).not.toContain(payment.sourceAddress);
    expect(serialized).not.toContain("125.5000000");
    expect(serialized).not.toContain(payment.operationId);
    expect(getStoredProof()).toMatchObject({
      proofType: ProofType.PAYMENT_RECEIPT,
      schemaVersion: "earnproof.payment-receipt.v1",
      claim: {
        disclosurePolicy: { senderHidden: true, amountHidden: true },
        thresholdEncrypted: null,
      },
    });
  });

  it.each([
    [true, false],
    [false, true],
    [true, true],
  ])(
    "applies sender=%s and amount=%s disclosure independently",
    async (discloseSender, discloseAmount) => {
      const { service, getStoredProof } = harness();
      const result = await service.createPaymentReceiptProof(user, {
        paymentId: "payment_1",
        discloseSender,
        discloseAmount,
      });

      expect(result.credential.claim).toEqual(
        expect.objectContaining({
          ...(discloseSender
            ? { sourceAddress: payment.sourceAddress }
            : undefined),
          ...(discloseAmount ? { amount: "125.5000000" } : undefined),
        }),
      );
      if (discloseSender) {
        expect(result.credential.claim).toHaveProperty(
          "sourceAddress",
          payment.sourceAddress,
        );
      } else {
        expect(result.credential.claim).not.toHaveProperty("sourceAddress");
      }
      if (!discloseAmount) {
        expect(result.credential.claim).not.toHaveProperty("amount");
      }
      expect(getStoredProof().claim.disclosurePolicy).toMatchObject({
        senderHidden: !discloseSender,
        amountHidden: !discloseAmount,
      });
    },
  );

  it("makes missing and non-owned payments indistinguishable", async () => {
    const { service } = harness(null);

    for (const paymentId of ["missing", "belongs-to-another-user"]) {
      try {
        await service.createPaymentReceiptProof(user, { paymentId });
        throw new Error("Expected payment lookup to fail");
      } catch (error) {
        expect(error).toBeInstanceOf(NotFoundException);
        expect((error as NotFoundException).getResponse()).toEqual({
          code: ApiErrorCode.PAYMENT_NOT_FOUND,
          message: "Payment not found",
        });
      }
    }
  });

  it("rejects ineligibility before exclusion and uses stable codes", async () => {
    const both = harness({
      ...payment,
      isEligible: false,
      classification: PaymentClassification.EXCLUDED,
    });
    await expect(
      both.service.createPaymentReceiptProof(user, { paymentId: "payment_1" }),
    ).rejects.toMatchObject({
      constructor: UnprocessableEntityException,
      response: {
        code: ApiErrorCode.PAYMENT_NOT_ELIGIBLE,
      },
    });

    const excluded = harness({
      ...payment,
      classification: PaymentClassification.EXCLUDED,
    });
    await expect(
      excluded.service.createPaymentReceiptProof(user, {
        paymentId: "payment_1",
      }),
    ).rejects.toMatchObject({
      response: { code: ApiErrorCode.PAYMENT_EXCLUDED },
    });
  });

  it("reconstructs a valid receipt and detects tampering", async () => {
    const { service, getStoredProof } = harness();
    const created = await service.createPaymentReceiptProof(user, {
      paymentId: "payment_1",
      discloseSender: true,
      discloseAmount: true,
    });

    await expect(service.verifyProof(created.proofId)).resolves.toMatchObject({
      result: VerificationResult.VALID,
      credential: created.credential,
    });

    getStoredProof().credentialHash = "sha256:tampered";
    await expect(service.verifyProof(created.proofId)).resolves.toMatchObject({
      result: VerificationResult.INVALID_SIGNATURE,
      status: "invalid",
    });
  });

  it("uses existing expiration and revocation behavior", async () => {
    const { service, getStoredProof } = harness();
    const created = await service.createPaymentReceiptProof(user, {
      paymentId: "payment_1",
    });

    jest.useFakeTimers().setSystemTime(new Date("2100-01-01T00:00:00.000Z"));
    try {
      await expect(service.verifyProof(created.proofId)).resolves.toMatchObject(
        {
          result: VerificationResult.EXPIRED,
        },
      );
    } finally {
      jest.useRealTimers();
    }

    getStoredProof().status = ProofStatus.REVOKED;
    await expect(service.verifyProof(created.proofId)).resolves.toMatchObject({
      result: VerificationResult.REVOKED,
    });
  });

  it("enqueues issuance and revocation without calling the contract inline", async () => {
    const contract = {
      anchorProof: jest
        .fn()
        .mockResolvedValue({ anchored: true, transactionHash: "anchor_tx" }),
      revokeProof: jest
        .fn()
        .mockResolvedValue({ anchored: true, transactionHash: "revoke_tx" }),
      getProofStatus: jest.fn(),
    };
    const { service, prisma, getStoredProof } = harness(payment, contract);
    const created = await service.createPaymentReceiptProof(user, {
      paymentId: "payment_1",
    });

    expect(created.anchoring).toEqual({
      anchored: false,
      reason: "pending",
    });
    expect(contract.anchorProof).not.toHaveBeenCalled();
    expect(prisma.anchoringIntent.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        proofId: created.proofId,
        operation: "REGISTER",
        status: "PENDING",
      }),
    });

    getStoredProof().contractTransactionHash = "anchor_tx";

    const revoked = await service.revokeProof(user, created.proofId);
    expect(revoked.status).toBe(ProofStatus.REVOKED);
    expect(contract.revokeProof).not.toHaveBeenCalled();
    expect(prisma.anchoringIntent.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        proofId: created.proofId,
        operation: "REVOKE",
        status: "PENDING",
      }),
    });
  });
});
