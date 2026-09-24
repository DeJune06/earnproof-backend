import {
  BadRequestException,
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
  PaymentClassification,
  Proof,
  ProofClaim,
  Prisma,
  ProofStatus,
  ProofType,
  RevocationActorType,
  RevocationReasonCode,
  VerificationResult,
  VerificationOutcome,
} from "@prisma/client";
import { createHmac, randomUUID } from "crypto";
import { VerificationEventService } from "../audit/verification-event.service";
import { AuthenticatedUser } from "../auth/auth.types";
import { canonicalize } from "../common/crypto/canonicalize";
import { sha256 } from "../common/crypto/hash";
import { PaymentEncryptionKeyringService } from "../common/crypto/payment-encryption-keyring.service";
import { ApiErrorCode } from "../common/dto/api-error.dto";
import { PrismaService } from "../database/prisma.service";
import { WebhookDeliveryService } from "../webhooks/webhook-delivery.service";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";
import { CreatePaymentReceiptProofDto } from "./dto/create-payment-receipt-proof.dto";
import {
  CreateRecurringIncomeProofDto,
  IntervalUnit,
} from "./dto/create-recurring-income-proof.dto";
import { ListProofsDto } from "./dto/list-proofs.dto";
import { RevokeProofDto } from "./dto/revoke-proof.dto";

const SCHEMA_VERSION = "earnproof.minimum-income.v1";
const PAYMENT_RECEIPT_SCHEMA_VERSION = "earnproof.payment-receipt.v1";
const RECURRING_INCOME_SCHEMA_VERSION = "earnproof.recurring-income.v1";
const DEFAULT_EXPIRY_DAYS = 30;

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

type EarnProofCredential =
  | MinimumIncomeCredential
  | PaymentReceiptCredential
  | RecurringIncomeCredential;

@Injectable()
export class ProofsService {
  private readonly signingSecret: string;
  private readonly paymentEncryptionKeyring: PaymentEncryptionKeyringService;
  private readonly stellarNetwork: string;
  private readonly anchoringEnabled: boolean;
  private readonly anchoringRequired: boolean;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
    private readonly verificationEventService: VerificationEventService,
    @Optional()
    private readonly contractAnchoringService?: ContractAnchoringService,
    @Optional()
    private readonly webhookDeliveryService?: WebhookDeliveryService,
  ) {
    this.signingSecret = configService.getOrThrow<string>(
      "credentialSigningSecret",
    );
    this.paymentEncryptionKeyring = new PaymentEncryptionKeyringService(
      configService,
    );
    this.stellarNetwork = configService.getOrThrow<string>("stellar.network");
    this.anchoringEnabled =
      configService.get<boolean>("contractAnchoring.enabled") ?? false;
    this.anchoringRequired =
      configService.get<boolean>("contractAnchoring.required") ?? false;
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
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        classification: true,
        isEligible: true,
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
    if (payment.classification === PaymentClassification.EXCLUDED) {
      throw new UnprocessableEntityException({
        code: ApiErrorCode.PAYMENT_EXCLUDED,
        message: "Payment is excluded from proof issuance",
      });
    }

    const senderHidden = input.discloseSender !== true;
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
      sourceAddress: senderHidden ? undefined : payment.sourceAddress,
      amount,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(canonicalize(credential))}`;
    const commitment = `sha256:${sha256(credentialHash)}`;

    const proof = await this.prisma.$transaction(async (tx) => {
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
                ...(senderHidden
                  ? undefined
                  : { sourceAddress: payment.sourceAddress }),
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
    });

    return {
      ...updated,
      revokedAt: updated.revokedAt?.toISOString() ?? revokedAt.toISOString(),
      anchoring: anchoringResult,
    };
  }

  async verifyProof(proofId: string) {
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

    if (!proof || !proof.claim) {
      // Fail-open policy: record event asynchronously
      // If event recording fails, the verification response is still returned.
      // This ensures verification availability over audit completeness.
      this.verificationEventService
        .recordEvent(VerificationOutcome.UNKNOWN, proofId, {
          outcome: "UNKNOWN",
          timestamp: new Date(),
        })
        .catch(() => {
          // Error already logged by the service
          // Verification continues unblocked
        });

      return {
        result: VerificationResult.UNKNOWN_PROOF,
        status: "unknown",
      };
    }

    const policy = this.jsonPolicy(proof.claim.disclosurePolicy);
    const cadence = this.revealCadence(proof.claim.frequency);
    const credential =
      proof.proofType === ProofType.RECURRING_INCOME
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

    const contractStatus = proof.contractTransactionHash
      ? await this.contractAnchoringService?.getProofStatus(proof.id)
      : undefined;

    if (contractStatus?.checked) {
      if (contractStatus.revoked) {
        result = VerificationResult.REVOKED;
      } else if (result === VerificationResult.VALID && !contractStatus.valid) {
        result = VerificationResult.INVALID_SIGNATURE;
      }
    }

    // Convert VerificationResult to VerificationOutcome for event recording
    const outcome = this.mapResultToOutcome(result);

    // Fail-open policy: record verification event asynchronously
    // If event recording fails, the verification response is still returned.
    // This ensures verification availability over audit completeness.
    // Event recording errors are caught and logged by the service.
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

    this.emitWebhook(proof.userId, "proof.verified", {
      proofId: proof.id,
      result,
      verifiedAt: new Date().toISOString(),
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
    this.emitWebhook(userId, "proof.created", {
      proofId: proof.id,
      proofType: proof.proofType,
      schemaVersion: proof.schemaVersion,
      status: proof.status,
      network: proof.network,
      assetCode: proof.assetCode,
      assetIssuer: proof.assetIssuer,
      periodStart: proof.periodStart?.toISOString() ?? null,
      periodEnd: proof.periodEnd?.toISOString() ?? null,
      expiresAt: proof.expiresAt.toISOString(),
      credentialHash: proof.credentialHash,
      contractTransactionHash: proof.contractTransactionHash ?? null,
      issuedAt: proof.createdAt.toISOString(),
    });
  }

  private emitWebhook(
    userId: string,
    event: "proof.created" | "proof.revoked" | "proof.verified",
    data: Record<string, unknown>,
  ) {
    this.webhookDeliveryService
      ?.enqueueForUser(userId, event, { event, data } as never)
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

  private signCredential<T extends EarnProofCredential>(credential: T) {
    const canonicalPayload = canonicalize(credential);
    return {
      ...credential,
      proof: {
        type: "HMAC-SHA256",
        credentialHash: `sha256:${sha256(canonicalPayload)}`,
        signature: `hmac-sha256:${createHmac("sha256", this.signingSecret)
          .update(canonicalPayload)
          .digest("base64url")}`,
      },
    };
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
}
