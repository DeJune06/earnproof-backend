import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PrismaService } from "../database/prisma.service";
import {
  DEFAULT_ATTESTATION_CLOCK_SKEW_MS,
  EffectiveAttestationStatus,
  canAttestationAuthorizeIssuance,
  computeEffectiveAttestationStatus,
} from "./attestation-status";

/**
 * Read side of issuer attestation status (#207).
 *
 * The effective status is computed on read from the untouched stored fields, so
 * it is correct the instant an attestation expires — even before the
 * reconciliation job has moved the stored `status`. Both readers use the same
 * pure function, so the scheduled job and this API never disagree.
 */
@Injectable()
export class AttestationsService {
  private readonly clockSkewMs: number;

  constructor(
    private readonly prisma: PrismaService,
    config: ConfigService,
  ) {
    this.clockSkewMs = config.get<number>(
      "attestation.clockSkewMs",
      DEFAULT_ATTESTATION_CLOCK_SKEW_MS,
    );
  }

  /** Effective status of an attestation right now. */
  async getEffectiveStatus(
    attestationId: string,
    now: Date = new Date(),
  ): Promise<EffectiveAttestationStatus> {
    const attestation = await this.prisma.attestation.findUnique({
      where: { id: attestationId },
      select: { status: true, expiresAt: true, revokedAt: true },
    });
    if (!attestation) {
      throw new NotFoundException("Attestation not found");
    }
    return computeEffectiveAttestationStatus(attestation, now, this.clockSkewMs);
  }

  /**
   * Whether an attestation may authorize new issuance right now.
   *
   * Computed from the live fields, so an expired attestation is refused the
   * moment it expires regardless of whether the reconciler has run yet.
   */
  async canAuthorizeIssuance(
    attestationId: string,
    now: Date = new Date(),
  ): Promise<boolean> {
    const attestation = await this.prisma.attestation.findUnique({
      where: { id: attestationId },
      select: { status: true, expiresAt: true, revokedAt: true },
    });
    if (!attestation) return false;
    return canAttestationAuthorizeIssuance(attestation, now, this.clockSkewMs);
  }

  /**
   * Throw unless an attestation may authorize new issuance.
   *
   * A single guard for issuance call sites, so "expired attestations cannot
   * authorize new issuance" is enforced in one place rather than re-derived at
   * each caller.
   */
  async assertCanAuthorizeIssuance(
    attestationId: string,
    now: Date = new Date(),
  ): Promise<void> {
    if (!(await this.canAuthorizeIssuance(attestationId, now))) {
      throw new ForbiddenException(
        "Attestation is not in an active state and cannot authorize issuance",
      );
    }
  }
}
