import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Cron, CronExpression } from "@nestjs/schedule";
import { PrismaService } from "../database/prisma.service";
import { AuthAuditService } from "./auth-audit.service";
import { SessionService } from "./session.service";

@Injectable()
export class CleanupJob {
  private readonly logger = new Logger(CleanupJob.name);
  private readonly challengeRetentionDays: number;
  private readonly auditRetentionDays: number;

  constructor(
    private readonly sessionService: SessionService,
    private readonly auditService: AuthAuditService,
    private readonly prisma: PrismaService,
    configService: ConfigService,
  ) {
    this.challengeRetentionDays = Number(
      configService.get<number>("auth.challengeRetentionDays") ?? 7,
    );
    this.auditRetentionDays = Number(
      configService.get<number>("auth.auditRetentionDays") ?? 90,
    );
  }

  @Cron(
    process.env.AUTH_SESSION_CLEANUP_CRON ??
      CronExpression.EVERY_DAY_AT_MIDNIGHT,
  )
  async deleteExpiredSessions(): Promise<void> {
    const deleted = await this.sessionService.deleteExpired();
    this.logger.log(`Removed ${deleted} expired authentication session(s)`);
  }

  @Cron(
    process.env.AUTH_CHALLENGE_CLEANUP_CRON ??
      CronExpression.EVERY_DAY_AT_2AM,
  )
  async deleteOldChallenges(): Promise<void> {
    const deleted = await this.cleanupChallenges();
    this.logger.log(`Removed ${deleted} old challenge record(s)`);
  }

  @Cron(
    process.env.AUTH_AUDIT_CLEANUP_CRON ??
      CronExpression.EVERY_DAY_AT_3AM,
  )
  async deleteOldAuditEvents(): Promise<void> {
    const deleted = await this.auditService.cleanupOldEvents(
      this.auditRetentionDays,
    );
    this.logger.log(`Removed ${deleted} old auth audit event(s)`);
  }

  @Cron(
    process.env.AUTH_WALLET_ROTATION_CLEANUP_CRON ??
      CronExpression.EVERY_DAY_AT_2AM,
  )
  async deleteOldWalletRotations(): Promise<void> {
    const deleted = await this.cleanupWalletRotations();
    this.logger.log(`Removed ${deleted} old wallet rotation record(s)`);
  }

  /**
   * Delete wallet rotations whose deadline passed more than the challenge
   * retention window ago, whatever their outcome.
   *
   * A rotation row holds both wallet addresses in the clear; once the
   * rotation can no longer be completed it is only evidence, and the durable
   * evidence is the `user.wallet_rotated` audit record, which holds hashes.
   *
   * @returns Number of rotations deleted
   */
  async cleanupWalletRotations(now: Date = new Date()): Promise<number> {
    try {
      const cutoff = new Date(
        now.getTime() - this.challengeRetentionDays * 24 * 60 * 60 * 1000,
      );
      const result = await this.prisma.walletRotation.deleteMany({
        where: { expiresAt: { lt: cutoff } },
      });
      return result.count;
    } catch (error) {
      this.logger.error(
        `Wallet rotation cleanup failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return 0;
    }
  }

  /**
   * Clean up expired and sufficiently old used challenges.
   *
   * Removes:
   * 1. All expired challenges (past expiresAt)
   * 2. Used challenges older than retention period
   *
   * Bounded batch operation to avoid long-running transactions.
   *
   * @returns Number of challenges deleted
   */
  private async cleanupChallenges(): Promise<number> {
    try {
      const now = new Date();
      const retentionCutoff = new Date(
        now.getTime() - this.challengeRetentionDays * 24 * 60 * 60 * 1000,
      );

      // Delete in two phases to keep queries simple and indexed

      // Phase 1: Delete all expired challenges
      const expiredResult = await this.prisma.walletChallenge.deleteMany({
        where: {
          expiresAt: {
            lt: now,
          },
        },
      });

      // Phase 2: Delete old used challenges (beyond retention window)
      const usedResult = await this.prisma.walletChallenge.deleteMany({
        where: {
          usedAt: {
            not: null,
            lt: retentionCutoff,
          },
        },
      });

      const totalDeleted = expiredResult.count + usedResult.count;

      this.logger.log(
        `Challenge cleanup: deleted ${expiredResult.count} expired, ${usedResult.count} old used (total: ${totalDeleted})`,
      );

      return totalDeleted;
    } catch (error) {
      this.logger.error(
        `Challenge cleanup failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return 0;
    }
  }
}
