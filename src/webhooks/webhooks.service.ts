import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ResourceStatus } from "@prisma/client";
import { randomBytes } from "crypto";
import { PaymentEncryptionKeyringService } from "../common/crypto/payment-encryption-keyring.service";
import { PrismaService } from "../database/prisma.service";
import { ConflictException } from "../common/exceptions/domain.exceptions";
import { CreateWebhookDto } from "./dto/create-webhook.dto";
import { UpdateWebhookEventsDto } from "./dto/update-webhook-events.dto";
import { OrganizationQuotaService } from "../quotas/organization-quota.service";
import { WebhookDeliveryService } from "./webhook-delivery.service";
import { WebhookCircuitBreakerService } from "./webhook-circuit-breaker.service";

/** Signing secret length in bytes (produces a 64-char hex string). */
const SECRET_BYTES = 32;

@Injectable()
export class WebhooksService {
  private readonly paymentEncryptionKeyring: PaymentEncryptionKeyringService;

  constructor(
    private readonly prisma: PrismaService,
    private readonly deliveryService: WebhookDeliveryService,
    private readonly circuitBreaker: WebhookCircuitBreakerService,
    configService: ConfigService,
    private readonly quotas: OrganizationQuotaService,
  ) {
    this.paymentEncryptionKeyring = new PaymentEncryptionKeyringService(
      configService,
    );
  }

  /**
   * Create a webhook endpoint for the given organisation.
   *
   * Returns the raw signing secret ONCE — it is never retrievable again.
   * The caller must store it securely.
   */
  async create(organizationId: string, dto: CreateWebhookDto) {
    const rawSecret = randomBytes(SECRET_BYTES).toString("hex");
    const secretEncrypted = this.paymentEncryptionKeyring.encrypt(rawSecret);

    // De-duplicate events list
    const events = [...new Set(dto.events)];

    // Quota check and creation commit together; see OrganizationQuotaService.
    const webhook = await this.prisma.$transaction(async (tx) => {
      await this.quotas.assertCapacity(tx, organizationId, "webhooks");
      return tx.webhook.create({
        data: {
          organizationId,
          url: dto.url,
          secretEncrypted,
          events,
          payloadVersion: dto.payloadVersion ?? CURRENT_WEBHOOK_PAYLOAD_VERSION,
          status: ResourceStatus.ACTIVE,
        },
        select: {
          id: true,
          url: true,
          events: true,
          payloadVersion: true,
          status: true,
          createdAt: true,
        },
      });
    const webhook = await this.prisma.webhook.create({
      data: {
        organizationId,
        url: dto.url,
        secretEncrypted,
        events,
        status: ResourceStatus.ACTIVE,
        revision: 0,
      },
      select: {
        id: true,
        url: true,
        events: true,
        status: true,
        revision: true,
        createdAt: true,
      },
    });

    // Initialize circuit breaker for new webhook
    await this.circuitBreaker.initializeCircuit(webhook.id);

    return {
      ...webhook,
      // Returned once at creation time only.
      signingSecret: rawSecret,
    };
  }

  /** List all webhook endpoints for an organisation. */
  listForOrg(organizationId: string) {
    return this.prisma.webhook.findMany({
      where: { organizationId },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        url: true,
        events: true,
        payloadVersion: true,
        status: true,
        revision: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /** Get a single webhook, asserting ownership. */
  async getForOrg(organizationId: string, webhookId: string) {
    const webhook = await this.prisma.webhook.findUnique({
      where: { id: webhookId },
      select: {
        id: true,
        organizationId: true,
        url: true,
        events: true,
        payloadVersion: true,
        status: true,
        revision: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    this.assertOwnership(webhook, organizationId, webhookId);
    return webhook!;
  }

  /**
   * Rotate the signing secret.
   *
   * Returns the new raw secret once.  In-flight deliveries using the old
   * secret will fail (they will retry using the new secret on the next
   * attempt, since they re-decrypt at execution time).
   */
  async rotateSecret(organizationId: string, webhookId: string) {
    const webhook = await this.assertOwnedWebhook(organizationId, webhookId);

    const newRawSecret = randomBytes(SECRET_BYTES).toString("hex");
    const newSecretEncrypted = this.paymentEncryptionKeyring.encrypt(newRawSecret);

    await this.prisma.webhook.update({
      where: { id: webhookId },
      data: {
        secretEncrypted: newSecretEncrypted,
        revision: webhook.revision + 1,
      },
    });

    return {
      webhookId,
      signingSecret: newRawSecret,
      rotatedAt: new Date().toISOString(),
      note: "Any in-flight deliveries signed with the old secret will fail their current attempt. They will be retried with the new secret.",
    };
  }

  /** Update subscribed event types. */
  async updateEvents(
    organizationId: string,
    webhookId: string,
    dto: UpdateWebhookEventsDto,
  ) {
    const webhook = await this.assertOwnedWebhook(organizationId, webhookId);
    const events = [...new Set(dto.events)];

    // Attempt optimistic update with revision check
    const updated = await this.prisma.webhook.updateMany({
      where: {
        id: webhookId,
        revision: dto.expectedRevision,
      },
      data: {
        events,
        revision: dto.expectedRevision + 1,
      },
    });

    // If no records were updated, the revision didn't match
    if (updated.count === 0) {
      throw new ConflictException(
        "Webhook has been modified by another request. Please refresh and retry.",
        webhook.revision,
      );
    }

    return this.prisma.webhook.findUnique({
      where: { id: webhookId },
      select: { id: true, url: true, events: true, status: true, revision: true, updatedAt: true },
    });
  }

  /** Disable (suspend) a webhook endpoint without deleting it. */
  async disable(organizationId: string, webhookId: string) {
    const webhook = await this.assertOwnedWebhook(organizationId, webhookId);

    return this.prisma.webhook.update({
      where: { id: webhookId },
      data: {
        status: ResourceStatus.SUSPENDED,
        revision: webhook.revision + 1,
      },
      select: { id: true, status: true, revision: true, updatedAt: true },
    });
  }

  /** Re-enable a previously disabled webhook endpoint. */
  async enable(organizationId: string, webhookId: string) {
    const webhook = await this.assertOwnedWebhook(organizationId, webhookId);

    return this.prisma.webhook.update({
      where: { id: webhookId },
      data: {
        status: ResourceStatus.ACTIVE,
        revision: webhook.revision + 1,
      },
      select: { id: true, status: true, revision: true, updatedAt: true },
    });
  }

  /** Soft-delete (mark DELETED) a webhook endpoint. */
  async delete(organizationId: string, webhookId: string) {
    const webhook = await this.assertOwnedWebhook(organizationId, webhookId);

    await this.prisma.webhook.update({
      where: { id: webhookId },
      data: {
        status: ResourceStatus.DELETED,
        revision: webhook.revision + 1,
      },
    });

    // Clean up circuit breaker state
    await this.circuitBreaker.deleteCircuitState(webhookId);

    return { deleted: true, webhookId };
  }

  /**
   * Replay a specific delivery.
   *
   * Authorization (DEVELOPER or ADMIN role) is enforced in the controller.
   * The caller must also own the webhook org.
   */
  async replayDelivery(
    organizationId: string,
    deliveryId: string,
    replayedById: string,
  ) {
    // Verify the delivery belongs to one of this org's webhooks.
    const delivery = await this.prisma.webhookDelivery.findUnique({
      where: { id: deliveryId },
      include: {
        webhook: { select: { organizationId: true } },
      },
    });

    if (!delivery) {
      throw new NotFoundException("Delivery not found");
    }

    if (delivery.webhook.organizationId !== organizationId) {
      throw new ForbiddenException("Delivery does not belong to this organisation");
    }

    // Persist audit record before dispatching.
    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: replayedById,
        action: "webhook.delivery.replayed",
        resourceType: "webhookDelivery",
        resourceId: deliveryId,
        metadata: {
          webhookId: delivery.webhookId,
          eventType: delivery.eventType,
          eventId: delivery.eventId,
          originalAttempt: delivery.attempt,
        },
      },
    });

    const newDeliveryId = await this.deliveryService.replay(deliveryId, replayedById);

    return {
      replayDeliveryId: newDeliveryId,
      originalDeliveryId: deliveryId,
      eventId: delivery.eventId,
      eventType: delivery.eventType,
      replayedBy: replayedById,
      replayedAt: new Date().toISOString(),
    };
  }

  /**
   * Send a synthetic, signed `webhook.test` event to an endpoint and return
   * redacted delivery diagnostics.
   *
   * Role authorization (DEVELOPER or ADMIN) is enforced in the controller; this
   * asserts the endpoint belongs to the caller's organisation and is active,
   * the same preconditions a replay has. Nothing is persisted: see
   * `WebhookDeliveryService.sendTestDelivery`.
   */
  async sendTestDelivery(organizationId: string, webhookId: string) {
    const webhook = await this.prisma.webhook.findUnique({
      where: { id: webhookId },
      select: {
        id: true,
        organizationId: true,
        url: true,
        secretEncrypted: true,
        status: true,
      },
    });

    this.assertOwnership(webhook, organizationId, webhookId);

    if (webhook!.status !== ResourceStatus.ACTIVE) {
      throw new BadRequestException(
        "Cannot send a test delivery to a disabled webhook endpoint",
      );
    }

    return this.deliveryService.sendTestDelivery(webhook!);
  }

  /**
   * List delivery records for a webhook endpoint.
   * Response body and sensitive headers are never stored in delivery rows,
   * so this is safe to return directly.
   */
  async listDeliveries(organizationId: string, webhookId: string) {
    await this.assertOwnedWebhook(organizationId, webhookId);

    return this.prisma.webhookDelivery.findMany({
      where: { webhookId },
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true,
        eventType: true,
        eventId: true,
        schemaVersion: true,
        attempt: true,
        status: true,
        statusCode: true,
        // responseBody stored truncated — safe to return
        responseBody: true,
        durationMs: true,
        failureReason: true,
        replayOf: true,
        replayedBy: true,
        deliveredAt: true,
        nextRetryAt: true,
        deadLetteredAt: true,
        deadLetterReason: true,
        redrivenAt: true,
        createdAt: true,
      },
    });
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private async assertOwnedWebhook(organizationId: string, webhookId: string) {
    const webhook = await this.prisma.webhook.findUnique({
      where: { id: webhookId },
      select: { id: true, organizationId: true, status: true, revision: true },
    });
    this.assertOwnership(webhook, organizationId, webhookId);
    return webhook!;
  }

  private assertOwnership(
    webhook: { organizationId: string } | null,
    organizationId: string,
    webhookId: string,
  ): void {
    if (!webhook) {
      throw new NotFoundException(`Webhook ${webhookId} not found`);
    }
    if (webhook.organizationId !== organizationId) {
      throw new ForbiddenException("Webhook does not belong to this organisation");
    }
  }

  /** Expose decrypt for testing secret rotation. */
  revealSecret(secretEncrypted: string): string {
    return this.paymentEncryptionKeyring.decrypt(secretEncrypted);
  }
}
