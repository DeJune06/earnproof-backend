import { QuotasModule } from "../quotas/quotas.module";
import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { WebhookDeadLetterService } from "./webhook-dead-letter.service";
import { WebhookDeliveryService } from "./webhook-delivery.service";
import { WebhookSigningService } from "./webhook-signing.service";
import { WebhookCircuitBreakerService } from "./webhook-circuit-breaker.service";
import { WebhooksController } from "./webhooks.controller";
import { WebhooksService } from "./webhooks.service";

@Module({
  imports: [AuthModule, QuotasModule],
  controllers: [WebhooksController],
  providers: [
    WebhooksService,
    WebhookDeliveryService,
    WebhookSigningService,
    WebhookCircuitBreakerService,
  ],
  exports: [WebhookDeliveryService, WebhookCircuitBreakerService],
})
export class WebhooksModule {}
