import { QuotasModule } from "../quotas/quotas.module";
import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { StellarModule } from "../stellar/stellar.module";
import { PaymentFinalityService } from "./payment-finality.service";
import { PaymentsController } from "./payments.controller";
import { PaymentsService } from "./payments.service";
import { PaymentClassificationHistoryService } from "./payment-classification-history.service";

@Module({
  imports: [AuthModule, StellarModule, QuotasModule],
  controllers: [PaymentsController],
  providers: [PaymentsService, PaymentFinalityService],
  providers: [PaymentsService, PaymentClassificationHistoryService],
  exports: [PaymentsService, PaymentClassificationHistoryService],
})
export class PaymentsModule {}
