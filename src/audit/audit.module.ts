import { Module } from "@nestjs/common";
import { AuditAdminController } from "./audit-admin.controller";
import { AuditAdminService } from "./audit-admin.service";
import { AuditVerificationService } from "./audit-verification.service";
import { VerificationEventService } from "./verification-event.service";

@Module({
  controllers: [AuditAdminController],
  providers: [
    VerificationEventService,
    AuditAdminService,
    AuditVerificationService,
  ],
  exports: [VerificationEventService, AuditVerificationService],
})
export class AuditModule {}
