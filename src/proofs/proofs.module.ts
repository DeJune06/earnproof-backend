import { QuotasModule } from "../quotas/quotas.module";
import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { AuthModule } from "../auth/auth.module";
import { AttestationsModule } from "../attestations/attestations.module";
import { WebhooksModule } from "../webhooks/webhooks.module";
import { CredentialVerificationKeyService } from "../common/crypto/credential-verification-key.service";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { ProofsController } from "./proofs.controller";
import { ProofsService } from "./proofs.service";
import { ProofSharingService } from "./proof-sharing.service";
import { ProofReconciliationService } from "./proof-reconciliation.service";
import { ProofVerificationAbuseService } from "../common/rate-limit/proof-verification-abuse.service";

@Module({
  imports: [AuthModule, AuditModule, AttestationsModule, WebhooksModule],
  controllers: [ProofsController],
  providers: [
    ContractAnchoringService,
    CredentialVerificationKeyService,
    ProofsService,
    ProofSharingService,
    ProofVerificationAbuseService,
  ],
  exports: [
    ContractAnchoringService, 
    CredentialVerificationKeyService,
    ProofSharingService,
  ],
    ProofReconciliationService,
  ],
  exports: [ContractAnchoringService, CredentialVerificationKeyService, ProofReconciliationService],
})
export class ProofsModule {}
