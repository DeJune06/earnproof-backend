import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { Clock, SystemClock } from "../common/time/clock";
import { DatabaseModule } from "../database/database.module";
import { IssuerAddressRotationController } from "./issuer-address-rotation.controller";
import { IssuerAddressRotationService } from "./issuer-address-rotation.service";
import { AttestationsService } from "./attestations.service";
import { IssuersService } from "./issuers.service";
import { IssuersController } from "./issuers.controller";
import { IssuerRegistryService } from "./issuer-registry.service";
import { IssuerReconciliationService } from "./issuer-reconciliation.service";

@Module({
  imports: [DatabaseModule, AuthModule],
  controllers: [IssuersController, IssuerAddressRotationController],
  providers: [
    IssuerRegistryService,
    IssuersService,
    IssuerAddressRotationService,
    { provide: Clock, useClass: SystemClock },
  ],
  exports: [IssuersService, IssuerAddressRotationService],
  controllers: [IssuersController],
  providers: [IssuerRegistryService, IssuersService, IssuerReconciliationService],
  exports: [IssuersService, IssuerReconciliationService],
})
export class IssuersModule {}
