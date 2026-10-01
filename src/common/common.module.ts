import { Module, Global } from "@nestjs/common";
import { IdempotencyService } from "./services/idempotency.service";
import { IdempotentInterceptor } from "./interceptors/idempotent.interceptor";

/**
 * Global common module providing shared services and interceptors.
 */
@Global()
@Module({
  providers: [IdempotencyService, IdempotentInterceptor],
  exports: [IdempotencyService, IdempotentInterceptor],
})
export class CommonModule {}
