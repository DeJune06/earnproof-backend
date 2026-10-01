import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { SkipThrottle, Throttle } from "@nestjs/throttler";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthenticatedRoute } from "../common/decorators/authorization-policy.decorator";
import { Idempotent } from "../common/decorators/idempotent.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedUser } from "../auth/auth.types";
import { EligibilityExplanationDto } from "./dto/eligibility-explanation.dto";
import { ListPaymentsDto } from "./dto/list-payments.dto";
import { PaymentResponseDto } from "./dto/payment-response.dto";
import { SyncResultDto } from "./dto/sync-result.dto";
import { UpdatePaymentClassificationDto } from "./dto/update-payment-classification.dto";
import { 
  PaymentClassificationHistoryDto,
  ListPaymentClassificationHistoryDto 
} from "./dto/payment-classification-history.dto";
import { PaymentsService } from "./payments.service";
import { PaymentClassificationHistoryService } from "./payment-classification-history.service";

@ApiBearerAuth()
@ApiTags("payments")
@UseGuards(AuthGuard)
@Controller("payments")
export class PaymentsController {
  constructor(
    private readonly paymentsService: PaymentsService,
    private readonly classificationHistoryService: PaymentClassificationHistoryService,
  ) {}

  @ApiOperation({
    summary: "Sync payments from Stellar Horizon",
    description:
      "Fetches all incoming payment operations for the authenticated wallet from Stellar Horizon " +
      "and upserts them into the local database. Returns a summary of what was created, updated, " +
      "and skipped. Operations whose asset is not on the supported-asset list are counted as " +
      "skipped and marked ineligible.",
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Sync completed. Returns operation counts.",
    type: SyncResultDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.SERVICE_UNAVAILABLE,
    description: "Stellar Horizon or the database is temporarily unreachable.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: "Idempotency key was used with a different request payload.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.REQUEST_TIMEOUT,
    description: "Previous idempotent request is still being processed.",
    type: ApiErrorDto,
  })
  @SkipThrottle({ default: true, verification: true })
  @Throttle({ strict: {} })
  @Idempotent({ headerName: "idempotency-key", required: true })
  @Post("sync")
  @AuthenticatedRoute({ ownership: "user" })
  syncPayments(@CurrentUser() user: AuthenticatedUser): Promise<SyncResultDto> {
    return this.paymentsService.syncPayments(user);
  }

  @ApiOperation({
    summary: "List payments for the authenticated user",
    description:
      "Returns up to 100 payments owned by the authenticated wallet, ordered by `occurredAt` " +
      "descending. Filter by `classification` and/or `assetCode` as needed.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Array of payment records. `amountEncrypted` is excluded from the response.",
    type: [PaymentResponseDto],
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Query parameters failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @Get()
  @AuthenticatedRoute({ ownership: "user" })
  listPayments(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListPaymentsDto,
  ) {
    return this.paymentsService.listPayments(user.id, query);
  }

  @ApiOperation({
    summary: "Get a single payment by ID",
    description:
      "Returns a single payment record that belongs to the authenticated user. " +
      "Returns 404 if the payment does not exist or belongs to another user.",
  })
  @ApiParam({ name: "id", description: "Payment ID (cuid).", example: "clx1abc2def3ghi4" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "The requested payment.",
    type: PaymentResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Payment not found or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @Get(":id")
  @AuthenticatedRoute({ ownership: "user" })
  getPayment(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
  ) {
    return this.paymentsService.getPayment(user.id, paymentId);
  }

  @ApiOperation({
    summary: "Explain a payment's eligibility",
    description:
      "Returns the active eligibility decision for one of the caller's payments: the policy " +
      "version that produced it, the evaluated factors, a reason code per factor, which proof " +
      "families it permits, and recent historical decisions. A payment without a decision under " +
      "the current policy is evaluated first. Contains no memo, amount, or counterparty address.",
  })
  @ApiParam({ name: "id", description: "Payment ID (cuid).", example: "clx1abc2def3ghi4" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "The eligibility explanation.",
    type: EligibilityExplanationDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Payment not found or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @Get(":id/eligibility")
  explainEligibility(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
  ): Promise<EligibilityExplanationDto> {
    return this.paymentsService.explainEligibility(user.id, paymentId) as Promise<EligibilityExplanationDto>;
  }

  @ApiOperation({
    summary: "Update the classification of a payment",
    description:
      "Sets a new user-assigned classification on the payment and writes an audit log entry. " +
      "Only the owner of the payment may update it.",
  })
  @ApiParam({ name: "id", description: "Payment ID (cuid).", example: "clx1abc2def3ghi4" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Updated payment record.",
    type: PaymentResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Request body failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Payment not found or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @Patch(":id/classification")
  @AuthenticatedRoute({ ownership: "user" })
  updateClassification(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
    @Body() body: UpdatePaymentClassificationDto,
  ) {
    return this.paymentsService.updateClassification(
      user,
      paymentId,
      body.classification,
      body.reasonCode,
    );
  }

  @ApiOperation({
    summary: "Get classification history for a payment",
    description:
      "Returns the immutable history of classification changes for a payment. " +
      "Only the owner of the payment may view its history.",
  })
  @ApiParam({ name: "id", description: "Payment ID (cuid).", example: "clx1abc2def3ghi4" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Classification change history.",
    type: [PaymentClassificationHistoryDto],
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Payment not found or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @Get(":id/classification-history")
  @AuthenticatedRoute({ ownership: "user" })
  getClassificationHistory(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
    @Query() query: ListPaymentClassificationHistoryDto,
  ) {
    return this.classificationHistoryService.getPaymentHistory(user, paymentId, query);
  }
}
