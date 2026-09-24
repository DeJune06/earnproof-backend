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
import { AuthenticatedUser } from "../auth/auth.types";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { AuthGuard } from "../common/guards/auth.guard";
import { ProofAnchoringStatusResponseDto } from "./dto/anchoring-intent-status.dto";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";
import { CreatePaymentReceiptProofDto } from "./dto/create-payment-receipt-proof.dto";
import { CreateRecurringIncomeProofDto } from "./dto/create-recurring-income-proof.dto";
import { ListProofsDto } from "./dto/list-proofs.dto";
import { ProofCreatedDto } from "./dto/proof-created.dto";
import {
  ProofDetailResponseDto,
  ProofListResponseDto,
} from "./dto/proof-history-response.dto";
import { RetryAnchoringResponseDto } from "./dto/retry-anchoring-response.dto";
import { RevokeProofDto } from "./dto/revoke-proof.dto";
import { RevokeProofResponseDto } from "./dto/revoke-proof-response.dto";
import { VerifyProofResponseDto } from "./dto/verify-proof-response.dto";
import { VerificationStatsDto } from "./dto/verification-stats.dto";
import { ProofsService } from "./proofs.service";

@ApiTags("proofs")
@Controller("proofs")
export class ProofsController {
  constructor(private readonly proofsService: ProofsService) {}

  @ApiBearerAuth()
  @ApiOperation({
    summary: "List the authenticated user's proofs",
    description:
      "Returns cursor-paginated proof summaries. The response separates local lifecycle status, credential validity, expiration, and contract anchoring state without exposing protected payment data.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Proof history page.",
    type: ProofListResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: "The cursor or issued-at date range is invalid.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Get()
  listProofs(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListProofsDto,
  ) {
    return this.proofsService.listProofs(user.id, query);
  }

  @ApiBearerAuth()
  @ApiOperation({
    summary: "Get an owned proof",
    description:
      "Returns proof details for the owner or an administrator. Unknown and non-owned proof IDs produce the same not-found response.",
  })
  @ApiParam({ name: "id", description: "Proof ID (uuid)." })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Proof details.",
    type: ProofDetailResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Proof not found or not accessible to this user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Get(":id")
  getProofDetail(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.proofsService.getProofDetail(user, id);
  }

  @ApiOperation({
    summary: "Create a selectively disclosed payment-receipt proof",
    description:
      "Issues a receipt credential for one eligible payment owned by the authenticated user. Sender and exact amount are hidden unless independently opted in.",
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Payment-receipt proof created.",
    type: ProofCreatedDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Payment does not exist or belongs to another user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description:
      "Payment is excluded, ineligible, or request validation failed.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Post("payment-receipt")
  createPaymentReceiptProof(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreatePaymentReceiptProofDto,
  ) {
    return this.proofsService.createPaymentReceiptProof(user, body);
  }

  @ApiOperation({
    summary: "Create a minimum-income proof",
    description:
      "Generates a privacy-preserving credential asserting that the authenticated wallet " +
      "received at least `thresholdAmount` of a given asset during the specified period. " +
      "The exact income and individual transactions are never disclosed; only the boolean " +
      "outcome (threshold met) is embedded in the credential.",
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.CREATED,
    description:
      "Proof created. Returns the signed credential and an optional anchoring result.",
    type: ProofCreatedDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Request body failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description:
      "Business rule violation — e.g. period range invalid, payments ineligible, " +
      "asset mismatch, or threshold not met.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  // Proof creation is expensive (Stellar reads, contract anchoring) — the
  // "strict" tier, not "default". SkipThrottle excludes the OTHER named
  // throttlers so this route is judged against exactly one budget, not all
  // three simultaneously (see rate-limit.module.ts's doc comment).
  @SkipThrottle({ default: true, verification: true })
  @Throttle({ strict: {} })
  @Post("minimum-income")
  createMinimumIncomeProof(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateMinimumIncomeProofDto,
  ) {
    return this.proofsService.createMinimumIncomeProof(user, body);
  }

  @ApiOperation({
    summary: "Create a recurring-income proof",
    description:
      "Issues a privacy-preserving credential when every requested cadence interval contains at least one eligible income payment in the selected asset.",
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Recurring-income proof created.",
    type: ProofCreatedDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description:
      "The cadence is unsatisfied or a selected payment violates the ownership, classification, eligibility, asset, or period rules.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Post("recurring-income")
  createRecurringIncomeProof(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateRecurringIncomeProofDto,
  ) {
    return this.proofsService.createRecurringIncomeProof(user, body);
  }

  @ApiOperation({
    summary: "Revoke a proof",
    description:
      "Marks the proof as REVOKED and records the revoking actor, reason, and revocation timestamp. " +
      "If the proof was anchored on-chain, a revocation transaction is also submitted. " +
      "The owner of the proof or an administrator may revoke it. Idempotent: revoking an " +
      "already-revoked proof returns its original revocation metadata unchanged.",
  })
  @ApiBearerAuth()
  @ApiParam({
    name: "id",
    description: "Proof ID (uuid).",
    example: "018e1234-abcd-7000-8000-abcdef012345",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Proof revoked.",
    type: RevokeProofResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Proof not found.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: "Proof does not belong to the authenticated user and they are not an administrator.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Patch(":id/revoke")
  revokeProof(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
    @Body() body?: RevokeProofDto,
  ) {
    return this.proofsService.revokeProof(user, id, body);
  }

  @ApiOperation({
    summary: "Get a proof's anchoring status",
    description:
      "Returns the current on-chain anchoring intent(s) for a proof (at most one REGISTER " +
      "and one REVOKE). This is a live status snapshot, not a per-attempt history: the " +
      "schema keeps one row per operation, overwritten on each attempt. Any failure detail " +
      "returned is already redacted. Available to the proof's owner or an administrator.",
  })
  @ApiBearerAuth()
  @ApiParam({
    name: "id",
    description: "Proof ID (uuid).",
    example: "018e1234-abcd-7000-8000-abcdef012345",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Anchoring status for the proof.",
    type: ProofAnchoringStatusResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Proof not found, or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Get(":id/anchoring")
  getProofAnchoringStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.proofsService.getProofAnchoringStatus(user, id);
  }

  @ApiOperation({
    summary: "Retry a permanently-failed anchoring intent",
    description:
      "Requeues a FAILED, permanently-errored anchoring intent for the worker to retry on " +
      "its next poll cycle. Does not invoke the chain synchronously. Only a permanently-" +
      "failed intent is eligible; a PENDING intent is already scheduled to retry itself, and " +
      "a PROCESSING or CONFIRMED intent cannot be retried. Available to the proof's owner or " +
      "an administrator.",
  })
  @ApiBearerAuth()
  @ApiParam({
    name: "id",
    description: "Proof ID (uuid).",
    example: "018e1234-abcd-7000-8000-abcdef012345",
  })
  @ApiParam({
    name: "intentId",
    description: "Anchoring intent ID.",
    example: "clx1abc2def3ghi4",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "The intent was requeued.",
    type: RetryAnchoringResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description:
      "Proof not found, does not belong to the authenticated user, or the intent does not " +
      "belong to this proof.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "The intent is not eligible for retry (not permanently failed).",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Post(":id/anchoring/:intentId/retry")
  retryProofAnchoring(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
    @Param("intentId") intentId: string,
  ) {
    return this.proofsService.retryProofAnchoring(user, id, intentId);
  }

  @ApiOperation({
    summary: "Verify a proof (public)",
    description:
      "Public endpoint. Reconstructs the credential from the stored proof, recomputes the " +
      "HMAC commitment, and returns the verification result. No authentication required — " +
      "third parties such as issuers can call this endpoint directly.",
  })
  @ApiParam({
    name: "id",
    description: "Proof ID (uuid).",
    example: "018e1234-abcd-7000-8000-abcdef012345",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Verification result and the signed credential.",
    type: VerifyProofResponseDto,
  })
  @SkipThrottle({ default: true, strict: true })
  @Throttle({ verification: {} })
  @Get(":id/verify")
  verifyProof(@Param("id") id: string) {
    return this.proofsService.verifyProof(id);
  }

  @ApiBearerAuth()
  @ApiOperation({
    summary: "Get aggregate verification statistics for a proof",
    description:
      "Returns privacy-safe outcome counts. Only the proof owner may access these statistics; verifier identity is never returned.",
  })
  @ApiParam({ name: "id", description: "Proof ID (uuid)." })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Aggregate verification outcome counts.",
    type: VerificationStatsDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: "The proof belongs to another user.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "Proof not found.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Get(":id/verification-stats")
  getVerificationStats(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.proofsService.getVerificationStats(user.id, id);
  }
}
