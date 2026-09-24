import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { AnchoringOperation, AnchoringStatus } from "@prisma/client";

export class AnchoringIntentStatusDto {
  @ApiProperty({ example: "clx1abc2def3ghi4" })
  id!: string;

  @ApiProperty({ enum: AnchoringOperation, example: AnchoringOperation.REGISTER })
  operation!: AnchoringOperation;

  @ApiProperty({ enum: AnchoringStatus, example: AnchoringStatus.FAILED })
  status!: AnchoringStatus;

  @ApiProperty({
    description: "Number of delivery attempts made for this intent so far.",
    example: 3,
  })
  attemptCount!: number;

  @ApiPropertyOptional({ nullable: true, description: "ISO-8601 UTC timestamp of the last attempt." })
  lastAttemptAt!: string | null;

  @ApiPropertyOptional({
    nullable: true,
    description: "ISO-8601 UTC timestamp the worker will next retry at, for a PENDING intent.",
  })
  nextRetryAt!: string | null;

  @ApiPropertyOptional({
    nullable: true,
    description: "Redacted failure detail from the most recent attempt. Never a raw error.",
  })
  lastErrorSafe!: string | null;

  @ApiProperty({
    description:
      "True once the worker has stopped retrying automatically (a permanent error or the attempt cap was reached). Only these intents are eligible for a manual retry.",
    example: true,
  })
  permanentError!: boolean;

  @ApiPropertyOptional({ nullable: true, description: "On-chain transaction hash once confirmed." })
  transactionHash!: string | null;
}

export class ProofAnchoringStatusResponseDto {
  @ApiProperty({ example: "clx1abc2def3ghi4" })
  proofId!: string;

  @ApiProperty({
    type: () => [AnchoringIntentStatusDto],
    description:
      "One entry per anchoring operation attempted for this proof (at most REGISTER and REVOKE).",
  })
  intents!: AnchoringIntentStatusDto[];
}
