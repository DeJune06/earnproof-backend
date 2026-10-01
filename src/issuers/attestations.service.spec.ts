import { ForbiddenException, NotFoundException } from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { AttestationsService } from "./attestations.service";

const NOW = new Date("2026-09-24T12:00:00.000Z");

const config = { get: jest.fn((_key: string, def: number) => def) };

function serviceWith(row: object | null) {
  const prisma = {
    attestation: { findUnique: jest.fn().mockResolvedValue(row) },
  };
  return {
    prisma,
    service: new AttestationsService(prisma as never, config as never),
  };
}

describe("AttestationsService", () => {
  it("computes ACTIVE for a live attestation", async () => {
    const { service } = serviceWith({
      status: ResourceStatus.ACTIVE,
      expiresAt: new Date(NOW.getTime() + 3_600_000),
      revokedAt: null,
    });
    await expect(service.getEffectiveStatus("a", NOW)).resolves.toBe("ACTIVE");
  });

  it("computes EXPIRED from live fields even before the reconciler runs", async () => {
    const { service } = serviceWith({
      status: ResourceStatus.ACTIVE, // stored status still ACTIVE
      expiresAt: new Date(NOW.getTime() - 3_600_000),
      revokedAt: null,
    });
    await expect(service.getEffectiveStatus("a", NOW)).resolves.toBe("EXPIRED");
  });

  it("throws NotFound for an unknown attestation", async () => {
    const { service } = serviceWith(null);
    await expect(service.getEffectiveStatus("missing", NOW)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it("refuses issuance for an expired attestation", async () => {
    const { service } = serviceWith({
      status: ResourceStatus.ACTIVE,
      expiresAt: new Date(NOW.getTime() - 3_600_000),
      revokedAt: null,
    });
    await expect(service.canAuthorizeIssuance("a", NOW)).resolves.toBe(false);
    await expect(
      service.assertCanAuthorizeIssuance("a", NOW),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("permits issuance for an active attestation", async () => {
    const { service } = serviceWith({
      status: ResourceStatus.ACTIVE,
      expiresAt: new Date(NOW.getTime() + 3_600_000),
      revokedAt: null,
    });
    await expect(service.canAuthorizeIssuance("a", NOW)).resolves.toBe(true);
    await expect(
      service.assertCanAuthorizeIssuance("a", NOW),
    ).resolves.toBeUndefined();
  });

  it("treats an unknown attestation as unable to authorize issuance", async () => {
    const { service } = serviceWith(null);
    await expect(service.canAuthorizeIssuance("missing", NOW)).resolves.toBe(
      false,
    );
  });
});
