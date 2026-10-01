/**
 * Collects PAYMENT_ENCRYPTION_KEY_V0, _V1, ... into an indexed object
 * (`{ 0: "...", 1: "..." }`) for the payment-encryption keyring service.
 * Loads until the first gap, same convention as VERIFICATION_HASH_SALT_V*.
 */
function loadPaymentEncryptionKeyVersions(): Record<number, string> {
  const versions: Record<number, string> = {};
  for (let i = 0; i < 100; i++) {
    const value = process.env[`PAYMENT_ENCRYPTION_KEY_V${i}`];
    if (value) {
      versions[i] = value;
    } else {
      break;
    }
  }
  return versions;
}

/**
 * Collects CREDENTIAL_SIGNING_SECRET_V0, _V1, ... into an indexed object,
 * same loading convention as the payment-encryption keyring above.
 */
function loadCredentialSigningKeyVersions(): Record<number, string> {
  const versions: Record<number, string> = {};
  for (let i = 0; i < 100; i++) {
    const value = process.env[`CREDENTIAL_SIGNING_SECRET_V${i}`];
    if (value) {
      versions[i] = value;
    } else {
      break;
    }
  }
  return versions;
}

/**
 * Collects CREDENTIAL_SIGNING_SECRET_V0_VERIFY_UNTIL, _V1_VERIFY_UNTIL, ...
 * An operator sets this ISO-8601 timestamp on a key when demoting it from
 * active to verify-only, marking the end of its overlap window. A version
 * with no VERIFY_UNTIL set never expires on its own — an operator retires it
 * by removing its secret entirely, same as the payment-encryption keyring.
 */
function loadCredentialSigningKeyVerifyUntil(): Record<number, string> {
  const deadlines: Record<number, string> = {};
  for (let i = 0; i < 100; i++) {
    const value = process.env[`CREDENTIAL_SIGNING_SECRET_V${i}_VERIFY_UNTIL`];
    if (value) {
      deadlines[i] = value;
    }
  }
  return deadlines;
}

export const configuration = () => ({
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: Number(process.env.PORT ?? 4000),
  databaseUrl: process.env.DATABASE_URL,
  redisUrl: process.env.REDIS_URL,
  appUrl: process.env.APP_URL ?? "http://localhost:3000",
  apiUrl: process.env.API_URL ?? "http://localhost:4000",
  stellar: {
    network: process.env.STELLAR_NETWORK ?? "testnet",
    horizonUrl:
      process.env.STELLAR_HORIZON_URL ?? "https://horizon-testnet.stellar.org",
    networkPassphrase:
      process.env.STELLAR_NETWORK_PASSPHRASE ??
      "Test SDF Network ; September 2015",
    finality: {
      // How far behind the last verified checkpoint a ledger divergence can
      // reach. Payments in this window are held and re-verified; anything
      // older is treated as final. 17,280 ledgers is roughly one day at ~5s.
      historyLedgers: Number(
        process.env.STELLAR_FINALITY_HISTORY_LEDGERS ?? 17_280,
      ),
      // Pages one reconciliation read may walk. A window deeper than this
      // stays held and is resumed on the next sync rather than read unbounded.
      reconciliationMaxPages: Number(
        process.env.STELLAR_FINALITY_RECONCILIATION_MAX_PAGES ?? 10,
    // Per-network circuit breaker around Horizon transport calls. Defaults are
    // conservative: five consecutive transient failures open the circuit for
    // 30s, then a single probe must succeed twice to close it.
    circuitBreaker: {
      failureThreshold: Number(
        process.env.HORIZON_CIRCUIT_FAILURE_THRESHOLD ?? 5,
      ),
      openDurationMs: Number(
        process.env.HORIZON_CIRCUIT_OPEN_DURATION_MS ?? 30_000,
      ),
      halfOpenMaxProbes: Number(
        process.env.HORIZON_CIRCUIT_HALF_OPEN_MAX_PROBES ?? 1,
      ),
      successThreshold: Number(
        process.env.HORIZON_CIRCUIT_SUCCESS_THRESHOLD ?? 2,
      ),
    },
  },
  sessionSecret: process.env.SESSION_SECRET,
  credentialSigningSecret: process.env.CREDENTIAL_SIGNING_SECRET,
  credentialSigningKeyVersions: loadCredentialSigningKeyVersions(),
  credentialSigningKeyVersion: Number(
    process.env.CREDENTIAL_SIGNING_KEY_VERSION ?? 0,
  ),
  credentialSigningKeyVerifyUntil: loadCredentialSigningKeyVerifyUntil(),
  credentialSigningSecretPrevious: process.env.CREDENTIAL_SIGNING_SECRET_PREVIOUS,
  credentialSigningKeyId:
    process.env.CREDENTIAL_SIGNING_KEY_ID ?? "credential-key-0",
  credentialSigningPreviousKeyId: process.env.CREDENTIAL_SIGNING_PREVIOUS_KEY_ID,
  credentialSigningKeyOverlapDays: Number(
    process.env.CREDENTIAL_SIGNING_KEY_OVERLAP_DAYS ?? 30,
  ),
  paymentEncryptionKey: process.env.PAYMENT_ENCRYPTION_KEY,
  paymentEncryptionKeyVersions: loadPaymentEncryptionKeyVersions(),
  paymentEncryptionKeyVersion: Number(
    process.env.PAYMENT_ENCRYPTION_KEY_VERSION ?? 0,
  ),
  verificationEventRetentionDays: Number(
    process.env.VERIFICATION_EVENT_RETENTION_DAYS ?? 90,
  ),
  verificationHashSaltVersion: Number(
    process.env.VERIFICATION_HASH_SALT_VERSION ?? 0,
  ),
  auth: {
    challengeRetentionDays: Number(
      process.env.AUTH_CHALLENGE_RETENTION_DAYS ?? 7,
    ),
    auditRetentionDays: Number(process.env.AUTH_AUDIT_RETENTION_DAYS ?? 90),
    sessionCleanupCron: process.env.AUTH_SESSION_CLEANUP_CRON ?? "0 0 * * *",
    challengeCleanupCron: process.env.AUTH_CHALLENGE_CLEANUP_CRON ?? "0 2 * * *",
    auditCleanupCron: process.env.AUTH_AUDIT_CLEANUP_CRON ?? "0 3 * * *",
    rateLimits: {
      maxChallengeCreations: Number(
        process.env.AUTH_RATE_LIMIT_MAX_CHALLENGE_CREATIONS ?? 10,
      ),
      challengeCreationWindowMs: Number(
        process.env.AUTH_RATE_LIMIT_CHALLENGE_CREATION_WINDOW_MS ?? 900000, // 15 minutes
      ),
      maxVerifications: Number(
        process.env.AUTH_RATE_LIMIT_MAX_VERIFICATIONS ?? 5,
      ),
      verificationWindowMs: Number(
        process.env.AUTH_RATE_LIMIT_VERIFICATION_WINDOW_MS ?? 900000, // 15 minutes
      ),
    },
  },
  contractAnchoring: {
    enabled: process.env.CONTRACT_ANCHORING_ENABLED === "true",
    required: process.env.CONTRACT_ANCHORING_REQUIRED === "true",
    stellarCliPath: process.env.STELLAR_CLI_PATH ?? "stellar",
    source: process.env.STELLAR_CLI_SOURCE,
    proofRegistryContractId: process.env.PROOF_REGISTRY_CONTRACT_ID,
    issuerAddress: process.env.EARNPROOF_ISSUER_ADDRESS,
    schemaVersion: Number(process.env.EARNPROOF_SCHEMA_VERSION ?? 1),
    // Per-network, per-operation circuit breaker around contract invocation.
    // Slightly more tolerant than Horizon's: a contract call is heavier and its
    // transient failures noisier, so the circuit waits for more of them and
    // cools off longer before probing.
    circuitBreaker: {
      failureThreshold: Number(
        process.env.CONTRACT_CIRCUIT_FAILURE_THRESHOLD ?? 5,
      ),
      openDurationMs: Number(
        process.env.CONTRACT_CIRCUIT_OPEN_DURATION_MS ?? 60_000,
      ),
      halfOpenMaxProbes: Number(
        process.env.CONTRACT_CIRCUIT_HALF_OPEN_MAX_PROBES ?? 1,
      ),
      successThreshold: Number(
        process.env.CONTRACT_CIRCUIT_SUCCESS_THRESHOLD ?? 2,
      ),
    },
  },
  health: {
    // Probe timeout. Must stay below the orchestrator's own probe timeout, or a
    // slow dependency produces overlapping in-flight probes against a system
    // that is already struggling.
    probeTimeoutMs: Number(process.env.HEALTH_PROBE_TIMEOUT_MS ?? 2000),
    // How long a probe result is reused. Readiness is polled continuously by
    // every replica and load balancer, so without caching the probe load scales
    // with poll rate rather than with anything meaningful.
    cacheTtlMs: Number(process.env.HEALTH_CACHE_TTL_MS ?? 5000),
  },
  webhooks: {
    // Attempts per delivery chain before the terminal attempt is
    // dead-lettered. Automatic retries never exceed this.
    maxDeliveryAttempts: Number(process.env.WEBHOOK_MAX_DELIVERY_ATTEMPTS ?? 5),
    // Upper bound on one bounded-batch redrive request.
    maxRedriveBatchSize: Number(process.env.WEBHOOK_REDRIVE_MAX_BATCH ?? 25),
  },
  proofSharing: {
    // Longest lifetime a share token may be issued with. A token never
    // outlives the proof it shares either.
    maxTtlMinutes: Number(process.env.PROOF_SHARE_TOKEN_MAX_TTL_MINUTES ?? 10_080),
    defaultTtlMinutes: Number(
      process.env.PROOF_SHARE_TOKEN_DEFAULT_TTL_MINUTES ?? 1_440,
    ),
  },
  // Per-organization operational quotas. Every organization is held to these
  // limits independently; see docs/quotas.md.
  quotas: {
    maxActiveApiKeys: Number(process.env.QUOTA_MAX_ACTIVE_API_KEYS ?? 25),
    maxWebhooks: Number(process.env.QUOTA_MAX_WEBHOOKS ?? 10),
    proofRequestsPerDay: Number(process.env.QUOTA_PROOF_REQUESTS_PER_DAY ?? 1_000),
    syncsPerHour: Number(process.env.QUOTA_SYNCS_PER_HOUR ?? 12),
  },
  issuerRegistry: {
    enabled: process.env.ISSUER_REGISTRY_ENABLED === "true",
    stellarCliPath: process.env.STELLAR_CLI_PATH ?? "stellar",
    source: process.env.STELLAR_CLI_SOURCE,
    contractId: process.env.ISSUER_REGISTRY_CONTRACT_ID,
  },
  organizations: {
    export: {
      // AES-256 key (hex or base64) for encrypting export archives at rest.
      // Absent means the export worker stays idle rather than writing plaintext.
      encryptionKey: process.env.ORGANIZATION_EXPORT_ENCRYPTION_KEY,
      // Where encrypted archives are staged; defaults under the OS temp dir.
      tempDir: process.env.ORGANIZATION_EXPORT_TEMP_DIR,
      // How long a job (and its artifact) lives before the expiry sweep removes it.
      jobTtlHours: Number(process.env.ORGANIZATION_EXPORT_JOB_TTL_HOURS ?? 24),
      // How long a single-use download handoff token is valid.
      downloadTtlMinutes: Number(
        process.env.ORGANIZATION_EXPORT_DOWNLOAD_TTL_MINUTES ?? 10,
      ),
    },
  },
  retention: {
    walletChallengeDays: Number(
      process.env.RETENTION_WALLET_CHALLENGE_DAYS ?? 7,
    ),
    authSessionDays: Number(process.env.RETENTION_AUTH_SESSION_DAYS ?? 30),
    webhookDeliveryDays: Number(
      process.env.RETENTION_WEBHOOK_DELIVERY_DAYS ?? 30,
    ),
    auditLogDays: Number(process.env.RETENTION_AUDIT_LOG_DAYS ?? 365),
    failedAnchoringDays: Number(
      process.env.RETENTION_FAILED_ANCHORING_DAYS ?? 90,
    ),
    cleanupCron: process.env.RETENTION_CLEANUP_CRON ?? "0 3 * * *",
    dryRun: process.env.RETENTION_DRY_RUN === "true",
  },
  rateLimit: {
    // "default": the global ceiling applied to every route that does not opt
    // into a stricter named throttler below. Anonymous callers get this limit;
    // RoleAwareThrottlerGuard multiplies it for authenticated callers.
    defaultTtlMs: Number(process.env.RATE_LIMIT_DEFAULT_TTL_MS ?? 60_000),
    defaultLimit: Number(process.env.RATE_LIMIT_DEFAULT_LIMIT ?? 100),
    // "strict": expensive operations such as proof creation and payment sync.
    strictTtlMs: Number(process.env.RATE_LIMIT_STRICT_TTL_MS ?? 60_000),
    strictLimit: Number(process.env.RATE_LIMIT_STRICT_LIMIT ?? 10),
    // "verification": public proof-verification lookups.
    verificationTtlMs: Number(
      process.env.RATE_LIMIT_VERIFICATION_TTL_MS ?? 60_000,
    ),
    verificationLimit: Number(process.env.RATE_LIMIT_VERIFICATION_LIMIT ?? 30),
    authenticatedMultiplier: Number(
      process.env.RATE_LIMIT_AUTHENTICATED_MULTIPLIER ?? 3,
    ),
    proofVerificationWindowMs: Number(
      process.env.PROOF_VERIFICATION_ABUSE_WINDOW_MS ?? 900000,
    ),
    proofVerificationUnknownLimit: Number(
      process.env.PROOF_VERIFICATION_UNKNOWN_LIMIT ?? 10,
    ),
    proofVerificationRepeatedLimit: Number(
      process.env.PROOF_VERIFICATION_REPEATED_LIMIT ?? 60,
    ),
    proofVerificationDistinctClientLimit: Number(
      process.env.PROOF_VERIFICATION_DISTINCT_CLIENT_LIMIT ?? 100,
    ),
  },
  verificationMetadataBudgetPerProof: Number(
    process.env.VERIFICATION_METADATA_BUDGET_PER_PROOF ?? 100,
  ),
  verificationMetadataBudgetWindowMs: Number(
    process.env.VERIFICATION_METADATA_BUDGET_WINDOW_MS ?? 86400000,
  ),
});

//Configuration addition
apiDeprecation: {
  allowedDocumentationOrigins: (
    process.env.API_DEPRECATION_ALLOWED_DOCUMENTATION_ORIGINS ??
    ""
  )
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),

  routes: [],
},
