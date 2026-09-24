/**
 * Request resource limits, in one place.
 *
 * Domain validation runs late: by the time a DTO is checked, the body has been
 * read off the socket, parsed into objects, and walked by class-transformer. A
 * request that is *validly shaped* but enormous — ten thousand payment ids, a
 * megabyte of metadata, an array nested five hundred deep — costs memory, CPU
 * and database work before a single domain rule has an opinion about it.
 *
 * These limits are the earlier boundary. They are collected here rather than
 * spread across `main.ts` and a dozen DTOs so that the answer to "what is the
 * largest request this service accepts?" is one file, and so the tests in
 * `test/security/` can assert against the same numbers the application uses.
 *
 * Every value is a deliberate trade, and the reasoning is recorded next to it:
 * a limit whose justification is lost gets raised the first time it is
 * inconvenient.
 */

/** Bytes in a kilobyte, for readability below. */
const KB = 1024;

/**
 * Global JSON body limit.
 *
 * 64 KB is roughly forty times the largest legitimate request this API has
 * (a proof creation carrying a few dozen payment ids), and small enough that a
 * thousand concurrent oversized requests cannot exhaust a small container's
 * memory. Enforced by the body parser, so an oversized body is refused while it
 * is still bytes on a socket — never parsed, never logged, never validated.
 */
export const GLOBAL_BODY_LIMIT_BYTES = 64 * KB;

/**
 * Route-specific overrides, matched by path prefix, longest prefix first.
 *
 * Only two exist, and both tighten rather than loosen:
 *
 * - Authentication is unauthenticated and therefore the cheapest place to
 *   attack. A challenge or verification carries an address, an id and a
 *   signature: 8 KB is generous by two orders of magnitude.
 * - Credential verification is the one endpoint that legitimately takes a
 *   document. Its DTO caps the credential at 32 KB, so the transport limit sits
 *   just above that; a larger body cannot become a valid request and there is
 *   no reason to parse it.
 */
export const ROUTE_BODY_LIMITS: ReadonlyArray<{
  readonly prefix: string;
  readonly bytes: number;
}> = [
  { prefix: "/api/v1/auth", bytes: 8 * KB },
  { prefix: "/api/v1/credentials/verify", bytes: 40 * KB },
];

/** The body limit that applies to a path. */
export function bodyLimitForPath(path: string): number {
  const match = [...ROUTE_BODY_LIMITS]
    .sort((a, b) => b.prefix.length - a.prefix.length)
    .find((route) => path.startsWith(route.prefix));

  return match?.bytes ?? GLOBAL_BODY_LIMIT_BYTES;
}

/**
 * Structural limits applied to every parsed body.
 *
 * The byte limit alone does not bound the work a body creates. 64 KB of
 * `[[[[[...` is sixteen thousand levels deep and will overflow the stack in any
 * recursive walk — class-transformer's included — before validation reports
 * anything. 64 KB of `[1,1,1,...]` is twenty thousand array elements, each of
 * which class-validator will visit.
 *
 * These are checked immediately after parsing and before validation, in one
 * iterative pass with no recursion, so the check itself cannot be the thing
 * that overflows.
 */
export const PAYLOAD_SHAPE_LIMITS = {
  /**
   * Maximum nesting depth.
   *
   * The deepest legitimate request body in this API is a credential envelope at
   * five levels; twelve leaves room for growth and still stops a stack attack
   * three orders of magnitude short.
   */
  maxDepth: 12,

  /**
   * Maximum items in any single array.
   *
   * Above the largest domain limit (500 payment ids on a proof) so that a
   * request refused here is refused for being abusive, not for being large; a
   * request that exceeds a domain limit gets the domain's own, more useful,
   * validation error.
   */
  maxArrayItems: 1_000,

  /**
   * Maximum length of any single string.
   *
   * The longest legitimate string is a webhook URL at 2 KB. 8 KB catches the
   * "one enormous field" shape without arguing with any real request.
   */
  maxStringLength: 8 * KB,

  /**
   * Maximum total nodes (objects, arrays, and values) in one body.
   *
   * Bounds the cost of validation itself, which is proportional to node count
   * rather than to bytes. Also bounds the shape check, which stops at this
   * many nodes rather than walking a hostile body to the end.
   */
  maxNodes: 20_000,
} as const;

/**
 * Field limits used by DTOs.
 *
 * Named for what they bound rather than for their value, so a DTO reads as a
 * statement about the domain and the number stays in one place.
 */
export const FIELD_LIMITS = {
  /** A cuid is 25 characters; 64 leaves room without accepting a document. */
  id: 64,
  /** Stellar asset codes are at most 12 characters. */
  assetCode: 12,
  /**
   * A decimal amount as a string.
   *
   * Stellar amounts are at most 19 significant digits with 7 decimal places;
   * 32 characters accepts every representable value and refuses a megabyte of
   * digits before the regex has to scan it.
   */
  decimalAmount: 32,
  /** Stellar addresses are exactly 56 characters. */
  stellarAddress: 56,
  /** Human-facing names: keys, organisations, display names. */
  name: 120,
  /** A URL long enough for any real endpoint, short enough to log safely. */
  url: 2 * KB,
  /**
   * Payment ids per proof.
   *
   * A year of daily payments is 365, so 500 accepts every realistic proof while
   * bounding the `IN` list, the amount decryption, and the credential this
   * produces. Without a cap, one request can ask the database to load an
   * unbounded number of rows.
   */
  paymentIdsPerProof: 500,
  /** Free-form metadata objects, by serialised size and nesting depth. */
  metadataBytes: 8 * KB,
  metadataDepth: 5,
  /**
   * A private, free-form revocation reason.
   *
   * Long enough for an operator note, short enough that it cannot be used to
   * smuggle an unbounded document into an audit-log row.
   */
  revocationReason: 500,
} as const;
