/**
 * Runtime configuration, read once from environment variables at import time.
 *
 * Every knob the server needs is collected into the exported `config` object so
 * the rest of the code never reaches into `process.env` directly. Defaults are
 * chosen for the bundled Keycloak demo (see `samples/keycloak`).
 */

/** Read an env var, falling back to `fallback`; throw if required and unset. */
function env(name: string, fallback?: string): string {
  const v = process.env[name];

  if (v === undefined || v === "") {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return v;
}

/** Split a scope-style string on whitespace or commas into a clean list. */
function splitList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Parse the trusted OIDC issuer list. Accepts `OIDC_ISSUERS` (comma-separated,
 * multi-issuer) or `OIDC_ISSUER` (single). Trailing slashes are stripped so
 * issuer comparisons elsewhere are exact string matches.
 *
 * At least one issuer is required: a resource server with no trusted issuer
 * could never accept a token, so we fail fast at startup (matching the Python
 * sample) rather than silently rejecting every request.
 */
function issuerList(): string[] {
  const raw = process.env.OIDC_ISSUERS || process.env.OIDC_ISSUER || "";

  const issuers = raw
    .split(",")
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);

  if (issuers.length === 0) {
    throw new Error(
      "Missing required environment variable: OIDC_ISSUER (or OIDC_ISSUERS)",
    );
  }

  return issuers;
}

// Read once: the default for SUPPORTED_SCOPES doubles as the default for
// REQUIRED_SCOPES below, so it's resolved here rather than inline twice.
const supportedScopesRaw = env("SUPPORTED_SCOPES", "openid profile email");

/**
 * Process-wide configuration singleton.
 *
 * All scalar reads go through {@link env}: with a fallback it behaves like
 * `process.env.X || fallback`; without one it throws, so required vars fail
 * fast at startup. (Direct `process.env` access lives only in `issuerList()`,
 * which needs two different variable names.)
 */
export const config = {
  /** Human-readable name advertised to MCP clients. */
  serverName: env("SERVER_NAME", "Simple MCP OAuth"),
  /** Externally reachable base URL; used to build absolute metadata URLs. */
  publicUrl: env("PUBLIC_URL").replace(/\/$/, ""),
  /** This server's resource id — the value tokens must carry in `aud` (RFC 8707). */
  resource: env("RESOURCE"),
  port: parseInt(env("PORT", "3000"), 10),

  /** Authorization servers trusted to mint access tokens. */
  issuers: issuerList(),

  /** Scopes advertised in Protected Resource Metadata (informational). */
  supportedScopes: splitList(supportedScopesRaw),
  /** Scopes a token must carry (any one) to reach `/mcp`; defaults to supported. */
  requiredScopes: splitList(env("REQUIRED_SCOPES", supportedScopesRaw)),

  /** Confidential client credentials used to perform token exchange. */
  clientId: env("CLIENT_ID", ""),
  clientSecret: env("CLIENT_SECRET", ""),

  /** Strategy for obtaining a downstream credential ("token-exchange"). */
  downstreamStrategy: env("DOWNSTREAM_STRATEGY", "token-exchange"),
  /** Audience requested for the exchanged downstream token. */
  downstreamAudience: env("DOWNSTREAM_AUDIENCE", "downstream-api"),
  /** Base URL of the downstream API the `api_call` tool talks to. */
  downstreamBaseUrl: env("DOWNSTREAM_BASE_URL", ""),

  /** Timeout for all outbound HTTP calls, in milliseconds (env is in seconds). */
  requestTimeoutMs: parseInt(env("REQUEST_TIMEOUT", "20"), 10) * 1000,

  /**
   * Return true if `aud` (string or array) contains our resource id.
   *
   * Tokens are accepted only when explicitly audience-bound to this server,
   * which stops a token minted for another resource in the same realm from
   * being replayed here (the "confused deputy" guard).
   */
  audienceMatches(aud: unknown): boolean {
    if (aud === null || aud === undefined) {
      return false;
    }

    const values = Array.isArray(aud) ? aud : [aud];

    return values.includes(this.resource);
  },
};
