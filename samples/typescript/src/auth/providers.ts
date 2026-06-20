/**
 * OIDC provider discovery and access-token verification.
 *
 * This module is the trust boundary of the server: it turns an opaque bearer
 * string into a verified {@link AuthenticatedUser}, or throws {@link TokenError}.
 * Discovered providers (a JWKS key source + token endpoint) are cached per
 * issuer so the discovery document is fetched only once.
 */

import {
  createRemoteJWKSet,
  jwtVerify,
  decodeJwt,
  type JWTPayload,
} from "jose";

import { config } from "../config.js";

/** Thrown when a token is missing, malformed, untrusted, or fails validation. */
export class TokenError extends Error {}

/** The verified identity behind a request, derived from token claims. */
export interface AuthenticatedUser {
  subject: string;
  issuer: string;
  email?: string;
  scopes: string[];
  roles: string[];
  /** Original bearer string, kept so it can be the subject of a token exchange. */
  rawToken: string;
  claims: JWTPayload;
}

/** Cached per-issuer discovery result. */
interface Provider {
  issuer: string;
  /** Lazily fetches and caches the issuer's signing keys for verification. */
  jwksClient: ReturnType<typeof createRemoteJWKSet>;
  /** Token endpoint, used later for token exchange. */
  tokenEndpoint: string;
}

// issuer -> Provider. Populated lazily by discover() and reused thereafter.
const registry = new Map<string, Provider>();

/**
 * Fetch (and cache) the issuer's OIDC discovery document.
 *
 * Reads `/.well-known/openid-configuration` to learn the JWKS URI and token
 * endpoint. Subsequent calls for the same issuer return the cached provider.
 */
async function discover(issuer: string): Promise<Provider> {
  const existing = registry.get(issuer);
  if (existing) {
    return existing;
  }

  const resp = await fetch(`${issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(config.requestTimeoutMs),
  });

  if (!resp.ok) {
    throw new Error(`OIDC discovery failed for ${issuer}: ${resp.status}`);
  }

  const doc = (await resp.json()) as {
    jwks_uri: string;
    token_endpoint: string;
  };

  const provider: Provider = {
    issuer,
    jwksClient: createRemoteJWKSet(new URL(doc.jwks_uri)),
    tokenEndpoint: doc.token_endpoint,
  };

  registry.set(issuer, provider);

  return provider;
}

/**
 * Pre-discover all configured issuers at startup. Best-effort: failures (e.g. a
 * provider not being up yet) are ignored and retried on first use.
 */
export async function warmProviders(): Promise<void> {
  await Promise.allSettled(config.issuers.map((issuer) => discover(issuer)));
}

/** Return the OAuth token endpoint for `issuer` (used by token exchange). */
export async function tokenEndpoint(issuer: string): Promise<string> {
  const provider = await discover(issuer);
  return provider.tokenEndpoint;
}

/**
 * Validate a bearer token and return the {@link AuthenticatedUser}.
 *
 * The checks, in order:
 * 1. Decode (without verifying) to read the `iss` claim.
 * 2. Reject any issuer not in the trusted list.
 * 3. Verify signature, issuer, and expiry against the issuer's JWKS.
 * 4. Verify the audience explicitly contains our resource id.
 *
 * Any failure throws {@link TokenError}; the caller turns that into a 401.
 */
export async function verifyAccessToken(token: string): Promise<AuthenticatedUser> {
  // Step 1: peek at the unverified claims only to find the issuer. Nothing here
  // is trusted — it just tells us which provider to verify against.
  let unverified: JWTPayload;
  try {
    unverified = decodeJwt(token);
  } catch (e) {
    throw new TokenError("Malformed token");
  }

  // Step 2: the issuer must be one we explicitly trust.
  const issuer = String(unverified.iss ?? "").replace(/\/$/, "");
  if (!issuer || !config.issuers.includes(issuer)) {
    throw new TokenError(`Untrusted issuer: ${issuer || "<none>"}`);
  }

  // Step 3: cryptographically verify with the issuer's signing key. Audience is
  // checked manually below so we control the message and matching logic.
  const provider = await discover(issuer);

  let claims: JWTPayload;
  try {
    const result = await jwtVerify(token, provider.jwksClient, {
      issuer,
      algorithms: ["RS256", "ES256"],
    });
    claims = result.payload;
  } catch (e) {
    throw new TokenError(
      `Signature/issuer/expiry verification failed: ${(e as Error).message}`,
    );
  }

  // Step 4: the token must be audience-bound to this resource server.
  if (!config.audienceMatches(claims.aud)) {
    throw new TokenError(
      `Token audience ${JSON.stringify(claims.aud)} does not include ${config.resource}`,
    );
  }

  // Keycloak puts realm roles under realm_access.roles; scopes are a
  // space-delimited string in the standard "scope" claim.
  const realmAccess = (claims.realm_access as { roles?: string[] } | undefined) ?? {};
  const roles = realmAccess.roles ?? [];
  const scope = claims.scope;

  return {
    subject: String(claims.sub ?? ""),
    issuer,
    email: claims.email ? String(claims.email) : undefined,
    scopes: typeof scope === "string" ? scope.split(/\s+/).filter(Boolean) : [],
    roles,
    rawToken: token,
    claims,
  };
}
