/**
 * Obtaining a credential to call the downstream API as the current user.
 *
 * The MCP server is a confidential OAuth client. Rather than forwarding the
 * user's own token (which is audience-bound to *this* server), it performs an
 * RFC 8693 token exchange to get a fresh token whose audience is the downstream
 * API, while preserving the user's identity — keeping each token scoped to
 * exactly one audience.
 */

import { config } from "../config.js";
import { type AuthenticatedUser, tokenEndpoint } from "./providers.js";

/** A ready-to-use Authorization header plus who the call acts as. */
export interface DownstreamCredential {
  authorizationHeader: string;
  actingAs: string;
}

/**
 * Exchange the user's access token for a downstream-audience token (RFC 8693).
 *
 * Sends a token-exchange grant to the issuer's token endpoint using this
 * server's confidential client credentials, with the user's token as the
 * subject. The returned token is audience-bound to `downstreamAudience`.
 */
async function exchange(user: AuthenticatedUser): Promise<DownstreamCredential> {
  const endpoint = await tokenEndpoint(user.issuer);

  const data = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    subject_token: user.rawToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    audience: config.downstreamAudience,
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
  });

  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: data,
    signal: AbortSignal.timeout(config.requestTimeoutMs),
  });

  if (resp.status !== 200) {
    const text = await resp.text();
    throw new Error(`Token exchange failed (${resp.status}): ${text}`);
  }

  const json = (await resp.json()) as { access_token: string };

  return {
    authorizationHeader: `Bearer ${json.access_token}`,
    actingAs: user.email || user.subject,
  };
}

/**
 * Return a downstream credential for `user` per the configured strategy.
 *
 * Only `token-exchange` is implemented; the indirection leaves room for other
 * strategies (e.g. a static service token) without touching callers.
 */
export async function resolveDownstreamCredential(
  user: AuthenticatedUser,
): Promise<DownstreamCredential> {
  if (config.downstreamStrategy === "token-exchange") {
    return exchange(user);
  }

  throw new Error(`Unknown downstream strategy: ${config.downstreamStrategy}`);
}
