/**
 * OAuth Protected Resource Metadata (RFC 9728).
 *
 * Computes the two paths the metadata document is served at and builds the
 * document itself. Clients fetch this to discover which authorization servers
 * issue tokens for this resource; the 401 challenge points here.
 */

import { config } from "../config.js";

// The resource's path component (e.g. "/mcp"), used to build the canonical,
// resource-suffixed metadata path that clients derive from the resource id.
const RESOURCE_PATH = new URL(config.resource).pathname.replace(/\/$/, "");

/** Bare well-known metadata path. */
export const METADATA_PATH = "/.well-known/oauth-protected-resource";
/**
 * Metadata path that includes the resource's path component. Equal to
 * {@link METADATA_PATH} when the resource has no path; served additionally
 * otherwise.
 */
export const CANONICAL_METADATA_PATH = `${METADATA_PATH}${RESOURCE_PATH}`;

/** Build the Protected Resource Metadata document (RFC 9728). */
export function protectedResourceMetadata() {
  return {
    resource: config.resource,
    authorization_servers: config.issuers,
    bearer_methods_supported: ["header"],
    scopes_supported: config.supportedScopes,
    resource_documentation: `${config.publicUrl}/`,
  };
}
