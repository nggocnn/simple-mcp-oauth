/**
 * The MCP server factory and the tools it exposes.
 *
 * Two tools are registered:
 * - `whoami`   — echoes the caller's verified identity.
 * - `api_call` — calls the downstream API on the user's behalf, gated on a role.
 *
 * The authenticated user is not passed as a tool argument; it is carried in an
 * {@link AsyncLocalStorage} store that the auth middleware (see `server.ts`)
 * populates for the duration of each request. `currentUser.getStore()` returns
 * it inside a tool, or `undefined`/`null` if a tool is somehow reached without
 * an authenticated user.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { config } from "./config.js";
import { type AuthenticatedUser } from "./auth/providers.js";
import { resolveDownstreamCredential } from "./auth/downstream.js";

/**
 * Per-request authenticated user, propagated through the async call stack — the
 * TypeScript analogue of Python's ContextVar. Set via `currentUser.run(...)` in
 * the auth middleware; read with `getStore()` inside tools.
 */
export const currentUser = new AsyncLocalStorage<AuthenticatedUser | null>();

// Realm role required to use the downstream-calling tool. In the demo, alice
// has it and bob does not — demonstrating per-user authorization at the tool
// level (a valid token is necessary but not sufficient).
const REQUIRED_DOWNSTREAM_ROLE = "downstream-reader";

/** Wrap a string as an MCP text tool result. */
function text(value: string) {
  return { content: [{ type: "text" as const, text: value }] };
}

/**
 * Create a fresh `McpServer` with both tools registered.
 *
 * A new instance is built per request because the HTTP transport runs in
 * stateless mode (see `server.ts`), so there is no long-lived server to reuse.
 */
export function createMcpServer(): McpServer {
  const mcp = new McpServer({
    name: config.serverName,
    version: "0.0.1",
  });

  // whoami — return the caller's identity as JSON.
  mcp.registerTool(
    "whoami",
    { description: "whoami" },
    async () => {
      const user = currentUser.getStore();

      if (!user) {
        return text(JSON.stringify({ error: "No authenticated user." }));
      }

      return text(
        JSON.stringify({
          subject: user.subject,
          email: user.email,
          issuer: user.issuer,
          roles: user.roles,
        }),
      );
    },
  );

  // api_call — call the downstream search API as the user, after a role check.
  mcp.registerTool(
    "api_call",
    { inputSchema: { query: z.string() } },
    async ({ query }) => {
      const user = currentUser.getStore();

      if (!user) {
        return text("Forbidden: no authenticated user.");
      }

      // Tool-level authorization gate.
      if (!user.roles.includes(REQUIRED_DOWNSTREAM_ROLE)) {
        return text(
          `Forbidden: ${user.email || user.subject} lacks the required '${REQUIRED_DOWNSTREAM_ROLE}' role.`,
        );
      }

      const url = `${config.downstreamBaseUrl}/api/search?q=${encodeURIComponent(query)}`;

      try {
        // Exchange the user's token for a downstream-audience token, then call.
        const cred = await resolveDownstreamCredential(user);
        const resp = await fetch(url, {
          headers: { Authorization: cred.authorizationHeader },
          signal: AbortSignal.timeout(config.requestTimeoutMs),
        });
        const body = await resp.text();

        // Report URL, acting identity, and downstream status/body so the whole
        // flow is observable from the tool result.
        return text(
          `Called ${url}\nacting as: ${cred.actingAs}\nstatus: ${resp.status}\nbody: ${body}`,
        );
      } catch (e) {
        return text(`Downstream call failed: ${(e as Error).message}`);
      }
    },
  );

  return mcp;
}
