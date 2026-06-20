/**
 * Express application: OAuth-protected MCP endpoint plus public metadata.
 *
 * Wiring overview:
 * - `GET /.well-known/oauth-protected-resource` (and the resource-suffixed
 *   canonical path) serve OAuth Protected Resource Metadata (RFC 9728) publicly.
 * - `GET /healthz` is an unauthenticated liveness probe.
 * - Everything under `/mcp` is guarded by {@link authMiddleware}, which enforces
 *   a valid, audience-bound, sufficiently-scoped bearer token before the MCP
 *   transport ever sees the request.
 *
 * Pass `--transport stdio` (or the `stdio` arg) to run a local, unauthenticated
 * stdio server instead — handy for development.
 */

import express, { type Request, type Response, type NextFunction } from "express";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { config } from "./config.js";
import { createMcpServer, currentUser } from "./tools.js";
import { verifyAccessToken, warmProviders, TokenError } from "./auth/providers.js";
import {
  METADATA_PATH,
  CANONICAL_METADATA_PATH,
  protectedResourceMetadata,
} from "./auth/metadata.js";

/**
 * Sanitize a string for safe inclusion in an HTTP header value.
 *
 * Token-derived text (e.g. a forged `iss`) ends up in the `WWW-Authenticate`
 * header, so drop anything outside printable ASCII — neutralizing CR/LF header
 * injection — and downgrade double quotes to single quotes so the header's
 * quoted strings can't be broken out of. Capped at 200 chars.
 */
function headerSafe(value: string): string {
  const cleaned = Array.from(value)
    .map((c) => (c >= " " && c <= "~" ? c : " "))
    .join("")
    .replace(/"/g, "'");

  return cleaned.slice(0, 200);
}

/** Send a 401 with a `WWW-Authenticate` header pointing at the metadata URL. */
function challenge(res: Response, error: string, description: string): void {
  const safe = headerSafe(description);
  const metadataUrl = `${config.publicUrl}${CANONICAL_METADATA_PATH}`;

  res
    .status(401)
    .set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${metadataUrl}", error="${headerSafe(error)}", error_description="${safe}"`,
    )
    .json({ error, error_description: safe });
}

/**
 * Enforce OAuth on `/mcp`: require a Bearer token, verify it, check the required
 * scopes, then bind the user into {@link currentUser} for the request before
 * handing off to the MCP handler. Any failure short-circuits with a 401.
 */
async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return challenge(res, "invalid_token", "Missing Bearer token");
  }

  const token = authHeader.slice("Bearer ".length).trim();

  let user;
  try {
    user = await verifyAccessToken(token);
  } catch (e) {
    // Expected validation failures become 401s; anything else is a real bug.
    if (e instanceof TokenError) {
      return challenge(res, "invalid_token", e.message);
    }
    throw e;
  }

  // Scope gate: the token must carry at least one required scope.
  const required = new Set(config.requiredScopes);
  if (required.size > 0 && !user.scopes.some((s) => required.has(s))) {
    return challenge(
      res,
      "insufficient_scope",
      `Token is missing required scope(s): ${[...required].sort().join(", ")}`,
    );
  }

  // Run the rest of the request within the user's context so tools can read it.
  currentUser.run(user, () => next());
}

/** Handle one MCP request with a fresh, stateless server + transport. */
async function handleMcp(req: Request, res: Response): Promise<void> {
  // Stateless transport: a new server + transport per request (no session id).
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  // Tear both down once the response is finished to avoid leaks.
  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
}

/** Assemble the Express app: metadata + health routes, MCP behind auth. */
function buildApp() {
  const app = express();
  app.use(express.json());

  const metadataHandler = (_req: Request, res: Response) =>
    res.json(protectedResourceMetadata());

  app.get(METADATA_PATH, metadataHandler);
  // Only add the resource-suffixed route when it differs from the bare path.
  if (CANONICAL_METADATA_PATH !== METADATA_PATH) {
    app.get(CANONICAL_METADATA_PATH, metadataHandler);
  }

  app.get("/healthz", (_req: Request, res: Response) => res.json({ ok: true }));

  app.use("/mcp", authMiddleware, (req: Request, res: Response) => {
    void handleMcp(req, res);
  });

  return app;
}

/** Run an unauthenticated MCP server over stdio (local development). */
async function runStdio(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/** Entry point: choose transport, warm provider caches, then serve. */
async function main(): Promise<void> {
  if (process.argv.includes("stdio") || process.argv.includes("--transport")) {
    await runStdio();
    return;
  }

  await warmProviders();

  const app = buildApp();
  app.listen(config.port, "0.0.0.0", () => {
    console.error(
      `${config.serverName} listening on :${config.port} ` +
        `(mcp endpoint: ${config.publicUrl}/mcp)`,
    );
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
