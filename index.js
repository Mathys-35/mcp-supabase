const express = require("express");
const { randomUUID } = require("node:crypto");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const {
  SSEServerTransport,
} = require("@modelcontextprotocol/sdk/server/sse.js");
const {
  StreamableHTTPServerTransport,
} = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { z } = require("zod");

const crypto = require("node:crypto");

// --- Config ---
const PORT = process.env.PORT || 3100;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const BASE_URL = "https://mcp-supabase.sylion.fr";

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !MCP_AUTH_TOKEN) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_KEY, MCP_AUTH_TOKEN"
  );
  process.exit(1);
}

// --- Table allowlist (defense-in-depth: blocks access to system tables) ---
const DEFAULT_TABLES = [
  "prospection_immobilier",
  "prospection_recrutement",
  "config",
];

const ALLOWED_TABLES = new Set(
  process.env.ALLOWED_TABLES
    ? process.env.ALLOWED_TABLES.split(",").map((t) => t.trim())
    : DEFAULT_TABLES
);

function validateTable(table) {
  if (!ALLOWED_TABLES.has(table)) {
    throw new Error(`Access denied: table "${table}" is not in the allowlist`);
  }
}

// --- OAuth token store (in-memory, tokens expire after 1h) ---
const oauthTokens = new Map();

function issueOAuthToken() {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 3600 * 1000;
  oauthTokens.set(token, expiresAt);
  for (const [t, exp] of oauthTokens) {
    if (exp < Date.now()) oauthTokens.delete(t);
  }
  return { token, expiresIn: 3600 };
}

function isValidOAuthToken(token) {
  const exp = oauthTokens.get(token);
  if (!exp) return false;
  if (exp < Date.now()) {
    oauthTokens.delete(token);
    return false;
  }
  return true;
}

const SUPABASE_REST_URL = SUPABASE_URL.replace(/\/$/, "") + "/rest/v1";

// --- Supabase helpers ---
async function supabaseRequest(method, path, { headers = {}, body } = {}) {
  const url = `${SUPABASE_REST_URL}${path}`;
  const opts = {
    method,
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      "Content-Type": "application/json",
      ...headers,
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  if (!res.ok)
    throw new Error(`Supabase ${method} ${path}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

function buildFilterQuery(filters) {
  if (!filters || typeof filters !== "object") return "";
  return Object.entries(filters)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
    )
    .join("&");
}

// --- MCP Server factory ---
function createMcpServer() {
  const server = new McpServer({
    name: "supabase-sylion",
    version: "1.0.0",
  });

  server.tool("list_tables", "List all available tables in Supabase", {}, async () => {
    return {
      content: [
        { type: "text", text: JSON.stringify([...ALLOWED_TABLES], null, 2) },
      ],
    };
  });

  server.tool(
    "read_rows",
    "Read rows from a Supabase table with optional filters, column selection, ordering and limit",
    {
      table: z.string().describe("Table name"),
      filters: z
        .record(z.string())
        .optional()
        .describe(
          "PostgREST filters as key-value pairs, e.g. {\"email_envoye\": \"eq.false\", \"element_de_perso\": \"is.null\"}"
        ),
      select: z
        .string()
        .optional()
        .describe("Columns to select (default: *)"),
      order: z
        .string()
        .optional()
        .describe("Order clause, e.g. 'created_at.desc'"),
      limit: z.number().optional().describe("Max rows to return (default: 100)"),
    },
    async ({ table, filters, select, order, limit }) => {
      validateTable(table);
      let path = `/${encodeURIComponent(table)}?select=${select || "*"}`;
      const filterQuery = buildFilterQuery(filters);
      if (filterQuery) path += `&${filterQuery}`;
      if (order) path += `&order=${encodeURIComponent(order)}`;
      if (limit) path += `&limit=${limit}`;
      const data = await supabaseRequest("GET", path);
      return {
        content: [
          { type: "text", text: JSON.stringify(data, null, 2) },
        ],
      };
    }
  );

  server.tool(
    "insert_rows",
    "Insert one or more rows into a Supabase table",
    {
      table: z.string().describe("Table name"),
      rows: z
        .union([z.record(z.any()), z.array(z.record(z.any()))])
        .describe("Row object or array of row objects to insert"),
      return_rows: z
        .boolean()
        .optional()
        .describe("Return inserted rows (default: false)"),
    },
    async ({ table, rows, return_rows }) => {
      validateTable(table);
      const path = `/${encodeURIComponent(table)}`;
      const headers = {};
      if (return_rows) headers["Prefer"] = "return=representation";
      else headers["Prefer"] = "return=minimal";
      const data = await supabaseRequest("POST", path, {
        headers,
        body: rows,
      });
      return {
        content: [
          {
            type: "text",
            text: return_rows
              ? JSON.stringify(data, null, 2)
              : "Rows inserted successfully",
          },
        ],
      };
    }
  );

  server.tool(
    "update_rows",
    "Update rows in a Supabase table matching the given filters",
    {
      table: z.string().describe("Table name"),
      filters: z
        .record(z.string())
        .describe(
          "PostgREST filters to match rows, e.g. {\"id\": \"eq.42\"}"
        ),
      data: z.record(z.any()).describe("Fields to update"),
      return_rows: z
        .boolean()
        .optional()
        .describe("Return updated rows (default: false)"),
    },
    async ({ table, filters, data, return_rows }) => {
      validateTable(table);
      let path = `/${encodeURIComponent(table)}?`;
      path += buildFilterQuery(filters);
      const headers = {};
      if (return_rows) headers["Prefer"] = "return=representation";
      else headers["Prefer"] = "return=minimal";
      const result = await supabaseRequest("PATCH", path, {
        headers,
        body: data,
      });
      return {
        content: [
          {
            type: "text",
            text: return_rows
              ? JSON.stringify(result, null, 2)
              : "Rows updated successfully",
          },
        ],
      };
    }
  );

  server.tool(
    "count_rows",
    "Count rows in a Supabase table with optional filters",
    {
      table: z.string().describe("Table name"),
      filters: z
        .record(z.string())
        .optional()
        .describe("PostgREST filters as key-value pairs"),
    },
    async ({ table, filters }) => {
      validateTable(table);
      let path = `/${encodeURIComponent(table)}?select=count`;
      const filterQuery = buildFilterQuery(filters);
      if (filterQuery) path += `&${filterQuery}`;
      const data = await supabaseRequest("GET", path, {
        headers: { Prefer: "count=exact" },
      });
      const count =
        Array.isArray(data) && data[0] ? data[0].count : "unknown";
      return {
        content: [{ type: "text", text: String(count) }],
      };
    }
  );

  return server;
}

// --- Auth middleware (accepts static MCP_AUTH_TOKEN or OAuth-issued tokens) ---
const WWW_AUTHENTICATE = `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`;

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log(`Auth: rejected ${req.method} ${req.path} — no Bearer token`);
    res.set("WWW-Authenticate", WWW_AUTHENTICATE);
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = authHeader.slice(7);
  if (token === MCP_AUTH_TOKEN || isValidOAuthToken(token)) {
    return next();
  }
  console.log(`Auth: rejected ${req.method} ${req.path} — invalid token`);
  res.set("WWW-Authenticate", WWW_AUTHENTICATE);
  return res.status(401).json({ error: "Unauthorized" });
}

// --- Express app ---
const app = express();
app.use(express.json());

// Health check (no auth)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "mcp-supabase-sylion" });
});

// --- OAuth 2.0 discovery endpoints (RFC 9728 + RFC 8414) ---

// Protected Resource Metadata (RFC 9728) — tells the client where the auth server is
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: BASE_URL,
    authorization_servers: [BASE_URL],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:tools"],
  });
});

// Authorization Server Metadata (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    registration_endpoint: `${BASE_URL}/oauth/register`,
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["mcp:tools"],
  });
});

// --- OAuth 2.0 endpoints ---

const authCodes = new Map();
const registeredClients = new Map();

// Dynamic client registration (MCP spec requirement)
app.post("/oauth/register", (req, res) => {
  const clientId = req.body.client_id || crypto.randomBytes(16).toString("hex");
  const clientSecret = crypto.randomBytes(32).toString("hex");

  registeredClients.set(clientId, {
    clientSecret,
    redirectUris: req.body.redirect_uris || [],
    clientName: req.body.client_name || "MCP Client",
  });

  console.log(`OAuth: registered client ${clientId}`);

  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: req.body.client_name || "MCP Client",
    redirect_uris: req.body.redirect_uris || [],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_post",
  });
});

// Authorization endpoint (auto-approves and redirects with code)
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;

  if (response_type !== "code") {
    return res.status(400).json({ error: "unsupported_response_type" });
  }

  const isConfiguredClient = client_id === OAUTH_CLIENT_ID;
  const isRegisteredClient = registeredClients.has(client_id);
  if (!isConfiguredClient && !isRegisteredClient) {
    console.log(`OAuth: rejected unknown client_id ${client_id}`);
    return res.status(401).json({ error: "invalid_client" });
  }

  console.log(`OAuth: authorize for client ${client_id}, redirect to ${redirect_uri}`);

  const code = crypto.randomBytes(32).toString("hex");
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method || "plain",
    expiresAt: Date.now() + 60 * 1000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);
  res.redirect(302, redirectUrl.toString());
});

// Token endpoint (authorization code + client credentials flows)
app.post("/oauth/token", express.urlencoded({ extended: false }), (req, res) => {
  let clientId, clientSecret;

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const parts = decoded.split(":");
    clientId = decodeURIComponent(parts[0]);
    clientSecret = decodeURIComponent(parts.slice(1).join(":"));
  } else {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const grantType = req.body.grant_type;
  console.log(`OAuth token: grant_type=${grantType}, client=${clientId}, content-type=${req.headers["content-type"]}`);

  if (grantType === "authorization_code") {
    const { code, redirect_uri, code_verifier } = req.body;
    const stored = authCodes.get(code);

    if (!stored || stored.expiresAt < Date.now()) {
      console.log("OAuth token: invalid or expired auth code");
      authCodes.delete(code);
      return res.status(400).json({ error: "invalid_grant" });
    }

    if (stored.codeChallenge) {
      let valid = false;
      if (stored.codeChallengeMethod === "S256") {
        const hash = crypto.createHash("sha256").update(code_verifier || "").digest("base64url");
        valid = hash === stored.codeChallenge;
      } else {
        valid = code_verifier === stored.codeChallenge;
      }
      if (!valid) {
        console.log("OAuth token: PKCE verification failed");
        authCodes.delete(code);
        return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      }
    }

    if (stored.redirectUri && redirect_uri !== stored.redirectUri) {
      console.log(`OAuth token: redirect_uri mismatch: ${redirect_uri} vs ${stored.redirectUri}`);
      authCodes.delete(code);
      return res.status(400).json({ error: "invalid_grant" });
    }

    authCodes.delete(code);
    const { token, expiresIn } = issueOAuthToken();
    console.log("OAuth token: issued via authorization_code");
    return res.json({ access_token: token, token_type: "Bearer", expires_in: expiresIn });
  }

  if (grantType === "client_credentials") {
    if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
      console.log("OAuth token: OAUTH_CLIENT_ID or OAUTH_CLIENT_SECRET not configured");
      return res.status(500).json({ error: "server_error" });
    }
    const isConfigured = clientId === OAUTH_CLIENT_ID && clientSecret === OAUTH_CLIENT_SECRET;
    const registered = registeredClients.get(clientId);
    const isRegistered = registered && registered.clientSecret === clientSecret;
    if (!isConfigured && !isRegistered) {
      return res.status(401).json({ error: "invalid_client" });
    }
    const { token, expiresIn } = issueOAuthToken();
    console.log("OAuth token: issued via client_credentials");
    return res.json({ access_token: token, token_type: "Bearer", expires_in: expiresIn });
  }

  console.log(`OAuth token: unsupported grant_type: ${grantType}`);
  return res.status(400).json({ error: "unsupported_grant_type" });
});

// --- SSE transport (legacy, for mcp-remote compatibility) ---
const sseSessions = {};

app.get("/sse", authMiddleware, async (req, res) => {
  console.log("SSE: new connection");
  const transport = new SSEServerTransport("/messages", res);
  sseSessions[transport.sessionId] = transport;

  transport.onclose = () => {
    delete sseSessions[transport.sessionId];
  };

  const server = createMcpServer();
  await server.connect(transport);
});

app.post("/messages", authMiddleware, async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = sseSessions[sessionId];
  if (!transport) {
    return res.status(400).json({ error: "Invalid session" });
  }
  await transport.handlePostMessage(req, res, req.body);
});

// --- Streamable HTTP transport ---
const streamableSessions = {};

async function handleStreamablePost(req, res) {
  const sessionId = req.headers["mcp-session-id"];
  console.log(`MCP transport: POST ${req.path}, session=${sessionId || "new"}`);

  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res, req.body);
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => {
      console.log(`MCP transport: session initialized ${id}`);
      streamableSessions[id] = transport;
    },
  });

  transport.onclose = () => {
    if (transport.sessionId) {
      delete streamableSessions[transport.sessionId];
    }
  };

  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
}

async function handleStreamableGet(req, res) {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
}

async function handleStreamableDelete(req, res) {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
}

// Mount transport at root (Claude.ai POSTs to the server URL directly)
app.post("/", authMiddleware, handleStreamablePost);
app.delete("/", authMiddleware, handleStreamableDelete);
app.get("/", (req, res) => {
  if (req.headers["mcp-session-id"] || (req.headers.accept && req.headers.accept.includes("text/event-stream"))) {
    return authMiddleware(req, res, () => handleStreamableGet(req, res));
  }
  res.json({ status: "ok", server: "mcp-supabase-sylion" });
});

// Mount transport at /mcp (backwards compatibility)
app.post("/mcp", authMiddleware, handleStreamablePost);
app.get("/mcp", authMiddleware, handleStreamableGet);
app.delete("/mcp", authMiddleware, handleStreamableDelete);

// --- REST API (for agents schedule that can't use MCP transport yet) ---

app.get("/api/read_rows", authMiddleware, async (req, res) => {
  try {
    const { table, select, order, limit, ...filters } = req.query;
    if (!table) return res.status(400).json({ error: "table is required" });
    validateTable(table);
    let path = `/${encodeURIComponent(table)}?select=${select || "*"}`;
    const filterQuery = buildFilterQuery(filters);
    if (filterQuery) path += `&${filterQuery}`;
    if (order) path += `&order=${encodeURIComponent(order)}`;
    if (limit) path += `&limit=${limit}`;
    const data = await supabaseRequest("GET", path);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/insert_rows", authMiddleware, async (req, res) => {
  try {
    const { table, rows, return_rows } = req.body;
    if (!table || !rows)
      return res.status(400).json({ error: "table and rows are required" });
    validateTable(table);
    const path = `/${encodeURIComponent(table)}`;
    const headers = {};
    headers["Prefer"] = return_rows ? "return=representation" : "return=minimal";
    const data = await supabaseRequest("POST", path, { headers, body: rows });
    res.json(return_rows ? data : { ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/update_rows", authMiddleware, async (req, res) => {
  try {
    const { table, filters, data: updateData, return_rows } = req.body;
    if (!table || !filters || !updateData)
      return res
        .status(400)
        .json({ error: "table, filters and data are required" });
    validateTable(table);
    let path = `/${encodeURIComponent(table)}?`;
    path += buildFilterQuery(filters);
    const headers = {};
    headers["Prefer"] = return_rows ? "return=representation" : "return=minimal";
    const result = await supabaseRequest("PATCH", path, {
      headers,
      body: updateData,
    });
    res.json(return_rows ? result : { ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/count_rows", authMiddleware, async (req, res) => {
  try {
    const { table, ...filters } = req.query;
    if (!table) return res.status(400).json({ error: "table is required" });
    validateTable(table);
    let path = `/${encodeURIComponent(table)}?select=count`;
    const filterQuery = buildFilterQuery(filters);
    if (filterQuery) path += `&${filterQuery}`;
    const data = await supabaseRequest("GET", path, {
      headers: { Prefer: "count=exact" },
    });
    const count =
      Array.isArray(data) && data[0] ? data[0].count : "unknown";
    res.json({ count });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- Start ---
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP Supabase server running on port ${PORT}`);
});
