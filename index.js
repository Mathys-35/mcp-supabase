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

// --- Config ---
const PORT = process.env.PORT || 3100;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !MCP_AUTH_TOKEN) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_KEY, MCP_AUTH_TOKEN"
  );
  process.exit(1);
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

  // Tool: list_tables
  server.tool("list_tables", "List all available tables in Supabase", {}, async () => {
    const tables = await supabaseRequest("GET", "/?select=*", {
      headers: { Accept: "application/json" },
    }).catch(async () => {
      // Fallback: query pg_tables via PostgREST RPC if available, or use known tables
      const knownTables = [
        "prospection_immobilier",
        "prospection_recrutement",
        "config",
        "linkedin_posts",
        "linkedin_themes",
        "linkedin_viral_patterns",
        "linkedin_hook_library",
        "linkedin_veille",
        "linkedin_idees",
        "linkedin_engagement",
        "linkedin_lead_magnets",
      ];
      return knownTables;
    });
    return {
      content: [
        { type: "text", text: JSON.stringify(tables, null, 2) },
      ],
    };
  });

  // Tool: read_rows
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

  // Tool: insert_rows
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

  // Tool: update_rows
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

  // Tool: count_rows
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

// --- Auth middleware ---
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }
  const token = authHeader.slice(7);
  if (token !== MCP_AUTH_TOKEN) {
    return res.status(403).json({ error: "Invalid token" });
  }
  next();
}

// --- Express app ---
const app = express();
app.use(express.json());

// Health check (no auth)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "mcp-supabase-sylion" });
});

// --- SSE transport (legacy, for mcp-remote compatibility) ---
const sseSessions = {};

app.get("/sse", authMiddleware, async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  sseSessions[transport.sessionId] = transport;

  transport.onclose = () => {
    delete sseSessions[transport.sessionId];
  };

  const server = createMcpServer();
  await server.connect(transport);
  await transport.start();
});

app.post("/messages", authMiddleware, async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = sseSessions[sessionId];
  if (!transport) {
    return res.status(400).json({ error: "Invalid session" });
  }
  await transport.handlePostMessage(req, res, req.body);
});

// --- Streamable HTTP transport (modern) ---
const streamableSessions = {};

app.post("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];

  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res, req.body);
    return;
  }

  // New session
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => {
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
});

app.get("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
});

app.delete("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && streamableSessions[sessionId]) {
    await streamableSessions[sessionId].handleRequest(req, res);
  } else {
    res.status(400).json({ error: "Invalid session" });
  }
});

// --- Start ---
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP Supabase server running on port ${PORT}`);
});
