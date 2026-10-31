import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const ROOT = path.resolve(process.env.DOCS_ROOT ?? "./docs");
const ALLOWED_HOSTS = new Set(["docs.example.com"]);
const server = new McpServer({ name: "devtools", version: "1.0.0" });

server.tool("git_log", "Show recent commits for a branch.", { branch: z.string().regex(/^[\w./-]+$/) }, async ({ branch }) => {
  const out = await new Promise<string>((resolve, reject) =>
    execFile("git", ["log", "--oneline", "--", branch], (e, stdout) => (e ? reject(e) : resolve(stdout))),
  );
  return { content: [{ type: "text", text: out }] };
});

server.tool("read_doc", "Read a documentation file inside the docs folder.", { path: z.string() }, async (args) => {
  const full = await realpath(path.resolve(ROOT, args.path));
  if (!full.startsWith(ROOT + path.sep)) throw new Error("outside docs folder");
  return { content: [{ type: "text", text: await readFile(full, "utf8") }] };
});

server.tool("fetch_doc", "Fetch a page from docs.example.com.", { url: z.string().url() }, async (args) => {
  const u = new URL(args.url);
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) throw new Error("host not allowed");
  const res = await fetch(u);
  return { content: [{ type: "text", text: await res.text() }] };
});

export default server;
