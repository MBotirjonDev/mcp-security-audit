#!/usr/bin/env node
'use strict';
/**
 * mcp-security-audit scanner. Zero dependencies, Node >= 18.
 *
 * Finds security leads in everything an AI coding agent loads or runs from a project:
 *   - MCP client configs   (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json,
 *                           ~/.claude.json, .gemini/settings.json, .codex/config.toml …)
 *   - MCP server source    (TypeScript/JavaScript/Python servers built on the MCP SDKs / FastMCP)
 *   - instruction files    (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules, SKILL.md,
 *                           copilot-instructions.md, .windsurfrules, .clinerules, commands, agents)
 *   - agent settings       (.claude/settings*.json permissions and hooks, Codex approval/sandbox)
 *
 * It only reads files. It makes no network calls and runs no commands. Secrets it finds are
 * masked in every output. Text decoded from hidden characters is printed as quoted data.
 *
 *   node scan.cjs [path] [--out leads.json] [--sarif leads.sarif] [--min-severity low]
 *                 [--fail-on high] [--user-config] [--include-tests] [--quiet] [--json]
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const RULES = require('./rules.cjs');

const VERSION = '0.1.0';
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const rank = (s) => SEVERITIES.indexOf(s);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit',
  'vendor', 'venv', '.venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache', '.tox', 'target',
  'coverage', '.dart_tool', 'Pods', '.gradle', '.idea', '.turbo', '.cache', 'site-packages',
]);
const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'fixtures', '__fixtures__', 'spec', 'e2e', 'testdata', 'evals', 'benchmarks', 'benchmark']);
const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py']);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 25000;

// ─── small helpers ───────────────────────────────────────────────────────────

const lineAt = (text, idx) => (idx <= 0 ? 1 : text.slice(0, idx).split('\n').length);
const toPosix = (p) => p.split(path.sep).join('/');
const clip = (s, n = 90) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function mask(secret) {
  const s = String(secret);
  if (s.length <= 8) return '****';
  return `${s.slice(0, 4)}…(${s.length} chars)`;
}

function readText(file) {
  let buf;
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    buf = fs.readFileSync(file);
  } catch { return null; }
  if (buf.subarray(0, 8000).includes(0)) return null; // binary
  return buf.toString('utf8');
}

/** JSON with comments and trailing commas (VS Code / Cursor configs). */
function parseJsonc(text) {
  try { return JSON.parse(text); } catch { /* fall through */ }
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') { out += n || ''; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === '/' && n === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') out += '\n'; i++; } i += 2; continue; }
    out += c;
    i++;
  }
  out = out.replace(/,(\s*[}\]])/g, '$1');
  try { return JSON.parse(out); } catch { return null; }
}

/** Just enough TOML for Codex: [mcp_servers.<name>] tables with strings, arrays and inline tables. */
function parseCodexToml(text) {
  const result = { servers: [], top: {} };
  const lines = text.split('\n');
  let table = null;
  let current = result.top;
  const parseValue = (raw) => {
    const v = raw.trim();
    if (/^"(?:[^"\\]|\\.)*"$/.test(v)) { try { return JSON.parse(v); } catch { return v.slice(1, -1); } }
    if (/^'[^']*'$/.test(v)) return v.slice(1, -1);
    if (v === 'true' || v === 'false') return v === 'true';
    if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
    if (v.startsWith('[')) {
      const items = [];
      const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
      let m;
      while ((m = re.exec(v))) items.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : m[2]);
      return items;
    }
    if (v.startsWith('{')) {
      const obj = {};
      const re = /([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')/g;
      let m;
      while ((m = re.exec(v))) obj[m[1].replace(/^"|"$/g, '')] = parseValue(m[2]);
      return obj;
    }
    return v;
  };
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const t = line.match(/^\[([^\]]+)\]$/);
    if (t) {
      const parts = t[1].split('.').map((p) => p.trim().replace(/^"|"$/g, ''));
      if (parts[0] === 'mcp_servers' && parts.length >= 2) {
        let srv = result.servers.find((s) => s.name === parts[1]);
        if (!srv) { srv = { name: parts[1], def: {}, line: i + 1 }; result.servers.push(srv); }
        if (parts.length === 2) current = srv.def;
        else { srv.def[parts[2]] = srv.def[parts[2]] || {}; current = srv.def[parts[2]]; }
        table = parts;
      } else { table = parts; current = {}; }
      continue;
    }
    const kv = line.match(/^([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*(.*)$/);
    if (!kv) continue;
    let raw = kv[2];
    // multi-line arrays / inline tables
    const open = (s) => (s.match(/[[{]/g) || []).length - (s.match(/[\]}]/g) || []).length;
    while (open(raw) > 0 && i + 1 < lines.length) { i++; raw += ` ${lines[i].trim()}`; }
    const key = kv[1].replace(/^"|"$/g, '');
    current[key] = parseValue(raw);
    if (!table) result.top[key] = current[key];
  }
  return result;
}

function semverLt(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) < (pb[i] || 0)) return true;
    if ((pa[i] || 0) > (pb[i] || 0)) return false;
  }
  return false;
}

// ─── secrets ─────────────────────────────────────────────────────────────────

const KNOWN_SECRETS = [
  ['GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['AWS access key id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['Stripe live key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/],
  ['Notion token', /\b(?:secret_|ntn_)[A-Za-z0-9]{30,}/],
  ['Supabase secret key', /\bsb_secret_[A-Za-z0-9_-]{20,}/],
  ['Linear API key', /\blin_api_[A-Za-z0-9]{30,}/],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
];
const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|\bPAT\b|_PAT$|CREDENTIAL|AUTH)/i;
const PLACEHOLDER = /^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_]+%|<[^>]+>|\{\{[^}]+\}\}|\[[^\]]+\])$|\$\{(env|input):|^(your|my|insert|enter|replace|paste|put)[-_ ]|^x{4,}|placeholder|changeme|example|dummy|redacted|^\*+$|^\.\.\.$|^<.*>$|^TODO/i;

function findKnownSecret(value) {
  if (typeof value !== 'string') return null;
  for (const [kind, re] of KNOWN_SECRETS) {
    const m = value.match(re);
    if (m) return { kind, value: m[0] };
  }
  return null;
}

function looksLikeLiteralSecret(name, value) {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.length < 12 || PLACEHOLDER.test(v)) return false;
  if (/^(true|false|null|\d+)$/i.test(v) || /^https?:\/\//i.test(v) || /^[./~]/.test(v) || /\s/.test(v)) return false;
  if (!SECRET_NAME.test(name)) return false;
  if (/^(Bearer|Basic|token)\s/i.test(v)) return true;
  return /[A-Za-z]/.test(v) && /\d/.test(v);
}

// ─── file classification ─────────────────────────────────────────────────────

const CONFIG_BASENAMES = new Set(['.mcp.json', 'mcp.json', 'mcp_config.json', 'claude_desktop_config.json', '.claude.json', 'mcp_settings.json', 'cline_mcp_settings.json']);
const INSTRUCTION_BASENAMES = new Set(['CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'AGENT.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules', '.roorules', 'copilot-instructions.md', 'SKILL.md', 'CONVENTIONS.md', '.goosehints']);

function classify(rel) {
  const base = path.posix.basename(rel);
  const kinds = [];
  if (CONFIG_BASENAMES.has(base)) kinds.push('config');
  if (/(^|\/)\.(cursor|vscode|gemini|roo|kiro|amazonq|windsurf|continue)\/[^/]*mcp[^/]*\.json$/i.test(rel)) kinds.push('config');
  if (/(^|\/)\.(gemini|qwen)\/settings\.json$/.test(rel)) kinds.push('config');
  if (/(^|\/)\.vscode\/settings\.json$/.test(rel)) kinds.push('config');
  if (/(^|\/)\.codex\/config\.toml$/.test(rel)) kinds.push('codex');
  if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(rel)) kinds.push('settings');
  if (INSTRUCTION_BASENAMES.has(base)) kinds.push('instructions');
  else if (/(^|\/)\.cursor\/rules\/.+\.(mdc|md)$/i.test(rel)
    || /(^|\/)\.github\/(instructions\/.+\.instructions\.md|prompts\/.+\.prompt\.md|chatmodes\/.+\.md)$/.test(rel)
    || /(^|\/)\.(claude|gemini|qwen)\/(commands|agents|skills)\/.+\.(md|toml)$/.test(rel)
    || /(^|\/)\.(clinerules|windsurf\/rules|roo\/rules[^/]*|kiro\/steering|amazonq\/rules|continue\/rules)\/.+\.(md|mdc|txt)$/.test(rel)) kinds.push('instructions');
  if (SOURCE_EXT.has(path.posix.extname(rel))) kinds.push('source');
  return [...new Set(kinds)];
}

function walk(root, opts) {
  const files = [];
  const stack = [''];
  while (stack.length && files.length < MAX_FILES) {
    const relDir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (!opts.includeTests && TEST_DIRS.has(e.name)) continue;
        stack.push(rel);
      } else if (e.isFile()) files.push(rel);
    }
  }
  return files.sort();
}

function userConfigPaths() {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  return [
    ['~/.claude.json', path.join(home, '.claude.json'), 'config'],
    ['~/.claude/settings.json', path.join(home, '.claude', 'settings.json'), 'settings'],
    ['~/.cursor/mcp.json', path.join(home, '.cursor', 'mcp.json'), 'config'],
    ['~/.codeium/windsurf/mcp_config.json', path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), 'config'],
    ['~/.gemini/settings.json', path.join(home, '.gemini', 'settings.json'), 'config'],
    ['~/.codex/config.toml', path.join(home, '.codex', 'config.toml'), 'codex'],
    ['~/Library/Application Support/Claude/claude_desktop_config.json', path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), 'config'],
    ['~/.config/Claude/claude_desktop_config.json', path.join(home, '.config', 'Claude', 'claude_desktop_config.json'), 'config'],
    ['%APPDATA%/Claude/claude_desktop_config.json', path.join(appData, 'Claude', 'claude_desktop_config.json'), 'config'],
    ['~/CLAUDE.md', path.join(home, '.claude', 'CLAUDE.md'), 'instructions'],
  ].filter(([, abs]) => { try { return fs.statSync(abs).isFile(); } catch { return false; } });
}

// ─── scanner state ───────────────────────────────────────────────────────────

function createScan(opts) {
  const leads = [];
  const seen = new Set();
  const stats = { configs: 0, servers: 0, instructions: 0, settings: 0, serverSources: 0 };
  const add = (rule, file, line, message, extra = {}) => {
    const meta = RULES[rule];
    if (!meta) throw new Error(`unknown rule ${rule}`);
    const key = `${rule}|${file}|${line}|${message}`;
    if (seen.has(key)) return;
    seen.add(key);
    leads.push({
      rule,
      severity: extra.severity || meta.severity,
      title: meta.title,
      message,
      file,
      line: line || 1,
      evidence: extra.evidence,
      guide: `checks/${meta.guide}`,
      fix: meta.fix,
      cwe: meta.cwe,
    });
  };
  return { opts, leads, stats, add };
}

// ─── MCP client configs ──────────────────────────────────────────────────────

function collectServers(obj, isMcpFile) {
  const out = [];
  if (!obj || typeof obj !== 'object') return out;
  const take = (map, scope) => {
    if (!map || typeof map !== 'object' || Array.isArray(map)) return;
    for (const [name, def] of Object.entries(map)) {
      if (def && typeof def === 'object' && !Array.isArray(def)) out.push({ name, def, scope });
    }
  };
  take(obj.mcpServers, '');
  if (isMcpFile) take(obj.servers, '');
  if (obj.mcp && typeof obj.mcp === 'object') take(obj.mcp.servers, '');
  take(obj.context_servers, '');
  if (obj.projects && typeof obj.projects === 'object') {
    for (const [proj, p] of Object.entries(obj.projects)) if (p && typeof p === 'object') take(p.mcpServers, proj);
  }
  return out;
}

const LAUNCHERS = new Set(['npx', 'bunx', 'pnpx', 'uvx', 'npx.cmd', 'bunx.cmd', 'pnpx.cmd', 'uvx.exe']);
const DOCKER_VALUE_FLAGS = new Set(['-v', '--volume', '--mount', '-e', '--env', '--env-file', '--name', '--network', '--net', '-p', '--publish', '-w', '--workdir', '--entrypoint', '-u', '--user', '--cap-add', '--cap-drop', '--pid', '--platform', '-l', '--label', '--add-host', '-m', '--memory', '--cpus', '--tmpfs', '--device', '--security-opt', '--ipc', '--hostname', '-h', '--restart', '--pull', '--log-driver', '--ulimit', '--gpus', '--shm-size']);

function splitCommand(def) {
  let command = typeof def.command === 'string' ? def.command.trim() : '';
  let args = Array.isArray(def.args) ? def.args.filter((a) => typeof a === 'string') : [];
  // "command": "npx -y pkg" written as one string
  if (command.includes(' ') && !/[\\/]/.test(command.split(' ')[0]) && args.length === 0) {
    const parts = command.split(/\s+/);
    command = parts[0];
    args = parts.slice(1);
  }
  return { command, args };
}

function packageArg(cmdBase, args) {
  // returns the package spec run by a launcher, or null
  let i = 0;
  if (cmdBase === 'pnpm' || cmdBase === 'yarn') { if (args[0] !== 'dlx') return null; i = 1; }
  if (cmdBase === 'npm') { if (args[0] !== 'exec') return null; i = 1; }
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '--') continue;
    if (a === '-p' || a === '--package' || a === '--from' || a === '--with') return args[i + 1] || null;
    if (/^--(package|from)=/.test(a)) return a.split('=').slice(1).join('=');
    if (a.startsWith('-')) continue;
    return a;
  }
  return null;
}

function isPinned(spec, kind) {
  if (!spec) return true;
  if (/^(\.|\/|~|[A-Za-z]:\\|file:)/.test(spec)) return true; // local path
  if (/^(git\+|https?:\/\/|github:)/.test(spec)) return /#[0-9a-f]{7,40}$|@[0-9a-f]{40}$/.test(spec);
  if (kind === 'uv') return /==\s*\d|@\d/.test(spec);
  const m = spec.match(/^(@[^/]+\/[^@]+|[^@]+)(?:@(.+))?$/);
  if (!m) return true;
  const ver = m[2];
  if (!ver) return false;
  return /^\d+\.\d+\.\d+/.test(ver) && !/[\^~*x]/.test(ver);
}

const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0|host\.docker\.internal)$/i;
const BROAD_ROOTS = /^(\/|~|~\/|\$HOME|\$\{HOME\}|%USERPROFILE%|\/Users\/?|\/home\/?|\/root\/?|[A-Za-z]:[\\/]?|\/Users\/[^/]+\/?|\/home\/[^/]+\/?|[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]?)$/;
const DOWNLOAD_PIPE = /(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*iex\b|Invoke-Expression|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh/i;

function analyzeServer(scan, file, text, srv) {
  const { name, def } = srv;
  const anchorIdx = Math.max(0, text.indexOf(JSON.stringify(name)));
  const lineOf = (needle) => {
    if (needle === undefined || needle === null) return lineAt(text, anchorIdx);
    const n = JSON.stringify(String(needle)).slice(1, -1);
    let i = text.indexOf(n, anchorIdx);
    if (i < 0) i = text.indexOf(n);
    return lineAt(text, i < 0 ? anchorIdx : i);
  };
  const label = srv.scope ? `"${name}" (project ${srv.scope})` : `"${name}"`;
  const { command, args } = splitCommand(def);
  const cmdBase = path.basename(command || '').toLowerCase().replace(/\.(exe|cmd)$/, '');

  // secrets in env / headers / url / args
  const env = def.env && typeof def.env === 'object' ? def.env : {};
  const headers = def.headers && typeof def.headers === 'object' ? def.headers : {};
  const checkValue = (where, key, value) => {
    if (typeof value !== 'string') return;
    const known = findKnownSecret(value);
    if (known && !PLACEHOLDER.test(value.trim())) {
      scan.add('MCP-CFG-001', file, lineOf(value), `${label} has a literal ${known.kind} in ${where}${key ? ` ${key}` : ''}`, { evidence: mask(known.value) });
    } else if (looksLikeLiteralSecret(key || '', value)) {
      scan.add('MCP-CFG-001', file, lineOf(value), `${label} has a literal secret in ${where} ${key}`, { evidence: mask(value), severity: 'high' });
    }
  };
  for (const [k, v] of Object.entries(env)) checkValue('env', k, v);
  for (const [k, v] of Object.entries(headers)) checkValue('headers', k, v);
  const url = def.url || def.httpUrl || def.serverUrl || def.uri;
  if (typeof url === 'string') {
    const known = findKnownSecret(url);
    const q = url.match(/[?&](api[_-]?key|token|access_token|key|secret|auth)=([^&#]{12,})/i);
    if (known) scan.add('MCP-CFG-001', file, lineOf(url), `${label} has a literal ${known.kind} in its URL`, { evidence: mask(known.value) });
    else if (q && !PLACEHOLDER.test(q[2])) scan.add('MCP-CFG-001', file, lineOf(url), `${label} has a credential in the URL query (${q[1]}=)`, { evidence: mask(q[2]), severity: 'high' });
  }
  args.forEach((a, i) => {
    const known = findKnownSecret(a);
    if (known) scan.add('MCP-CFG-001', file, lineOf(a), `${label} has a literal ${known.kind} in args`, { evidence: mask(known.value) });
    const flag = a.match(/^--?(token|api[-_]?key|access[-_]?token|secret|password|pat|auth[-_]?token|key)(=(.*))?$/i);
    if (flag) {
      const val = flag[3] !== undefined ? flag[3] : args[i + 1];
      if (val) scan.add('MCP-CFG-008', file, lineOf(a), `${label} passes ${flag[1]} as a command-line argument`, { evidence: PLACEHOLDER.test(val) ? val : mask(val) });
    }
  });

  // plain http
  const urls = [url, ...args.filter((a) => /^https?:\/\//i.test(a))].filter((u) => typeof u === 'string');
  for (const u of urls) {
    const m = u.match(/^http:\/\/([^/:?#]+|\[[^\]]+\])/i);
    if (m && !LOCAL_HOST.test(m[1])) scan.add('MCP-CFG-003', file, lineOf(u), `${label} connects to ${m[1]} over plain http`, { evidence: clip(u.replace(/([?&][^=]+=)[^&]+/g, '$1…')) });
  }

  if (!command) return;
  const full = [command, ...args].join(' ');

  // shell launchers and download pipes
  let effCmd = cmdBase;
  let effArgs = args;
  if (cmdBase === 'cmd' && /^\/c$/i.test(args[0] || '')) {
    effCmd = path.basename(args[1] || '').toLowerCase().replace(/\.(exe|cmd)$/, '');
    effArgs = args.slice(2);
  }
  if (DOWNLOAD_PIPE.test(full)) {
    scan.add('MCP-CFG-004', file, lineOf(command), `${label} pipes a download into a shell at launch`, { evidence: clip(full) });
  } else if (['bash', 'sh', 'zsh', 'dash', 'fish'].includes(cmdBase) && args.some((a) => /^-[a-z]*c[a-z]*$/.test(a))) {
    scan.add('MCP-CFG-004', file, lineOf(command), `${label} is launched through ${cmdBase} -c`, { evidence: clip(full), severity: 'medium' });
  } else if (['powershell', 'pwsh'].includes(cmdBase) && args.some((a) => /^-(c|command|e|encodedcommand)$/i.test(a))) {
    scan.add('MCP-CFG-004', file, lineOf(command), `${label} is launched through ${cmdBase} ${args.find((a) => /^-(c|command|e|encodedcommand)$/i.test(a))}`, { evidence: clip(full), severity: /^-e/i.test(args.find((a) => /^-(c|command|e|encodedcommand)$/i.test(a))) ? 'high' : 'medium' });
  }

  // launchers: pinning, mcp-remote CVE, filesystem roots
  const launcherKind = LAUNCHERS.has(effCmd) || LAUNCHERS.has(`${effCmd}.cmd`) ? (effCmd.startsWith('uvx') ? 'uv' : 'npm')
    : (['pnpm', 'yarn', 'npm'].includes(effCmd) ? 'npm' : (effCmd === 'pipx' && effArgs[0] === 'run' ? 'uv' : null));
  if (launcherKind) {
    const spec = packageArg(effCmd === 'pipx' ? 'npx' : effCmd, effCmd === 'pipx' ? effArgs.slice(1) : effArgs);
    if (spec) {
      if (!isPinned(spec, launcherKind)) {
        scan.add('MCP-CFG-002', file, lineOf(spec), `${label} runs ${spec} without a pinned version`, { evidence: clip([effCmd, ...effArgs].join(' ')) });
      }
      const remote = spec.match(/^mcp-remote@(\d+\.\d+\.\d+)/);
      if (remote && semverLt(remote[1], '0.1.16')) {
        scan.add('MCP-CFG-007', file, lineOf(spec), `${label} uses mcp-remote ${remote[1]} (fixed in 0.1.16)`, { evidence: spec });
      }
      if (/server-filesystem/.test(spec)) {
        const idx = effArgs.indexOf(spec);
        for (const root of effArgs.slice(idx + 1)) {
          if (!root.startsWith('-') && BROAD_ROOTS.test(root.trim())) {
            scan.add('MCP-CFG-006', file, lineOf(root), `${label} gives the filesystem server access to ${root}`, { evidence: root });
          }
        }
      }
    }
  }

  // docker / podman
  if (['docker', 'podman'].includes(effCmd) && effArgs.includes('run')) {
    const runArgs = effArgs.slice(effArgs.indexOf('run') + 1);
    let image = null;
    for (let i = 0; i < runArgs.length; i++) {
      const a = runArgs[i];
      const next = runArgs[i + 1] || '';
      const flagName = a.split('=')[0];
      const value = a.includes('=') ? a.split('=').slice(1).join('=') : next;
      if (a === '--privileged' || a === '--privileged=true') scan.add('MCP-CFG-005', file, lineOf(a), `${label} runs the container with --privileged`, { evidence: a });
      if (['--network', '--net'].includes(flagName) && value === 'host') scan.add('MCP-CFG-005', file, lineOf(a), `${label} shares the host network`, { evidence: `${flagName} host`, severity: 'medium' });
      if (flagName === '--pid' && value === 'host') scan.add('MCP-CFG-005', file, lineOf(a), `${label} shares the host PID namespace`, { evidence: '--pid host' });
      if (flagName === '--cap-add' && /^(ALL|SYS_ADMIN|SYS_PTRACE)$/i.test(value)) scan.add('MCP-CFG-005', file, lineOf(a), `${label} adds capability ${value}`, { evidence: `--cap-add ${value}` });
      if (['-v', '--volume', '--mount'].includes(flagName)) {
        const src = flagName === '--mount' ? ((value.match(/(?:^|,)(?:source|src)=([^,]+)/) || [])[1] || '') : value.split(':').slice(0, value.match(/^[A-Za-z]:\\/) ? 2 : 1).join(':');
        if (/docker\.sock/.test(src)) scan.add('MCP-CFG-005', file, lineOf(value), `${label} mounts the Docker socket (full control of the host's Docker)`, { evidence: clip(value) });
        else if (BROAD_ROOTS.test(src.trim())) scan.add('MCP-CFG-005', file, lineOf(value), `${label} mounts ${src} into the container`, { evidence: clip(value) });
      }
      if (a.startsWith('-')) {
        if (!a.includes('=') && DOCKER_VALUE_FLAGS.has(a)) i++;
        continue;
      }
      image = a;
      break;
    }
    if (image && !/@sha256:[0-9a-f]{64}$/.test(image)) {
      const last = image.split('/').pop();
      const tag = last.includes(':') ? last.split(':').pop() : '';
      if (!tag || tag === 'latest') scan.add('MCP-CFG-002', file, lineOf(image), `${label} runs image ${image} without a fixed tag or digest`, { evidence: image, severity: 'low' });
    }
  }
}

function analyzeConfig(scan, file, text, isMcpFile) {
  const obj = parseJsonc(text);
  if (!obj) return;
  const servers = collectServers(obj, isMcpFile);
  if (servers.length === 0) return;
  scan.stats.configs++;
  scan.stats.servers += servers.length;
  for (const srv of servers) analyzeServer(scan, file, text, srv);
}

function analyzeCodex(scan, file, text) {
  const toml = parseCodexToml(text);
  if (toml.servers.length) { scan.stats.configs++; scan.stats.servers += toml.servers.length; }
  for (const srv of toml.servers) analyzeServer(scan, file, text, { name: srv.name, def: srv.def, scope: '' });
  const ap = toml.top.approval_policy;
  const sb = toml.top.sandbox_mode;
  if (sb === 'danger-full-access' || (ap === 'never' && sb !== 'read-only' && sb !== 'workspace-write')) {
    const i = text.search(/sandbox_mode|approval_policy/);
    scan.add('AGT-PERM-001', file, lineAt(text, i), `Codex runs with approval_policy=${ap || '(default)'} and sandbox_mode=${sb || '(default)'}`, { evidence: `approval_policy=${ap}, sandbox_mode=${sb}` });
  }
}

// ─── agent settings (Claude Code) ────────────────────────────────────────────

const NET_CMD = /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|netcat|scp|rsync|ftp)\b/i;
const SENDS_DATA = /\s(-d|--data[\w-]*|-F|--form|-T|--upload-file|-X\s*(POST|PUT))\b|-Method\s+(Post|Put)|\|\s*(curl|nc)\b|>\s*\/dev\/tcp/i;

function analyzeSettings(scan, file, text, ctx) {
  const obj = parseJsonc(text);
  if (!obj || typeof obj !== 'object') return;
  scan.stats.settings++;
  const perms = obj.permissions || {};
  const at = (needle) => { const i = text.indexOf(needle); return lineAt(text, i < 0 ? 0 : i); };
  if (perms.defaultMode === 'bypassPermissions') {
    scan.add('AGT-PERM-001', file, at('bypassPermissions'), 'permissions.defaultMode is bypassPermissions: every tool call runs without confirmation', { evidence: '"defaultMode": "bypassPermissions"' });
  }
  const allow = Array.isArray(perms.allow) ? perms.allow : [];
  for (const rule of allow) {
    if (typeof rule !== 'string') continue;
    if (/^Bash(\(\s*\*?\s*(:\s*\*)?\s*\))?$/.test(rule.trim())) {
      scan.add('AGT-PERM-001', file, at(rule), `permissions.allow contains ${rule}: any shell command runs without confirmation`, { evidence: rule });
    }
  }
  if (obj.enableAllProjectMcpServers === true) {
    scan.add('AGT-PERM-002', file, at('enableAllProjectMcpServers'), 'enableAllProjectMcpServers is true: MCP servers from any opened repository start without approval', { evidence: '"enableAllProjectMcpServers": true' });
  }
  // hooks: every "command" string under hooks
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(visit); return; }
    for (const [k, v] of Object.entries(node)) {
      if (k === 'command' && typeof v === 'string') {
        if (DOWNLOAD_PIPE.test(v)) scan.add('AGT-PERM-003', file, at(JSON.stringify(v).slice(1, -1)), 'hook downloads a script and runs it', { evidence: clip(v) });
        else if (NET_CMD.test(v)) {
          const sends = SENDS_DATA.test(v);
          scan.add('AGT-PERM-003', file, at(JSON.stringify(v).slice(1, -1)), sends ? 'hook sends data over the network' : 'hook makes network requests', { evidence: clip(v), severity: sends ? 'high' : 'medium' });
        }
      } else visit(v);
    }
  };
  visit(obj.hooks);
  // secrets readable
  if (ctx && ctx.secretFiles.length && !/^~\//.test(file)) {
    const deny = Array.isArray(perms.deny) ? perms.deny.join(' ') : '';
    if (!/\.env|secret|\*\*/i.test(deny)) {
      scan.add('AGT-PERM-004', file, at('permissions') || 1, `project has ${ctx.secretFiles.slice(0, 3).join(', ')}${ctx.secretFiles.length > 3 ? ', …' : ''} but no deny rule for them`, { evidence: ctx.secretFiles[0] });
    }
  }
}

// ─── instruction files ───────────────────────────────────────────────────────

const RE_OVERRIDE = /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|every\s+)?(of\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding|original|system)\s+(instructions?|rules|guidelines|prompts?|directives)/i;
const RE_CONCEAL = /\b(do\s*n[o']?t|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|notify(ing)?|alert(ing)?|ask(ing)?|show(ing)?)\s+(this\s+|it\s+)?(to\s+)?(the\s+)?(user|developer|human|operator)\b/i;
/** Concealment that hides something from the user, not ordinary "don't tell the user it's done until…" rules. */
function concealMatch(line) {
  const m = line.match(RE_CONCEAL);
  if (!m) return null;
  const before = line.slice(0, m.index);
  const tail = line.slice(m.index + m[0].length);
  if (/^without/i.test(m[1])) {
    // "Never delete files without asking the user" is a safety rule, not concealment
    if (/\b(never|don'?t|do\s+not|must\s+not|should\s+not|shouldn'?t|cannot|can'?t)\b[^.!?]*$/i.test(before)) return null;
    if (/^ask/i.test(m[2])) return null;
    return m;
  }
  if (/\b(it|this|that|these|them)\s+(to\s+)?(the\s+)?(user|developer|human|operator)/i.test(m[0])) return m;
  if (/^\s*([.,;:!)\]"'`]|$|about\b|that\s+you\b|what\s+you\b|you\b|of\b|regarding\b|anything\b|this\b|these\b|it\b|how\b|where\b|why\b|the\s+(change|code|snippet|tool|instruction|request|file|step|url|link|data|key|token)s?\b)/i.test(tail)) return m;
  return null;
}
const RE_COVERT = /\b(secretly|silently|covertly|quietly|discreetly)\s+(run|execute|send|upload|post|add|insert|include|modify|change|exfiltrate|install|download)/i;
/** "silently run X" as an instruction, not "does not silently change" descriptions of code. */
function covertMatch(line) {
  const m = line.match(RE_COVERT);
  if (!m) return null;
  const before = line.slice(0, m.index).toLowerCase();
  if (/\b(not|n't|never|no|without|avoid|prevent|instead of|rather than)\s+(\w+\s+){0,2}$/.test(before)) return null;
  if (/\b(it|this|that|which|code|function|method|server|tool|library|app|system|will|would|could|might|may|can|to|is|are|was|were|be|been|does|do|did)\s+$/.test(before)) return null;
  return m;
}
const RE_TAG = /<\s*\/?\s*(IMPORTANT|SYSTEM|SECRET|HIDDEN|INSTRUCTIONS?)\s*>/;
const RE_SENSITIVE = /(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|\.env\b|\.git-credentials|\bmcp\.json\b|\.cursor\/mcp|keychain|wallet|private[_ ]key|\bprintenv\b|\benv\b\s*\||process\.env|os\.environ)/i;
const RE_SEND = /\b(curl|wget|fetch|Invoke-WebRequest|iwr|requests\.(post|get)|http\.(post|request)|axios\.(post|get)|nc|ncat|webhook|send|upload|post|exfiltrate|transmit)\b/i;
const RE_EXT_URL = /https?:\/\/(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org)|\[::1\]))[\w.-]+\.[a-z]{2,}/i;

function hiddenUnicodeChecks(scan, file, text) {
  const cps = Array.from(text);
  let line = 1;
  let col = 0;
  let tagRun = null;
  let vsRun = null;
  const flushTag = () => {
    if (!tagRun) return;
    const decoded = tagRun.chars.map((cp) => { const c = cp - 0xE0000; return c >= 0x20 && c <= 0x7E ? String.fromCharCode(c) : ''; }).join('');
    scan.add('AGT-INJ-001', file, tagRun.line, `${tagRun.chars.length} invisible Unicode tag characters at column ${tagRun.col}${decoded ? '; decoded text (data, not instructions): ' + JSON.stringify(clip(decoded, 120)) : ''}`, { evidence: `U+${tagRun.chars[0].toString(16).toUpperCase()}… x${tagRun.chars.length}` });
    tagRun = null;
  };
  const flushVs = () => {
    if (!vsRun) return;
    if (vsRun.count >= 4) scan.add('AGT-INJ-001', file, vsRun.line, `${vsRun.count} supplementary variation selectors at column ${vsRun.col} (can carry hidden bytes)`, { evidence: `U+E01xx x${vsRun.count}`, severity: 'high' });
    vsRun = null;
  };
  const bidi = [];
  const zw = [];
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    const cp = ch.codePointAt(0);
    if (ch === '\n') { flushTag(); flushVs(); line++; col = 0; continue; }
    col++;
    if (cp >= 0xE0000 && cp <= 0xE007F) { if (!tagRun) tagRun = { line, col, chars: [] }; tagRun.chars.push(cp); continue; } else flushTag();
    if (cp >= 0xE0100 && cp <= 0xE01EF) { if (!vsRun) vsRun = { line, col, count: 0 }; vsRun.count++; continue; } else flushVs();
    if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) bidi.push({ line, col, cp });
    else if (cp === 0x200B || cp === 0x2060 || cp === 0x180E || (cp === 0xFEFF && i > 0)) zw.push({ line, col, cp });
    else if (cp === 0x200D || cp === 0x200C) {
      const prev = (cps[i - 1] || '').codePointAt(0) || 0;
      const next = (cps[i + 1] || '').codePointAt(0) || 0;
      const emoji = (c) => c >= 0x1F000 || (c >= 0x2600 && c <= 0x27BF) || c === 0xFE0F || (c >= 0x2190 && c <= 0x2BFF);
      const complexScript = (c) => (c >= 0x0600 && c <= 0x06FF) || (c >= 0x0900 && c <= 0x0DFF) || (c >= 0x0750 && c <= 0x077F) || (c >= 0xFB50 && c <= 0xFDFF);
      if (!(emoji(prev) || emoji(next) || complexScript(prev) || complexScript(next))) zw.push({ line, col, cp });
    }
  }
  flushTag();
  flushVs();
  const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
  if (bidi.length) scan.add('AGT-INJ-002', file, bidi[0].line, `${bidi.length} bidirectional control character(s), first at column ${bidi[0].col}`, { evidence: [...new Set(bidi.map((b) => hex(b.cp)))].join(', ') });
  if (zw.length) scan.add('AGT-INJ-002', file, zw[0].line, `${zw.length} zero-width character(s), first at column ${zw[0].col}`, { evidence: [...new Set(zw.map((b) => hex(b.cp)))].join(', '), severity: zw.length >= 3 ? 'high' : 'medium' });
}

function analyzeInstructions(scan, file, text) {
  scan.stats.instructions++;
  hiddenUnicodeChecks(scan, file, text);
  const lines = text.split('\n');
  lines.forEach((raw, i) => {
    const l = raw.length > 2000 ? raw.slice(0, 2000) : raw;
    const ln = i + 1;
    let m;
    if ((m = l.match(RE_OVERRIDE))) scan.add('AGT-INJ-003', file, ln, `tells the agent to "${m[0]}"`, { evidence: clip(l.trim()) });
    if ((m = concealMatch(l))) scan.add('AGT-INJ-003', file, ln, `asks the agent to act "${m[0]}"`, { evidence: clip(l.trim()) });
    if ((m = covertMatch(l))) scan.add('AGT-INJ-003', file, ln, `asks the agent to "${m[0]}"`, { evidence: clip(l.trim()) });
    if (DOWNLOAD_PIPE.test(l)) scan.add('AGT-INJ-004', file, ln, 'tells the agent to download and run a script', { evidence: clip(l.trim()), severity: 'medium' });
    if (RE_SENSITIVE.test(l) && RE_SEND.test(l) && RE_EXT_URL.test(l)) scan.add('AGT-INJ-004', file, ln, 'combines secrets or env data with sending to an external URL', { evidence: clip(l.trim()) });
  });
  // HTML comments aimed at the agent
  const re = /<!--([\s\S]*?)-->/g;
  let m;
  while ((m = re.exec(text))) {
    const body = m[1].trim();
    if (body.length < 30 || /^(prettier|markdownlint|eslint|toc|begin|end|start|omit|vale|cspell|textlint|lint)/i.test(body)) continue;
    const aimed = /\b(you|assistant|agent|AI|model|claude|copilot|cursor|gemini|codex|LLM)\b/i.test(body);
    const imperative = /\b(ignore|always|never|must|run|execute|send|upload|install|do\s*n[o']?t|delete|add|insert|read)\b/i.test(body);
    if (aimed && imperative) scan.add('AGT-INJ-005', file, lineAt(text, m.index), 'HTML comment with instructions for the agent (invisible when rendered)', { evidence: clip(body.replace(/\s+/g, ' ')) });
  }
}

// ─── MCP server source ───────────────────────────────────────────────────────

const MCP_MARKERS = /@modelcontextprotocol\/sdk|from\s+mcp(\.server[\w.]*)?\s+import|^\s*import\s+mcp\b|\bFastMCP\b|\bnew\s+McpServer\s*\(|\bMcpServer\s*\(|\bserver\.(tool|registerTool|setRequestHandler)\s*\(|\bmcp\.tool\s*\(|@mcp\.(tool|resource|prompt)\b|from\s+fastmcp\s+import/m;
const TOOL_REGISTRATION = /\b(?:server|mcp|app)\.(?:tool|registerTool|resource|prompt)\s*\(|@\w+\.(?:tool|resource|prompt)\b|\bregisterTool\s*\(|setRequestHandler\s*\(\s*CallToolRequestSchema/;
const FILE_ARG = /^\s*(?:args|params|input|arguments|request\.params(?:\.arguments)?|req\.body|payload|data|opts|options)\s*(?:\.|\[\s*['"])\s*(?:file_?path|filePath|path|filename|fileName|file|target|dir|directory|dest|destination|src|source|name)\b|^\s*(?:file_?path|filePath|filename|fileName|target_?path|targetPath|user_?path|relative_?path|dest_?path)\b/;
const URL_ARG = /^\s*(?:args|params|input|arguments|request\.params(?:\.arguments)?|req\.body|payload|data)\s*(?:\.|\[\s*['"])\s*(?:url|uri|href|link|endpoint|target|address)\b|^\s*(?:url|uri|target_?url|targetUrl|endpoint|link|href)\b\s*[,)]/i;

function callArgs(text, openIdx) {
  // returns the text inside the parentheses starting at openIdx (index of "("), max 600 chars
  let depth = 0;
  for (let i = openIdx; i < Math.min(text.length, openIdx + 600); i++) {
    const c = text[i];
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return text.slice(openIdx + 1, i); }
  }
  return text.slice(openIdx + 1, openIdx + 600);
}

function isCommentLine(line, py) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || (py && t.startsWith('#'));
}

/** Line numbers (1-based) that are comments, docstrings or inside block comments. */
function nonCodeLines(text, py) {
  const set = new Set();
  const lines = text.split('\n');
  const TRIPLE = py ? ['"'.repeat(3), "'".repeat(3)] : [];
  let inBlock = null;
  lines.forEach((l, i) => {
    const t = l.trim();
    if (inBlock) {
      set.add(i + 1);
      if (l.includes(inBlock)) inBlock = null;
      return;
    }
    if (py) {
      if (t.startsWith('#')) { set.add(i + 1); return; }
      const opener = TRIPLE.find((q) => new RegExp(`^[rbuRBU]{0,2}${q}`).test(t));
      if (opener) {
        set.add(i + 1);
        const rest = t.slice(t.indexOf(opener) + 3);
        if (!rest.includes(opener)) inBlock = opener;
        return;
      }
      const assigned = TRIPLE.find((q) => l.includes(q) && l.split(q).length === 2);
      if (assigned) inBlock = assigned;
    } else {
      if (t.startsWith('//') || t.startsWith('*')) { set.add(i + 1); return; }
      if (t.startsWith('/*')) { set.add(i + 1); if (!t.includes('*/')) inBlock = '*/'; }
    }
  });
  return set;
}

const TOOL_INPUT = /^\s*(?:args|params|input|arguments|request\.params(?:\.arguments)?)\s*(?:\.|\[|$|,)/;
const stripStrings = (l) => l.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');

function analyzeServerSource(scan, file, text, opts = {}) {
  scan.stats.serverSources++;
  const py = file.endsWith('.py');
  const lines = text.split('\n');
  const nonCode = nonCodeLines(text, py);
  // strict: the file registers no tools itself (it was included because its package depends on an
  // MCP SDK), so only explicit tool-input expressions (args.x, params.x, input.x) count as input.
  const strict = !opts.hasMarkers;
  const sample = /(^|\/)(examples?|docs?|samples?|demos?|tutorials?|guides?|cookbook)\//.test(file);
  const add = (rule, ln, msg, extra = {}) => scan.add(rule, file, ln, msg, sample ? { ...extra, severity: 'low' } : extra);
  const evidence = (ln) => clip((lines[ln - 1] || '').trim());
  const skipLine = (ln) => nonCode.has(ln) || isCommentLine(lines[ln - 1] || '', py);
  hiddenUnicodeChecks(scan, file, text);

  const containment = py
    ? /is_relative_to|commonpath|realpath[\s\S]{0,200}startswith|resolve\(\)[\s\S]{0,120}relative_to|safe_join|secure_filename|validate_path|allowed_dir/i
    : /startsWith\s*\(|path\.relative\s*\(|realpath|isPathInside|is-path-inside|isWithin|isSubPath|sanitize-filename|safeJoin|validatePath|allowedDirectories/;
  const ssrfGuard = /allowlist|allow_list|allowedHosts|allowed_hosts|ALLOWED_(HOSTS|DOMAINS)|isPrivate|is_private|private.?ip|169\.254|ipaddress\.ip_address|ssrf|blockedHosts|BLOCKED_|denylist|validate_url|validateUrl/i;

  // command injection
  const re = py
    ? /\b(subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|os\.(?:system|popen)|asyncio\.create_subprocess_shell)\s*\(/g
    : /\b((?:child_process\.|cp\.)?(?:exec|execSync)|execAsync|execPromise|promisify\(\s*exec\s*\)|spawn|spawnSync|execFile|execFileSync)\s*\(/g;
  let m;
  while ((m = re.exec(text))) {
    const ln = lineAt(text, m.index);
    if (skipLine(ln)) continue;
    if (!py && /\.$/.test(text.slice(Math.max(0, m.index - 1), m.index)) && /^(exec|execSync)$/.test(m[1])) continue; // regex.exec(), db.exec()
    const inside = callArgs(text, m.index + m[0].length - 1);
    const first = inside.split(/,(?![^()[\]{}`]*[)\]}`])/)[0] || '';
    let why = '';
    if (py) {
      if (/^\s*\[/.test(first)) continue; // argument list
      const shellTrue = /shell\s*=\s*True/.test(inside);
      const literal = /^\s*["'][^"'{}%]*["']\s*$/.test(first);
      const isShellCall = shellTrue || /^os\.(system|popen)$|create_subprocess_shell|getoutput|getstatusoutput/.test(m[1]);
      const fromInput = TOOL_INPUT.test(first) || /\{\s*(args|params|input|arguments)\b/.test(first);
      if (isShellCall && !literal && (!strict || fromInput)) why = shellTrue ? `${m[1]}(..., shell=True) with a dynamic command` : `${m[1]} with a dynamic command`;
    } else {
      const shellOpt = /shell\s*:\s*(true|['"`])/.test(inside);
      const interp = /^\s*`[^`]*\$\{/.test(first) || /^\s*(['"`][^'"`]*['"`]|\w+)\s*\+/.test(first) || /\+\s*\w/.test(first);
      const ident = (first.match(/^\s*([A-Za-z_$][\w$]*)\s*$/) || [])[1];
      const builtVar = ident && new RegExp(`\\b${ident}\\s*=\\s*(\`[^\`]*\\$\\{|[^;\\n]*\\+\\s*[A-Za-z_$(])`).test(text);
      if (/^(?:child_process\.|cp\.)?(exec|execSync)$|execAsync|execPromise|promisify/.test(m[1])) {
        if (interp && (!strict || /\$\{\s*(args|params|input|arguments)\b/.test(first))) why = `${m[1]} with an interpolated command string`;
        else if (builtVar && !strict) why = `${m[1]} with a command string built by interpolation (${ident})`;
        else if (TOOL_INPUT.test(first)) why = `${m[1]} with a command taken from tool input`;
      } else if (shellOpt && (!strict || TOOL_INPUT.test(first))) why = `${m[1]} with shell: true`;
    }
    if (why) add('MCP-SRV-001', ln, why, { evidence: evidence(ln) });
  }

  lines.forEach((l, i) => {
    const ln = i + 1;
    const docstring = py && nonCode.has(ln) && !l.trim().startsWith('#');
    const code = !nonCode.has(ln) && !isCommentLine(l, py);
    // tool poisoning: string literals and Python docstrings (FastMCP tool descriptions are docstrings)
    if ((code && /["'`]/.test(l)) || docstring || (!py && nonCode.size === 0)) {
      let mm;
      if ((mm = l.match(RE_TAG))) add('MCP-SRV-002', ln, `string contains ${mm[0]}`, { evidence: evidence(ln) });
      else if ((mm = l.match(RE_OVERRIDE)) || (mm = concealMatch(l))) add('MCP-SRV-002', ln, `string tells the model "${mm[0]}"`, { evidence: evidence(ln) });
      else if (/\b(before|first|also|always)\b[^.\n]{0,40}\b(read|cat|open|include|send|pass|attach)\b/i.test(l) && RE_SENSITIVE.test(l)) add('MCP-SRV-002', ln, 'string asks the model to read or pass sensitive files', { evidence: evidence(ln) });
    }
    if (!code) return;
    const bare = stripStrings(l);
    // dynamic code
    if (py) {
      const ev = bare.match(/(?<![.\w])(eval|exec)\s*\(/);
      if (ev && !/\bexec\s*\(\s*["'][^"']*["']\s*\)/.test(l)) add('MCP-SRV-005', ln, `${ev[1]}() on runtime data`, { evidence: evidence(ln) });
      if (/\b(pickle|cPickle|marshal|dill)\.loads?\s*\(/.test(bare)) add('MCP-SRV-005', ln, 'unpickling data', { evidence: evidence(ln) });
      if (/\byaml\.load\s*\(/.test(bare) && !/SafeLoader|CSafeLoader|BaseLoader|safe_load/.test(l)) add('MCP-SRV-005', ln, 'yaml.load without SafeLoader', { evidence: evidence(ln), severity: 'medium' });
    } else if (/(?<![.\w$])eval\s*\(/.test(bare) || /\bnew\s+Function\s*\(/.test(bare) || /\bvm\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(/.test(bare)) {
      add('MCP-SRV-005', ln, 'dynamic code evaluation', { evidence: evidence(ln) });
    }
    // network exposure
    if (/\.listen\s*\([^)]*['"]0\.0\.0\.0['"]|\bhost\s*[:=]\s*['"]0\.0\.0\.0['"]|--host[=\s]+0\.0\.0\.0|HOST\s*\|\|\s*['"]0\.0\.0\.0['"]/.test(l)
      && !/allowedHosts|allowed_hosts|TrustedHostMiddleware|allowedOrigins|allowed_origins|validateOrigin|enableDnsRebindingProtection|dns_rebinding/.test(text)) {
      add('MCP-SRV-006', ln, 'server binds 0.0.0.0', { evidence: evidence(ln) });
    }
    // token passthrough
    if (/[Aa]uthorization['"]?\s*[:=]\s*(?:req|request|ctx|context|extra|incoming)\w*\.(?:headers|authInfo|requestInfo)/.test(l)
      || /[Aa]uthorization['"]?\s*:\s*request\.headers\s*(\.get\(|\[)/.test(l)
      || /headers\s*=\s*\{[^}]*["']Authorization["']\s*:\s*request\.headers/.test(l)) {
      add('MCP-SRV-007', ln, "forwards the caller's Authorization header downstream", { evidence: evidence(ln) });
    }
  });

  // path traversal
  if (!containment.test(text)) {
    const fsRe = py
      ? /\b(open|Path|os\.remove|os\.unlink|shutil\.(?:rmtree|copy|copyfile|move)|os\.listdir|os\.scandir)\s*\(/g
      : /\b(?:fs\.|fsp\.|fs\.promises\.|promises\.)?(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|rmdir|copyFile|rename|stat|open)\s*\(/g;
    let f;
    let reported = 0;
    while ((f = fsRe.exec(text)) && reported < 3) {
      const ln = lineAt(text, f.index);
      if (skipLine(ln)) continue;
      if (!py && /[\w$]\.$/.test(text.slice(Math.max(0, f.index - 2), f.index)) && !/(fs|fsp|promises)\.$/.test(text.slice(Math.max(0, f.index - 12), f.index))) continue;
      if (py && /[\w$]\.$/.test(text.slice(Math.max(0, f.index - 2), f.index)) && f[1] === 'open') continue; // pdfplumber.open(), zipfile.open() …
      const first = (callArgs(text, f.index + f[0].length - 1).split(',')[0] || '');
      const viaJoin = first.match(/path\.(?:join|resolve)\s*\(([^)]*)\)|os\.path\.join\s*\(([^)]*)\)/);
      const candidate = viaJoin ? (viaJoin[1] || viaJoin[2] || '').split(',').pop() : first;
      const joined = viaJoin ? (viaJoin[1] || viaJoin[2] || '').split(',').slice(1).join(',') : '';
      const hit = strict ? (TOOL_INPUT.test(candidate) || TOOL_INPUT.test(joined)) : (FILE_ARG.test(candidate) || (viaJoin && FILE_ARG.test(joined)));
      if (hit) {
        add('MCP-SRV-003', ln, `${f[1]}() on a path from tool input, and the file has no containment check`, { evidence: evidence(ln) });
        reported++;
      }
    }
  }

  // SSRF
  if (!ssrfGuard.test(text)) {
    const netRe = py
      ? /\b(requests\.(?:get|post|put|request|head)|httpx\.(?:get|post|request|stream)|client\.(?:get|post)|session\.(?:get|post)|urllib\.request\.urlopen|urlopen|aiohttp\.request)\s*\(/g
      : /\b(fetch|axios(?:\.(?:get|post|request|put|head))?|got(?:\.(?:get|post))?|undici\.request|request|http\.get|https\.get|ky(?:\.(?:get|post))?)\s*\(/g;
    let n;
    let reported = 0;
    while ((n = netRe.exec(text)) && reported < 3) {
      const ln = lineAt(text, n.index);
      if (skipLine(ln)) continue;
      if (!py && /[\w$]\.$/.test(text.slice(Math.max(0, n.index - 2), n.index)) && !/^(axios|got|ky|undici|http|https)/.test(n[1])) continue;
      const first = callArgs(text, n.index + n[0].length - 1);
      const explicit = (TOOL_INPUT.test(first) && /^\s*[\w.[\]'"]*(url|uri|href|link|endpoint|target|address|host)/i.test(first))
        || /^\s*`[^`]*\$\{\s*(args|params|input)\.\w*(url|host|domain)/i.test(first);
      const loose = URL_ARG.test(first) || /^\s*f["'][^"']*\{\s*(url|host|domain|endpoint)\w*\s*\}/i.test(first);
      if (strict ? explicit : (explicit || loose)) {
        add('MCP-SRV-004', ln, `${n[1]}() on a URL from tool input, and the file has no host allowlist or private-IP check`, { evidence: evidence(ln) });
        reported++;
      }
    }
  }
}

// ─── orchestration ───────────────────────────────────────────────────────────

function findMcpRoots(root, files) {
  const roots = new Set();
  for (const rel of files) {
    const base = path.posix.basename(rel);
    if (!['package.json', 'pyproject.toml', 'requirements.txt', 'setup.py', 'setup.cfg'].includes(base)) continue;
    const text = readText(path.join(root, rel)) || '';
    const isMcp = base === 'package.json'
      ? /"@modelcontextprotocol\/sdk"|"fastmcp"|"mcp-framework"|"@mastra\/mcp"/.test(text)
      : /(^|["'\s,\[])(mcp|fastmcp)(\[[^\]]*\])?\s*([<>=~!]=|>|<|["',\]\n]|$)/m.test(text);
    if (isMcp) roots.add(path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel));
  }
  return [...roots];
}

function scanProject(rootArg, options = {}) {
  const root = path.resolve(rootArg || '.');
  const scan = createScan(options);
  const files = walk(root, options);
  const mcpRoots = findMcpRoots(root, files);
  const inMcpRoot = (rel) => mcpRoots.some((r) => r === '' || rel === r || rel.startsWith(`${r}/`));
  const secretFiles = files.filter((rel) => /(^|\/)\.env(\.[\w-]+)?$/.test(rel) && !/\.(example|sample|template|dist)$/.test(rel) || /\.(pem|key|p12|pfx)$/.test(rel) || /(^|\/)(id_rsa|id_ed25519|credentials\.json|service-account[\w-]*\.json)$/.test(rel));

  for (const rel of files) {
    const kinds = classify(rel);
    if (!kinds.length) continue;
    const needsText = kinds.some((k) => k !== 'source') || inMcpRoot(rel) || SOURCE_EXT.has(path.posix.extname(rel));
    if (!needsText) continue;
    const text = readText(path.join(root, rel));
    if (text === null) continue;
    if (kinds.includes('config')) analyzeConfig(scan, rel, text, /mcp/i.test(path.posix.basename(rel)));
    if (kinds.includes('codex')) analyzeCodex(scan, rel, text);
    if (kinds.includes('settings')) { analyzeSettings(scan, rel, text, { secretFiles }); analyzeConfig(scan, rel, text, false); }
    if (kinds.includes('instructions')) analyzeInstructions(scan, rel, text);
    if (kinds.includes('source')) {
      const hasMarkers = MCP_MARKERS.test(text);
      const toolingDir = /(^|\/)(scripts|\.github|bin|tools|hack|ci)\//.test(rel);
      const inherits = inMcpRoot(rel) && !toolingDir;
      if (!hasMarkers && !inherits) continue;
      if (toolingDir && !TOOL_REGISTRATION.test(text)) continue; // repo tooling that only mentions MCP
      if (/\.(test|spec)\.[cm]?[jt]s$|(^|\/)test_[^/]+\.py$|_test\.py$|(^|\/)conftest\.py$/.test(rel) && !options.includeTests) continue;
      analyzeServerSource(scan, rel, text, { hasMarkers });
    }
  }

  if (options.userConfig) {
    for (const [display, abs, kind] of userConfigPaths()) {
      const text = readText(abs);
      if (text === null) continue;
      if (kind === 'config') analyzeConfig(scan, display, text, /mcp/i.test(path.basename(abs)));
      if (kind === 'codex') analyzeCodex(scan, display, text);
      if (kind === 'settings') { analyzeSettings(scan, display, text, null); analyzeConfig(scan, display, text, false); }
      if (kind === 'instructions') analyzeInstructions(scan, display, text);
    }
  }

  const min = rank(options.minSeverity || 'info');
  const leads = scan.leads
    .filter((l) => rank(l.severity) >= min)
    .sort((a, b) => rank(b.severity) - rank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule));
  return { root, name: path.basename(root), stats: { ...scan.stats, files: files.length, mcpRoots: mcpRoots.length }, leads };
}

function toSarif(result) {
  const rules = Object.entries(RULES).map(([id, r]) => ({
    id,
    name: id.replace(/-/g, ''),
    shortDescription: { text: r.title },
    fullDescription: { text: r.message },
    help: { text: `${r.message}\n\nFix: ${r.fix}`, markdown: `${r.message}\n\n**Fix:** ${r.fix}` },
    helpUri: `https://github.com/MBotirjonDev/mcp-security-audit/blob/main/skills/mcp-security-audit/checks/${r.guide}`,
    properties: { tags: ['security', r.cwe].filter(Boolean), 'security-severity': { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' }[r.severity] },
    defaultConfiguration: { level: { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }[r.severity] },
  }));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'mcp-security-audit', version: VERSION, informationUri: 'https://github.com/MBotirjonDev/mcp-security-audit', rules } },
      results: result.leads.map((l) => ({
        ruleId: l.rule,
        level: { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }[l.severity],
        message: { text: `${l.message}${l.evidence ? ` (${l.evidence})` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: l.file.startsWith('~') || l.file.startsWith('%') ? l.file.replace(/^[~%][^/]*\//, 'USER_CONFIG/') : l.file }, region: { startLine: l.line } } }],
        properties: { severity: l.severity },
      })),
    }],
  };
}

function printReport(result, quiet) {
  const s = result.stats;
  const out = [];
  out.push(`mcp-security-audit · ${result.name} · ${s.configs} MCP configs (${s.servers} servers) · ${s.serverSources} MCP server source files · ${s.instructions} instruction files · ${s.settings} agent settings`);
  out.push('');
  if (!result.leads.length) {
    out.push('No leads. (Leads are hints for the agent skill; an empty list is not a security sign-off.)');
  } else if (!quiet) {
    for (const l of result.leads) {
      out.push(`${l.severity.toUpperCase().padEnd(8)} ${l.rule.padEnd(12)} ${l.message}${l.evidence ? `  [${l.evidence}]` : ''}`);
      out.push(`${' '.repeat(9)}${l.file}:${l.line}`);
    }
  }
  const counts = SEVERITIES.slice().reverse().map((sv) => `${sv}: ${result.leads.filter((l) => l.severity === sv).length}`).join('  ');
  if (result.leads.length) { out.push(''); out.push(`${result.leads.length} leads  (${counts})`); }
  return out.join('\n');
}

function parseArgs(argv) {
  const o = { path: '.', minSeverity: 'info' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === '--out') o.out = val();
    else if (a === '--sarif') o.sarif = val();
    else if (a === '--min-severity') o.minSeverity = val();
    else if (a === '--fail-on') o.failOn = val();
    else if (a === '--include-tests') o.includeTests = true;
    else if (a === '--user-config') o.userConfig = true;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--json') o.json = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '--version') o.version = true;
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else o.path = a;
  }
  for (const k of ['minSeverity', 'failOn']) if (o[k] && o[k] !== 'none' && !SEVERITIES.includes(o[k])) throw new Error(`--${k === 'minSeverity' ? 'min-severity' : 'fail-on'} must be one of ${SEVERITIES.join(', ')}${k === 'failOn' ? ', none' : ''}`);
  return o;
}

function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (o.version) { console.log(VERSION); return; }
  if (o.help) {
    console.log('Usage: node scan.cjs [path] [--out leads.json] [--sarif leads.sarif] [--min-severity info|low|medium|high|critical]\n                    [--fail-on <severity>|none] [--user-config] [--include-tests] [--quiet] [--json]\n\n  --user-config  also scan your global agent configs (~/.claude.json, ~/.cursor/mcp.json, Claude Desktop, Codex, Windsurf, Gemini)');
    return;
  }
  if (!fs.existsSync(o.path)) { console.error(`No such path: ${o.path}`); process.exit(2); }
  const result = scanProject(o.path, o);
  const doc = { tool: 'mcp-security-audit', version: VERSION, target: result.name, generated_at: new Date().toISOString(), stats: result.stats, leads: result.leads };
  if (o.out) fs.writeFileSync(o.out, `${JSON.stringify(doc, null, 2)}\n`);
  if (o.sarif) fs.writeFileSync(o.sarif, `${JSON.stringify(toSarif(result), null, 2)}\n`);
  if (o.json) console.log(JSON.stringify(doc, null, 2));
  else console.log(printReport(result, o.quiet));
  if (o.failOn && o.failOn !== 'none' && result.leads.some((l) => rank(l.severity) >= rank(o.failOn))) process.exit(1);
}

if (require.main === module) main();
module.exports = { scanProject, toSarif, printReport, parseJsonc, parseCodexToml, isPinned, findKnownSecret, VERSION };
