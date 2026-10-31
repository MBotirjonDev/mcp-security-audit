#!/usr/bin/env node
'use strict';
/**
 * Checks the tool definitions an MCP server actually serves (zero dependencies).
 *
 *   node check-tools.cjs <tools.json> [--pin pins.json] [--update-pins]
 *                                     [--out report.json] [--fail-on high] [--quiet]
 *
 * <tools.json> is the result of a tools/list call, in any of these shapes:
 *   { "tools": [...] }   { "result": { "tools": [...] } }   [ ... ]
 *
 * Get it without connecting this script to anything, e.g. with the official inspector:
 *   npx @modelcontextprotocol/inspector --cli <server command> --method tools/list > tools.json
 *
 * --pin records a SHA-256 of every tool definition the first time, and on later runs
 * reports tools whose definition changed (a "rug pull") or that appeared or disappeared.
 *
 * This script only reads the JSON files you give it. It makes no network calls.
 */
const fs = require('fs');
const crypto = require('crypto');

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

const HIDDEN = /<\/?(?:IMPORTANT|important|SYSTEM|system-prompt|instructions?)>|\b(?:do not|don't|never) (?:tell|mention|inform|reveal|show)(?: (?:this|it|that|anything))?(?: to)? the user\b|\bignore (?:all |any )?(?:previous|prior|above|other) (?:instructions|rules|tools)\b|\bbefore (?:using|calling) (?:this|any other) tool,? (?:you )?(?:must |should )?(?:first )?(?:read|call|send|pass)\b|~\/\.ssh\b|\bid_rsa\b|\.aws\/credentials\b|\.env\b|mcp\.json\b|claude_desktop_config\b/i;
const INVISIBLE = /[\u200B-\u200D\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/;
const SHADOW = /\b(?:instead of|rather than|whenever you use|when (?:using|calling) the|all (?:other )?tools|every other tool|other servers?)\b/i;
const LINK = /https?:\/\/[^\s"')]+|\b[\w.+-]+@[\w-]+\.[\w.]+\b/;
const EXFIL_PARAM = /^(?:side_?note|context|conversation|chat_?history|history|notes?|metadata|debug(?:_info)?|feedback|summary|previous_messages|memory)$/i;

function loadTools(doc) {
  const list = Array.isArray(doc) ? doc : (doc && (doc.tools || (doc.result && doc.result.tools)));
  if (!Array.isArray(list)) throw new Error('No tools array found (expected { tools: [...] }, { result: { tools: [...] } } or [...])');
  return list.filter((t) => t && typeof t.name === 'string');
}

// Every human-readable string inside a tool definition, with where it came from.
function texts(tool) {
  const out = [];
  const walk = (v, where) => {
    if (typeof v === 'string') out.push({ where, text: v });
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${where}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, where ? `${where}.${k}` : k);
  };
  walk(tool, '');
  return out;
}

function paramNames(tool) {
  const schema = tool.inputSchema || tool.input_schema || {};
  return Object.keys(schema.properties || {});
}

function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
const digest = (tool) => crypto.createHash('sha256').update(canonical(tool)).digest('hex');

const show = (s) => s
  .replace(/[\u200B-\u200D\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/g,
    (ch) => `<U+${ch.codePointAt(0).toString(16).toUpperCase()}>`)
  .replace(/\s+/g, ' ').trim().slice(0, 180);

function check(tools, opts = {}) {
  const issues = [];
  const add = (severity, rule, tool, title, detail, where) => issues.push({ rule, severity_hint: severity, tool, title, where, detail });
  const names = tools.map((t) => t.name);

  for (const tool of tools) {
    for (const { where, text } of texts(tool)) {
      const field = where || 'name';
      if (INVISIBLE.test(text)) add('high', 'TOOL-INVISIBLE', tool.name, 'Invisible or bidi Unicode characters', show(text), field);
      const m = text.match(HIDDEN);
      if (m && field !== 'name') add('high', 'TOOL-HIDDEN', tool.name, 'Instruction aimed at the model, not a description', `…${show(text.slice(Math.max(0, m.index - 60), m.index + 100))}…`, field);
      if (field !== 'name' && SHADOW.test(text)) add('medium', 'TOOL-SHADOW', tool.name, 'Description tries to change how other tools are used', show(text), field);
      const others = names.filter((n) => n !== tool.name && n.length > 3 && new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(text));
      if (field !== 'name' && others.length) add('medium', 'TOOL-CROSSREF', tool.name, `Description mentions other tools (${others.join(', ')})`, show(text), field);
      if (field !== 'name' && LINK.test(text)) add('low', 'TOOL-LINK', tool.name, 'URL or e-mail address in a description', show(text), field);
    }
    const desc = typeof tool.description === 'string' ? tool.description : '';
    if (desc.length > 1000) add('low', 'TOOL-LONG', tool.name, `Unusually long description (${desc.length} chars)`, show(desc), 'description');
    for (const p of paramNames(tool)) {
      if (EXFIL_PARAM.test(p)) add('medium', 'TOOL-EXFIL-PARAM', tool.name, `Parameter "${p}" invites the model to pass conversation or file content`, 'Check that the tool needs it and what the server does with it.', `inputSchema.properties.${p}`);
    }
  }

  const pins = { changed: [], added: [], removed: [] };
  if (opts.pins) {
    const current = Object.fromEntries(tools.map((t) => [t.name, digest(t)]));
    for (const [name, hash] of Object.entries(current)) {
      if (!(name in opts.pins)) { pins.added.push(name); add('info', 'PIN-ADDED', name, 'New tool since the pinned snapshot', 'Review it before approving.', ''); }
      else if (opts.pins[name] !== hash) { pins.changed.push(name); add('high', 'PIN-CHANGED', name, 'Tool definition changed since it was pinned (possible rug pull)', `pinned ${opts.pins[name].slice(0, 12)}…, now ${hash.slice(0, 12)}…`, ''); }
    }
    for (const name of Object.keys(opts.pins)) if (!(name in current)) { pins.removed.push(name); add('info', 'PIN-REMOVED', name, 'Tool removed since the pinned snapshot', '', ''); }
  }

  issues.sort((a, b) => SEVERITIES.indexOf(b.severity_hint) - SEVERITIES.indexOf(a.severity_hint) || a.tool.localeCompare(b.tool));
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const i of issues) counts[i.severity_hint]++;
  return { tool: 'mcp-security-audit/check-tools', tools_checked: tools.length, counts, pins: opts.pins ? pins : undefined, issues };
}

function main() {
  const argv = process.argv.slice(2);
  const args = { file: null, pin: null, update: false, out: null, failOn: null, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--pin') args.pin = argv[++i];
    else if (a === '--update-pins') args.update = true;
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--quiet') args.quiet = true;
    else if (!args.file) args.file = a;
  }
  if (!args.file) { console.error('Usage: node check-tools.cjs <tools.json> [--pin pins.json] [--update-pins] [--out report.json] [--fail-on <severity>] [--quiet]'); process.exit(2); }
  if (args.failOn && !SEVERITIES.includes(args.failOn)) { console.error(`--fail-on must be one of ${SEVERITIES.join(', ')}`); process.exit(2); }

  let tools;
  try { tools = loadTools(JSON.parse(fs.readFileSync(args.file, 'utf8'))); } catch (e) { console.error(`${args.file}: ${e.message}`); process.exit(2); }

  let pins = null;
  if (args.pin && fs.existsSync(args.pin) && !args.update) pins = JSON.parse(fs.readFileSync(args.pin, 'utf8')).tools || {};
  const result = check(tools, { pins });
  if (args.pin && (args.update || !fs.existsSync(args.pin))) {
    fs.writeFileSync(args.pin, JSON.stringify({ pinned_at: new Date().toISOString(), tools: Object.fromEntries(tools.map((t) => [t.name, digest(t)])) }, null, 2) + '\n');
    if (!args.quiet) console.log(`pinned ${tools.length} tool definitions to ${args.pin}`);
  }
  if (args.out) fs.writeFileSync(args.out, JSON.stringify(result, null, 2) + '\n');
  if (!args.quiet) {
    console.log(`\nmcp-security-audit · check-tools · ${result.tools_checked} tools\n`);
    if (!result.issues.length) console.log('No issues in the served tool definitions.\n');
    for (const i of result.issues) {
      console.log(`${i.severity_hint.toUpperCase().padEnd(8)} ${i.rule.padEnd(17)} ${i.tool}: ${i.title}`);
      if (i.where) console.log(`         at ${i.where}`);
      if (i.detail) console.log(`         ${i.detail}`);
    }
    if (result.issues.length) console.log(`\n${result.issues.length} issues. Read each flagged text yourself before trusting the server.\n`);
  }
  if (args.failOn && result.issues.some((i) => SEVERITIES.indexOf(i.severity_hint) >= SEVERITIES.indexOf(args.failOn))) process.exit(1);
}

if (require.main === module) main();
module.exports = { check, loadTools, digest, canonical };
