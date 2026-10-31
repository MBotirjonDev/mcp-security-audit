# MCP and agent security audit: {{project}}

| | |
|---|---|
| Commit | `{{commit}}` |
| Date | {{date}} |
| Scope | {{repository / machine / single server}} |
| Clients | {{Claude Code, Cursor, VS Code, Claude Desktop, Codex …}} |
| Method | mcp-security-audit skill: map → scan → hunt → adversarial validation |

## Summary

| Critical | High | Medium | Low | Needs validation |
|---:|---:|---:|---:|---:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

{{3–5 sentences: what the agent can reach, the most serious path in plain words, what to fix first.}}

## MCP servers

| Server | Defined in | Transport | Package / image | Pinned | Credentials | Verdict |
|---|---|---|---|:---:|---|---|
| `{{name}}` | `{{file}}` | stdio / http | `{{pkg@version}}` | ✅ / ❌ | {{env names, scopes}} | {{ok / F-n}} |

## Confirmed findings

### F-1 · {{title}} (**{{Severity}}**)

**Where:** `{{file}}:{{line}}`

**Attacker:** {{who, and what they control: a package maintainer, a PR author, a web page the agent reads, a network position}}

**Attack path**
1. {{step}}
2. {{step}}
3. {{impact}}

**Fix**
```{{lang}}
{{exact change}}
```

---

## Needs validation

| ID | Title | What to run or check |
|---|---|---|
| F-n | {{title}} | `{{command}}` |

## Hardening notes

- {{pin versions, deny rules for secrets, separate agents for untrusted content, …}}

_Generated with [MCP Security Audit](https://github.com/MBotirjonDev/mcp-security-audit). Automated audits miss things; review new servers and rules files before you trust them._
