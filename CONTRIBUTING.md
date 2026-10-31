# Contributing

Every agent-security mistake you have seen in the wild is a rule someone else needs.

## Add a rule (≈20 minutes)

1. **Open an issue** with the *New rule* template: the vulnerable config/code/text, the safe
   version, and what an attacker gains.
2. Add the rule's metadata to `skills/mcp-security-audit/scripts/rules.cjs`
   (`MCP-CFG-NNN`, `MCP-SRV-NNN`, `AGT-INJ-NNN`, `AGT-PERM-NNN`).
3. Add the detection in `scripts/scan.cjs` (`analyzeServer`, `analyzeServerSource`,
   `analyzeInstructions` or `analyzeSettings`).
4. Add a positive case to `tests/fixtures/vuln_project/` and keep `tests/fixtures/clean_project/`
   clean; add a focused test in `tests/scan.test.cjs` for tricky negatives.
5. Add or extend the section in `checks/*.md` (the `guide` anchor must exist; tests check it).
6. Add the rule to the table in `README.md` (tests check this too).
7. `npm test`: all green, no new dependencies.

Please run your rule on a few real MCP repositories and report the false-positive count in the PR.

## Ground rules

- Zero runtime dependencies. Node ≥ 18 standard library only.
- The scanner never makes network calls, never runs commands, never starts MCP servers.
- Secrets are masked in every output. Token-shaped strings and invisible characters in tests
  are **generated at runtime**, never committed.
- The skill's own files must pass its own rules (`the skill does not flag itself` test).
- Rules produce **leads**; wording says "review" / "may".
- Found a vulnerability *in this project*? See [SECURITY.md](SECURITY.md).
- Be kind in reviews. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
