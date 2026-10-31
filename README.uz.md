# MCP Security Audit 🇺🇿

**AI agentingiz boshqalarning kodini ishga tushiradi va boshqalarning promptlarini o'qiydi. Qaysilari xavfli ekanini oldindan biling.**

Bu agent skill va unga qo'shimcha nol-bog'liqlikli skaner. U MCP serverlar, MCP konfiguratsiyalar,
agent qoidalar fayllari (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `SKILL.md`) va agent ruxsatlarini
xavfsizlik nuqtai nazaridan tekshiradi. Claude Code, Cursor, Codex, VS Code, Windsurf, Gemini CLI
va Claude Desktop bilan ishlaydi.

[English README](README.md)

## Nimalarni topadi

- MCP config ichida ochiq yozilgan **tokenlar** (GitHub, Anthropic, OpenAI, AWS va boshqalar)
- versiyasi qotirilmagan serverlar: `npx -y paket` har ishga tushganda eng yangi versiyani oladi
- **zaharlangan tool tavsiflari**: modelga `~/.ssh/id_rsa` ni o'qishni yoki foydalanuvchidan yashirishni buyuradigan matnlar
- qoidalar fayllariga **ko'rinmas Unicode** bilan yashirilgan buyruqlar (skaner ularni ochib ko'rsatadi)
- CVE-2025-6514 zaifligi bor `mcp-remote` versiyalari
- `bypassPermissions`, `Bash(*)` va `curl | bash` qiladigan hook'lar
- o'zingiz yozayotgan MCP serverda: command injection, path traversal, SSRF, `eval`, token passthrough

## Tez boshlash

```bash
npx skills add https://github.com/MBotirjonDev/mcp-security-audit --skill mcp-security-audit --global
```

So'ng agentga yozing:

```
audit the MCP and agent security of this repo
```

Faqat skaner (Node 18+, internet va o'rnatish shart emas):

```bash
node skills/mcp-security-audit/scripts/scan.cjs path/to/project
node skills/mcp-security-audit/scripts/scan.cjs . --user-config   # kompyuteringizdagi global configlar
```

Skaner faqat fayllarni o'qiydi: tarmoqqa chiqmaydi, buyruq ishga tushirmaydi, MCP serverlarni
ishga tushirmaydi. Topilgan tokenlar har doim yashirilgan (masked) holda chiqadi.

MIT litsenziyasi.
