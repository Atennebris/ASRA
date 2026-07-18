# ASRA
Autonomous Security Research Agent - ASRA

## Test scope / Legal notice

This agent performs active scanning (Nmap, Nuclei), vulnerability probing, and — for the allowed
target only — real exploitation (Metasploit, sqlmap). To keep every run legal without standing up
a private lab, all test targets are **public applications that explicitly authorize security
testing**:

| Target | Role | Authorization |
|---|---|---|
| `juice-shop.herokuapp.com` | Recommended for the exploitation allowlist (see below) | OWASP Juice Shop — intentionally vulnerable app (SQLi/XSS/broken auth/IDOR, etc.) |
| `ginandjuice.shop` | Recon/Analyze demo variety | Official PortSwigger (Burp Suite) test target |
| `google-gruyere.appspot.com` | Recon/Analyze demo variety | Google — explicitly authorized attack target |
| `public-firing-range.appspot.com` | Recon/Analyze, XSS focus | Google — official automated-scanner test bed |

Rules that apply for all of the above:

- Recon/scan-category tools (Nmap, Nuclei, native recon tools) may run against any target submitted
  through the scan form, including all four above.
- **Real exploitation (Metasploit, sqlmap, `default_creds_check`) only ever runs against a target
  that you have explicitly added to the allowlist** in the app's `/settings` screen. That allowlist
  is stored in `data/allowed_targets.json` and is **empty by default** — exploitation is impossible
  until you add a target there yourself. It is never populated from the scan form, from `.env`, or by
  the LLM; enforced as a hard guardrail in the tool runner (`agent/tools/runner.py`), not just by
  convention or a prompt instruction. In addition, every individual exploitation attempt still
  requires a separate human-in-the-loop approval in the session UI before it runs.
- These are shared public targets used by many other people for the same purpose — the agent must
  not hammer them with unnecessary aggressive Nuclei templates or fuzzing; only what a given demo
  scenario actually needs.
- No other domain is in scope. The agent is not authorized to scan or exploit anything outside this
  table.
