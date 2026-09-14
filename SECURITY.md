# Security Policy

ASRA is an autonomous pentesting agent — it drives real security tools (Nmap, Nuclei, Metasploit,
sqlmap, Hydra, etc.) and can actively exploit targets. That makes two different kinds of "security"
relevant to this project, and it's important to keep them separate:

1. **Vulnerabilities in ASRA itself** — bugs in this codebase that could compromise the machine
   running ASRA, leak stored secrets, or let ASRA be tricked into acting outside its intended scope.
   This is what this policy covers.
2. **ASRA's own scanning/exploitation capability** — the fact that ASRA can run Nmap, Nuclei,
   Metasploit, or sqlmap against a target, or brute-force a login with Hydra, is intended behavior,
   not a vulnerability to report. Misuse of that capability against a target you don't have
   authorization to test is covered by the [README's Disclaimer / Test scope & Legal notice
   sections](README.md#disclaimer), not by this file.

## Intended use

ASRA is built for **authorized security testing only** — engagements, bug bounty programs, CTFs,
and labs where you have explicit written permission to test the target. See
[README.md#test-scope--legal-notice](README.md#test-scope--legal-notice) for the current allowlist
mechanism and approved demo targets. Running ASRA against a target you are not authorized to test
is the user's responsibility, not a defect in the software — see the
[Disclaimer](README.md#disclaimer).

## Supported versions

ASRA does not yet publish tagged releases — it's developed on `main`. Security fixes are only
provided for the latest commit on `main`. If you're running an older checkout, update before
relying on a fix.

## Reporting a vulnerability

If you find a security issue in ASRA itself (not "the agent can be pointed at a target" — see
above), please report it privately rather than opening a public issue:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this repository (preferred —
  keeps the report private until a fix ships), or
- Contact the maintainer directly rather than filing a public issue if a private advisory isn't an
  option for you.

Please include: what you found, the affected file(s)/endpoint(s), steps to reproduce, and the
potential impact. There's no formal SLA given this is a small, actively-developed project, but
reports are triaged as soon as they're seen and a fix or mitigation is prioritized over new
features.

Please don't:
- Open a public GitHub issue for a vulnerability before it's been triaged and fixed.
- Test any finding against a real, non-consenting third party — ASRA's own approved demo targets
  (see README) or a local instance are enough to demonstrate an issue in the software itself.

## What counts as a vulnerability here

In scope — issues in ASRA's own code:

- **Allowlist/scope bypass** — anything that lets Recon-only or non-exploit tools run destructive
  actions, or lets exploitation fire against a target not present in `data/allowed_targets.json`
  (enforced in `agent/tools/runner.py`). This is ASRA's core safety guarantee; treat any bypass as
  high severity.
- **Approval-gate bypass** — a way to make an exploit attempt run without the required UI approval
  click when `EXPLOIT_REQUIRE_APPROVAL=true` is set.
- **Command/argument injection** in any tool builder (`agent/tools/builders/*.py`) or the tool
  runner — e.g. a crafted target/finding value that lets shell metacharacters escape into an
  `nmap`/`sqlmap`/`nuclei` invocation.
- **Secret handling bugs** — ASRA stores API keys, an optional plaintext sudo password
  (Settings → Optional interpreters/compilers), OAuth tokens (Codex/Copilot), and per-project
  identity credentials (`data/credentials/`) on disk. A bug that leaks these into logs, the browser
  UI, error responses, or the LLM's own context (beyond what's strictly needed for a tool call) is
  in scope.
- **Path traversal / arbitrary file read-write** — in project/session file handling
  (`projects/paths.py`, `sessions/store.py`), the wordlist catalog's "download from URL" feature, or
  the proof-report exporter.
- **SSRF in the web UI/backend itself** — as distinct from OOB/SSRF *detection* tooling
  (`oob_generate`, `interactsh-client` integration), which is intended functionality.
- **Auth/access-control gaps in the local web server** — e.g. a way to reach an authenticated-only
  route without the desktop shell's per-launch token, or an unauthenticated action that should
  require it.
- **Dependency vulnerabilities** with a real exploitation path in ASRA's own usage (a CVE in a
  pinned `requirements.txt`/`Cargo.toml` package that ASRA actually invokes in a vulnerable way).

Out of scope — intended behavior, not bugs:

- ASRA (or a tool it drives) successfully scanning, fingerprinting, brute-forcing, or exploiting a
  target — that's the product working as designed, gated by the allowlist above.
- The LLM producing an incorrect finding, a false positive/negative, or a suboptimal decision — a
  quality issue, not a security one (open a normal GitHub issue for those).
- Resource usage (CPU/bandwidth/disk) from a scan you configured and authorized yourself.
- Vulnerabilities in third-party tools ASRA shells out to (Nmap, Metasploit, sqlmap, ...) — report
  those upstream to the tool's own project.

## Data ASRA stores locally — know what's on disk

ASRA is local-only by design (no cloud, no database — see the README), but that means sensitive
data lives on your own filesystem instead. Almost none of it lives inside the git checkout itself —
know the real locations before assuming a repo-only cleanup (`git clean`, deleting the checkout) got
everything:

- **`.env`** (repo root) — LLM provider API keys, and optionally a plaintext WSL sudo password if
  you saved one in Settings for the nmap `-O` flag. This one genuinely lives in the checkout.
- **`Documents/ASRA/data/credentials/`** (or your `APP_DATA_DIR`) — per-project
  authenticated-identity credentials entered on the New Project form (e.g. login creds for an
  authenticated scan).
- **`Documents/ASRA/data/oob_sessions/`** — a fresh RSA private key per out-of-band (blind
  SSRF/XSS) session.
- **`Documents/ASRA/data/allowed_targets.json`** — the exploitation allowlist itself; not secret in
  the credential sense, but the definitive record of every target this install has ever been
  authorized to exploit.
- **`Documents/ASRA/data/codex_oauth_tokens.json` / `data/copilot_oauth_tokens.json`** — OAuth
  tokens for optional Codex/Copilot integrations.
- **Per-project folders** under `Documents/ASRA Projects/` (or your `PROJECTS_DIR`) — real scan
  findings, evidence, and `debug.log`, which can include target-identifying data and raw tool
  output from a real engagement.
- **The global app log** (`Documents/ASRA/debug.log`, or `APP_DATA_DIR`) — activity not tied to one
  project.

The repo's own `data/` folder (gitignored, `.gitkeep`'d so the directory layout survives a fresh
clone) is not where any of the above actually end up — everything above resolves through
`projects/paths.py`'s `resolve_global_app_dir()`/`resolve_projects_base_dir()` into your real OS
"Documents" folder instead (see the README's Configuration section for the `PROJECTS_DIR`/
`APP_DATA_DIR` overrides, and its Uninstalling section for exactly what to delete and where).

If you're filing a bug report or sharing logs for troubleshooting, scrub API keys, credentials, and
any real (non-demo) target details first.

## Security-relevant design already in place

Worth knowing before assuming something is a gap:

- **Allowlist-gated exploitation** — real exploitation tools only ever run against a target present
  in `data/allowed_targets.json`, populated only by an explicit per-project authorization, never by
  `.env` or the LLM itself (`agent/tools/runner.py`).
- **Optional human-in-the-loop approval** — `EXPLOIT_REQUIRE_APPROVAL=true` pauses each individual
  exploit attempt for a UI approval click; off by default (autonomous), but every attempt is logged
  either way in the audit trail Export Proof relies on.
- **Empirical brute-force preflight** — `hydra_start`/`web_login_bruteforce_start` test for an
  actual lockout/CAPTCHA/rate-limit signal before committing to a full run, rather than blindly
  hammering a defended login.
- **Desktop-shell session token** — in Desktop mode, the UI is locked to the shell window via a
  per-launch token so a stray browser tab can't reach that backend.
- **Wordlist "download from URL"** is a human-only action (no `ToolSpec`) — the agent itself cannot
  trigger an arbitrary download.

## Keeping dependencies current

`requirements.txt` (Python) and `desktop/src-tauri/Cargo.toml` (Rust, desktop shell only) pin
versions. If you notice a pinned dependency with a known CVE relevant to how ASRA actually uses it,
please report it the same way as above.
