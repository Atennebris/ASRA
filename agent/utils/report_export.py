"""Non-HTML proof-report export formats (txt/md/pdf/docx/zip) -- proof_report.html (Jinja,
main.py's export_proof route) stays exactly as it already worked and is untouched by this module.

Every other format is built from the SAME extraction pass (build_report_data below) so a recon
target's resolved-IP/known-hostname/OS-guess/technology lookup -- the same tolerant substring
matching session_fragment.html and proof_report.html both already do -- is written once here, not
once per format.
"""
from __future__ import annotations

import io
import os
import zipfile
from typing import Any

from agent.core import is_ungrounded_cve_lookup
from agent.utils.logger import get_logger

logger = get_logger("API")

EXPORT_FORMATS = ("html", "txt", "md", "pdf", "docx", "doc", "zip")


def _correction_note(f: dict) -> str | None:
    """Same "an earlier verdict was corrected" disclosure original_title already gets rendered
    with, extended to severity/qualification -- original_severity/original_qualifies_for_bounty are
    set by _apply_corrected_qualification (agent/core.py) whenever Exploit/Chain/skeptical
    verification's own re-check proves Analyze's first-guess severity/qualification no longer
    matches the evidence, but until now nothing in any exported report ever surfaced that a
    correction happened -- a finding that started Critical/qualifying and got corrected down to
    Low/non_qualifying (or the reverse) shipped showing only the final number, with no visible trace
    a human reviewer could use to tell the verdict had ever been anything else.
    """
    original_severity = f.get("original_severity")
    original_qualification = f.get("original_qualifies_for_bounty")
    if not original_severity and not original_qualification:
        return None
    parts = []
    if original_severity:
        parts.append(f'severity from "{original_severity}" to "{f.get("severity")}"')
    if original_qualification:
        parts.append(f'qualification from "{original_qualification}" to "{f.get("qualifies_for_bounty") or "unset"}"')
    return "Corrected " + " and ".join(parts) + " once further verification confirmed the real impact."


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _enrich_recon_target(t: dict, dns_map: dict, os_guesses: dict, technologies_by_host: dict) -> dict:
    host = t.get("host") or ""
    resolved_ips = dns_map.get(host) if host and not _is_ip(host) else None
    # record_target's own "host" is sometimes the literal IP itself (nmap's own output is
    # IP-based) -- same reverse lookup as session_fragment.html/proof_report.html.
    known_hostnames = [h for h, ips in dns_map.items() if host and _is_ip(host) and host in ips]
    os_guess = os_guesses.get(host)
    if not os_guess:
        for known_host, guess in os_guesses.items():
            if host and known_host and (host in known_host or known_host in host):
                os_guess = guess
                break
    technologies = technologies_by_host.get(host)
    if not technologies:
        for known_host, techs in technologies_by_host.items():
            if host and known_host and (host in known_host or known_host in host):
                technologies = techs
                break
    return {
        "host": host,
        "known_hostnames": known_hostnames,
        "resolved_ips": resolved_ips,
        "port": t.get("port"),
        "service": t.get("service"),
        "version": t.get("version"),
        "os_guess": os_guess,
        "technologies": technologies,
    }


def build_report_data(session: dict, generated_at: str) -> dict[str, Any]:
    """One extraction pass over `session`, reused by every render_* function below -- mirrors
    exactly what proof_report.html itself shows, so every export format tells the same story."""
    recon_result = session.get("recon_result") or {}
    dns_map = recon_result.get("dns_map") or {}
    os_guesses = recon_result.get("os_guesses") or {}
    technologies_by_host = recon_result.get("technologies") or {}
    recon_targets = [
        _enrich_recon_target(t, dns_map, os_guesses, technologies_by_host)
        for t in (recon_result.get("targets") or [])
    ]
    findings = session.get("findings") or []
    qualifying_hits = [
        f
        for f in findings
        if f.get("qualifies_for_bounty") == "qualifying" and f.get("verification") == "verified"
    ]
    # Real, tool-proven escalations (agent/core.py's _run_chain / record_chain_result) that turned
    # a finding which wouldn't get paid alone into something with demonstrated impact -- "no_chain_
    # found" attempts are deliberately excluded here, this section is proof, not a log of every
    # pass. Newest first, same ordering session_fragment.html's own Chain tab already uses.
    confirmed_chains = [a for a in (session.get("chain_attempts") or []) if a.get("outcome") == "chain_confirmed"][::-1]
    return {
        "target": session.get("target", ""),
        "session_id": session.get("session_id", ""),
        "generated_at": generated_at,
        "qualifying_hits": qualifying_hits,
        "confirmed_chains": confirmed_chains,
        "recon_targets": recon_targets,
        "recon_cves": recon_result.get("cves") or [],
        "findings": findings,
        "approvals": session.get("approvals") or [],
    }


def _recon_target_line(t: dict) -> str:
    line = t["host"]
    if t["known_hostnames"]:
        line += f" ({', '.join(t['known_hostnames'])})"
    if t["resolved_ips"]:
        line += f" ({', '.join(t['resolved_ips'])})"
    if t["os_guess"]:
        line += f" — {t['os_guess']}"
    return line


def _chain_heading(chain: dict) -> str:
    hop_tag = f" (hop {chain['hop']})" if chain.get("hop") and chain["hop"] > 1 else ""
    return " → ".join(chain.get("finding_titles") or []) + hop_tag


def render_txt(data: dict) -> str:
    lines: list[str] = ["ASRA PROOF REPORT", "=" * 60]
    lines += [f"Target: {data['target']}", f"Session: {data['session_id']}", f"Generated: {data['generated_at']}", ""]

    if data["qualifying_hits"]:
        lines.append(f"QUALIFYING FINDINGS -- VERIFIED & READY TO REPORT ({len(data['qualifying_hits'])})")
        lines.append("-" * 60)
        lines += [f"- {f.get('title')} ({f.get('severity')})" for f in data["qualifying_hits"]]
        lines.append("")

    if data["confirmed_chains"]:
        lines.append(f"ATTACK CHAINS -- DEMONSTRATED IMPACT ({len(data['confirmed_chains'])})")
        lines.append("-" * 60)
        for i, c in enumerate(data["confirmed_chains"], 1):
            lines.append(f"[{i}] {_chain_heading(c)}")
            if c.get("impact_scenario"):
                lines.append(f"    IMPACT: {c['impact_scenario']}")
            if c.get("reasoning"):
                lines.append(f"    {c['reasoning']}")
            if c.get("evidence_quotes"):
                lines.append("    Evidence quoted:")
                lines += [f"      - {q}" for q in c["evidence_quotes"]]
            if c.get("tool_call_proof"):
                lines.append("    Tool-call proof:")
                lines += [f"      {ln}" for ln in c["tool_call_proof"].splitlines()]
            lines.append("")
        lines.append("")

    if data["recon_targets"] or data["recon_cves"]:
        lines.append("RECON / ASSET INFO")
        lines.append("-" * 60)
        for t in data["recon_targets"]:
            lines.append(f"  {_recon_target_line(t)}")
            port = t["port"] if t["port"] is not None else "-"
            techs = ", ".join(t["technologies"]) if t["technologies"] else "-"
            lines.append(f"    Port: {port}  Service: {t['service'] or '-'}  Version: {t['version'] or '-'}  Tech: {techs}")
        if data["recon_cves"]:
            lines.append(f"  CVEs: {', '.join(data['recon_cves'])}")
        lines.append("")

    lines.append(f"FINDINGS ({len(data['findings'])})")
    lines.append("-" * 60)
    for i, f in enumerate(data["findings"], 1):
        tag = f" -- {f.get('qualifies_for_bounty')}" if f.get("qualifies_for_bounty") else ""
        lines.append(f"[{i}] {f.get('title')} -- {f.get('severity')}{tag}")
        if f.get("original_title"):
            lines.append(f'    (Originally reported as "{f["original_title"]}" -- corrected once exploitation confirmed the real target.)')
        correction_note = _correction_note(f)
        if correction_note:
            lines.append(f"    ({correction_note})")
        if f.get("description"):
            lines.append(f"    {f['description']}")
        lines.append(f"    Verification: {f.get('verification')}    Exploited: {f.get('exploited')}")
        if f.get("exploited") and (f.get("extracted_artifact") or f.get("artifact_usage_hint")):
            lines.append(f"    EXPLOITED -- ACCESS CONFIRMED: {f.get('extracted_artifact', '')} {f.get('artifact_usage_hint', '')}".rstrip())
        elif not f.get("exploited") and f.get("advisory_note"):
            lines.append(f"    Not exploitable: {f['advisory_note']}")
        if f.get("false_positive_reason"):
            lines.append(f"    Likely false positive: {f['false_positive_reason']}")
        elif is_ungrounded_cve_lookup(f):
            lines.append("    No confirmed target: matched by product name only -- no host in this scan's Recon results was ever confirmed running that product.")
        for label, key in (("Reproduction steps", "reproduction_steps"), ("PoC command", "poc_command"), ("Evidence", "evidence")):
            if f.get(key):
                lines.append(f"    {label}:")
                lines += [f"      {ln}" for ln in f[key].splitlines()]
        lines.append("")

    if data["approvals"]:
        lines.append("EXPLOIT APPROVALS")
        lines.append("-" * 60)
        lines += [f"- {a.get('finding_title')} -- {a.get('outcome')} -- {a.get('at')}" for a in data["approvals"]]
        lines.append("")

    return "\n".join(lines)


def render_md(data: dict) -> str:
    lines: list[str] = ["# ASRA Proof Report", ""]
    lines += [
        f"**Target:** {data['target']}  ",
        f"**Session:** {data['session_id']}  ",
        f"**Generated:** {data['generated_at']}",
        "",
    ]

    if data["qualifying_hits"]:
        lines.append(f"## \U0001f3af Qualifying findings — verified & ready to report ({len(data['qualifying_hits'])})")
        lines.append("")
        lines += [f"- **{f.get('title')}** ({f.get('severity')})" for f in data["qualifying_hits"]]
        lines.append("")

    if data["confirmed_chains"]:
        lines.append(f"## ☣ Attack chains — demonstrated impact ({len(data['confirmed_chains'])})")
        lines.append("")
        for i, c in enumerate(data["confirmed_chains"], 1):
            lines.append(f"### {i}. {_chain_heading(c)}")
            lines.append("")
            if c.get("impact_scenario"):
                lines.append(f"> **Impact:** {c['impact_scenario']}")
                lines.append("")
            if c.get("reasoning"):
                lines.append(c["reasoning"])
                lines.append("")
            if c.get("evidence_quotes"):
                lines.append("**Evidence quoted**")
                lines += [f"- {q}" for q in c["evidence_quotes"]]
                lines.append("")
            if c.get("tool_call_proof"):
                lines.append("**Tool-call proof**")
                lines.append("```")
                lines.append(c["tool_call_proof"])
                lines.append("```")
                lines.append("")

    if data["recon_targets"] or data["recon_cves"]:
        lines.append("## Recon / Asset Info")
        lines.append("")
        if data["recon_targets"]:
            lines.append("| Host | Port | Service | Version | Technologies |")
            lines.append("|---|---|---|---|---|")
            for t in data["recon_targets"]:
                port = t["port"] if t["port"] is not None else "—"
                techs = ", ".join(t["technologies"]) if t["technologies"] else "—"
                lines.append(f"| {_recon_target_line(t)} | {port} | {t['service'] or '—'} | {t['version'] or '—'} | {techs} |")
            lines.append("")
        if data["recon_cves"]:
            lines.append("CVEs: " + ", ".join(f"`{c}`" for c in data["recon_cves"]))
            lines.append("")

    lines.append(f"## Findings ({len(data['findings'])})")
    lines.append("")
    for i, f in enumerate(data["findings"], 1):
        tag = f" `{f.get('qualifies_for_bounty')}`" if f.get("qualifies_for_bounty") else ""
        lines.append(f"### {i}. {f.get('title')} — {f.get('severity')}{tag}")
        lines.append("")
        if f.get("original_title"):
            lines.append(f'*Originally reported as "{f["original_title"]}" — corrected once exploitation confirmed the real target.*')
            lines.append("")
        correction_note = _correction_note(f)
        if correction_note:
            lines.append(f"*{correction_note}*")
            lines.append("")
        if f.get("description"):
            lines.append(f["description"])
            lines.append("")
        lines.append(f"- **Verification:** {f.get('verification')}")
        lines.append(f"- **Exploited:** {f.get('exploited')}")
        lines.append("")
        if f.get("exploited") and (f.get("extracted_artifact") or f.get("artifact_usage_hint")):
            lines.append(f"> **Exploited — access confirmed.** {f.get('artifact_usage_hint', '')}".rstrip())
            if f.get("extracted_artifact"):
                lines.append(f"> `{f['extracted_artifact']}`")
            lines.append("")
        elif not f.get("exploited") and f.get("advisory_note"):
            lines.append(f"> **Not exploitable:** {f['advisory_note']}")
            lines.append("")
        if f.get("false_positive_reason"):
            lines.append(f"> ⊘ **Likely false positive:** {f['false_positive_reason']}")
            lines.append("")
        elif is_ungrounded_cve_lookup(f):
            lines.append("> ⊘ **No confirmed target:** matched by product name only — no host in this scan's Recon results was ever confirmed running that product.")
            lines.append("")
        for label, key in (("Reproduction steps", "reproduction_steps"), ("PoC command", "poc_command"), ("Evidence", "evidence")):
            if f.get(key):
                lines.append(f"**{label}**")
                lines.append("```")
                lines.append(f[key])
                lines.append("```")
                lines.append("")

    if data["approvals"]:
        lines.append("## Exploit approvals")
        lines.append("")
        lines += [f"- {a.get('finding_title')} — {a.get('outcome')} — {a.get('at')}" for a in data["approvals"]]
        lines.append("")

    return "\n".join(lines)


# Unicode font for the PDF export -- fpdf2's built-in core fonts (helvetica/courier) only cover
# Latin-1, and finding text (custom_instructions, evidence captured from a real target) is not
# guaranteed to stay inside that range. DejaVu Sans is a common Linux distro package
# (fonts-dejavu-core, already present on this project's own dev machine) rather than something
# bundled in this repo -- same "optional {TOOL}_PATH override, graceful degrade if missing"
# convention as NMAP_PATH/HTTPX_PATH, not a hard dependency: render_pdf falls back to the core
# Latin-1 font (logged once at debug level) instead of failing the whole export.
_DEFAULT_PDF_FONT_DIR = "/usr/share/fonts/truetype/dejavu"
_PDF_FONT_REGULAR_PATH = os.getenv("PDF_FONT_REGULAR_PATH") or f"{_DEFAULT_PDF_FONT_DIR}/DejaVuSans.ttf"
_PDF_FONT_BOLD_PATH = os.getenv("PDF_FONT_BOLD_PATH") or f"{_DEFAULT_PDF_FONT_DIR}/DejaVuSans-Bold.ttf"


def _register_pdf_font(pdf) -> str:
    if os.path.exists(_PDF_FONT_REGULAR_PATH):
        pdf.add_font("Report", "", _PDF_FONT_REGULAR_PATH)
        bold_path = _PDF_FONT_BOLD_PATH if os.path.exists(_PDF_FONT_BOLD_PATH) else _PDF_FONT_REGULAR_PATH
        pdf.add_font("Report", "B", bold_path)
        return "Report"
    logger.debug(
        "PDF export: Unicode font not found at %s (set PDF_FONT_REGULAR_PATH to override) -- "
        "falling back to the core Latin-1 font, non-Latin1 characters may not render correctly",
        _PDF_FONT_REGULAR_PATH,
    )
    return "helvetica"


def render_pdf(data: dict) -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    family = _register_pdf_font(pdf)
    pdf.add_page()

    # fpdf2's own multi_cell() default (new_x=XPos.RIGHT) leaves the cursor at the RIGHT edge of
    # whatever it just drew -- fine for a single cell, but the next w=0 ("full remaining width")
    # call then measures its available width from THAT x, which is already at the right margin,
    # leaving ~0px and raising "Not enough horizontal space to render a single character" on its
    # very first character. Confirmed live: exactly this, on the second line ever written ("Target:
    # ..."), right after the title. Every line in this report is meant to start a fresh line at the
    # left margin, so new_x/new_y are pinned here once instead of repeating them on every call.
    def line(h: float, text: str) -> None:
        pdf.multi_cell(0, h, text, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font(family, "B", 18)
    line(10, "ASRA Proof Report")
    pdf.set_font(family, "", 10)
    line(6, f"Target: {data['target']}")
    line(6, f"Session: {data['session_id']}")
    line(6, f"Generated: {data['generated_at']}")
    pdf.ln(4)

    if data["qualifying_hits"]:
        pdf.set_font(family, "B", 13)
        line(8, f"Qualifying findings -- verified & ready to report ({len(data['qualifying_hits'])})")
        pdf.set_font(family, "", 10)
        for f in data["qualifying_hits"]:
            line(6, f"- {f.get('title')} ({f.get('severity')})")
        pdf.ln(4)

    if data["confirmed_chains"]:
        pdf.set_font(family, "B", 13)
        line(8, f"Attack chains -- demonstrated impact ({len(data['confirmed_chains'])})")
        for i, c in enumerate(data["confirmed_chains"], 1):
            pdf.set_font(family, "B", 10)
            line(6, f"{i}. {_chain_heading(c)}")
            pdf.set_font(family, "", 9)
            if c.get("impact_scenario"):
                pdf.set_font(family, "B", 9)
                line(5, "Impact:")
                pdf.set_font(family, "", 9)
                line(5, c["impact_scenario"])
            if c.get("reasoning"):
                line(5, c["reasoning"])
            for q in c.get("evidence_quotes") or []:
                line(5, f"- {q}")
            if c.get("tool_call_proof"):
                pdf.set_font(family, "", 8)
                line(4.5, c["tool_call_proof"])
            pdf.ln(2)
        pdf.ln(2)

    if data["recon_targets"]:
        pdf.set_font(family, "B", 13)
        line(8, "Recon / Asset Info")
        pdf.set_font(family, "", 8)
        with pdf.table(col_widths=(38, 10, 15, 17, 20), text_align="LEFT") as table:
            header = table.row()
            for label in ("Host", "Port", "Service", "Version", "Technologies"):
                header.cell(label)
            for t in data["recon_targets"]:
                row = table.row()
                row.cell(_recon_target_line(t))
                row.cell(str(t["port"]) if t["port"] is not None else "-")
                row.cell(t["service"] or "-")
                row.cell(t["version"] or "-")
                row.cell(", ".join(t["technologies"]) if t["technologies"] else "-")
        if data["recon_cves"]:
            pdf.set_font(family, "", 9)
            line(6, "CVEs: " + ", ".join(data["recon_cves"]))
        pdf.ln(4)

    pdf.set_font(family, "B", 13)
    line(8, f"Findings ({len(data['findings'])})")
    for i, f in enumerate(data["findings"], 1):
        pdf.set_font(family, "B", 11)
        tag = f" [{f.get('qualifies_for_bounty')}]" if f.get("qualifies_for_bounty") else ""
        line(7, f"{i}. {f.get('title')} -- {f.get('severity')}{tag}")
        pdf.set_font(family, "", 9)
        if f.get("original_title"):
            line(5, f'Originally reported as "{f["original_title"]}" -- corrected once exploitation confirmed the real target.')
        correction_note = _correction_note(f)
        if correction_note:
            line(5, correction_note)
        if f.get("description"):
            line(5, f["description"])
        line(5, f"Verification: {f.get('verification')}    Exploited: {f.get('exploited')}")
        if f.get("exploited") and (f.get("extracted_artifact") or f.get("artifact_usage_hint")):
            line(5, f"EXPLOITED -- ACCESS CONFIRMED: {f.get('extracted_artifact', '')} {f.get('artifact_usage_hint', '')}".strip())
        elif not f.get("exploited") and f.get("advisory_note"):
            line(5, f"Not exploitable: {f['advisory_note']}")
        if f.get("false_positive_reason"):
            line(5, f"Likely false positive: {f['false_positive_reason']}")
        elif is_ungrounded_cve_lookup(f):
            line(5, "No confirmed target: matched by product name only.")
        for label, key in (("Reproduction steps", "reproduction_steps"), ("PoC command", "poc_command"), ("Evidence", "evidence")):
            if f.get(key):
                pdf.set_font(family, "B", 9)
                line(5, label)
                pdf.set_font(family, "", 8)
                line(4.5, f[key])
        pdf.ln(3)

    if data["approvals"]:
        pdf.set_font(family, "B", 13)
        line(8, "Exploit approvals")
        pdf.set_font(family, "", 9)
        for a in data["approvals"]:
            line(5, f"{a.get('finding_title')} -- {a.get('outcome')} -- {a.get('at')}")

    return bytes(pdf.output())


def _rtf_escape(text: str) -> str:
    """RTF control-word escaping for one already-final chunk of plain text: backslash/brace escapes
    plus a real \\uN? Unicode escape (RTF's own mechanism, RFC-documented as part of the format
    itself) for anything outside 7-bit ASCII -- Cyrillic domains/evidence text included, now that
    the New Project form accepts them. N is the code point as a SIGNED 16-bit value (RTF's own
    requirement: >= 0x8000 must be represented as N - 0x10000, negative), followed by a plain '?'
    fallback glyph for a reader that can't render the escape. Characters outside the Basic
    Multilingual Plane (rare in a pentest report -- astral-plane emoji, not real target text)
    degrade to a bare '?' rather than the more involved surrogate-pair form RTF would otherwise
    need -- an acceptable loss for something this unlikely, not worth the extra complexity.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "{":
            out.append("\\{")
        elif ch == "}":
            out.append("\\}")
        elif ch == "\n":
            out.append("\\par\n")
        elif ch == "\r":
            continue
        elif code < 0x80:
            out.append(ch)
        elif code <= 0xFFFF:
            signed = code if code < 0x8000 else code - 0x10000
            out.append(f"\\u{signed}?")
        else:
            out.append("?")
    return "".join(out)


def render_doc(data: dict) -> bytes:
    """The legacy "Word 97-2003" .doc format, alongside modern .docx -- the operator explicitly
    asked for both, with a sub-choice between them on export.

    No pure-Python library actually WRITES the old binary OLE/CFB-based .doc format (a few can
    read it, writing is a different story) without either real MS Word via COM automation
    (Windows-only, and this server runs on Linux/WSL2) or shelling out to LibreOffice -- neither is
    available or a reasonable dependency to add here. RTF is the honest, practical substitute: it's
    Microsoft's own plain-text-based format, every version of Word from the 1990s onward opens it
    correctly regardless of what the FILE'S OWN EXTENSION says (Word sniffs the real `{\\rtf1`
    signature at the start of the file, not the extension) -- serving RTF content with a `.doc`
    filename is a long-established, legitimate technique many real "Export to Word" features use,
    not a broken or fake file.
    """
    lines: list[str] = ["{\\rtf1\\ansi\\ansicpg1252\\deff0\\deflang1033", "{\\fonttbl{\\f0\\fswiss Helvetica;}}", "\\f0\\fs22"]

    def heading(text: str, size: int) -> None:
        lines.append(f"\\b\\fs{size} {_rtf_escape(text)}\\b0\\fs22\\par")

    def para(text: str) -> None:
        lines.append(f"{_rtf_escape(text)}\\par")

    heading("ASRA Proof Report", 36)
    para(f"Target: {data['target']}")
    para(f"Session: {data['session_id']}")
    para(f"Generated: {data['generated_at']}")
    lines.append("\\par")

    if data["qualifying_hits"]:
        heading(f"Qualifying findings -- verified & ready to report ({len(data['qualifying_hits'])})", 28)
        for f in data["qualifying_hits"]:
            para(f"\\bullet  {f.get('title')} ({f.get('severity')})")
        lines.append("\\par")

    if data["confirmed_chains"]:
        heading(f"Attack chains -- demonstrated impact ({len(data['confirmed_chains'])})", 28)
        for i, c in enumerate(data["confirmed_chains"], 1):
            heading(f"{i}. {_chain_heading(c)}", 22)
            if c.get("impact_scenario"):
                para(f"Impact: {c['impact_scenario']}")
            if c.get("reasoning"):
                para(c["reasoning"])
            for q in c.get("evidence_quotes") or []:
                para(f"\\bullet  {q}")
            if c.get("tool_call_proof"):
                para("Tool-call proof:")
                for ln in c["tool_call_proof"].splitlines():
                    para("    " + ln)
        lines.append("\\par")

    if data["recon_targets"]:
        heading("Recon / Asset Info", 28)
        for t in data["recon_targets"]:
            port = t["port"] if t["port"] is not None else "-"
            techs = ", ".join(t["technologies"]) if t["technologies"] else "-"
            para(f"{_recon_target_line(t)} -- Port {port}, Service {t['service'] or '-'}, Version {t['version'] or '-'}, Tech {techs}")
        if data["recon_cves"]:
            para("CVEs: " + ", ".join(data["recon_cves"]))
        lines.append("\\par")

    heading(f"Findings ({len(data['findings'])})", 28)
    for i, f in enumerate(data["findings"], 1):
        tag = f" [{f.get('qualifies_for_bounty')}]" if f.get("qualifies_for_bounty") else ""
        heading(f"{i}. {f.get('title')} -- {f.get('severity')}{tag}", 24)
        if f.get("original_title"):
            para(f'Originally reported as "{f["original_title"]}" -- corrected once exploitation confirmed the real target.')
        correction_note = _correction_note(f)
        if correction_note:
            para(correction_note)
        if f.get("description"):
            para(f["description"])
        para(f"Verification: {f.get('verification')}    Exploited: {f.get('exploited')}")
        if f.get("exploited") and (f.get("extracted_artifact") or f.get("artifact_usage_hint")):
            para(f"EXPLOITED -- ACCESS CONFIRMED: {f.get('extracted_artifact', '')} {f.get('artifact_usage_hint', '')}".strip())
        elif not f.get("exploited") and f.get("advisory_note"):
            para(f"Not exploitable: {f['advisory_note']}")
        if f.get("false_positive_reason"):
            para(f"Likely false positive: {f['false_positive_reason']}")
        elif is_ungrounded_cve_lookup(f):
            para("No confirmed target: matched by product name only.")
        for label, key in (("Reproduction steps", "reproduction_steps"), ("PoC command", "poc_command"), ("Evidence", "evidence")):
            if f.get(key):
                para(label + ":")
                for ln in f[key].splitlines():
                    para("    " + ln)
        lines.append("\\par")

    if data["approvals"]:
        heading("Exploit approvals", 28)
        for a in data["approvals"]:
            para(f"{a.get('finding_title')} -- {a.get('outcome')} -- {a.get('at')}")

    lines.append("}")
    # Every piece of real text above already went through _rtf_escape, which only ever emits plain
    # 7-bit-ASCII control words/escapes -- errors="replace" is a pure safety net, not something
    # expected to ever actually trigger.
    return "\n".join(lines).encode("ascii", errors="replace")


def render_docx(data: dict) -> bytes:
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    doc.add_heading("ASRA Proof Report", level=1)
    doc.add_paragraph(f"Target: {data['target']}")
    doc.add_paragraph(f"Session: {data['session_id']}")
    doc.add_paragraph(f"Generated: {data['generated_at']}")

    if data["qualifying_hits"]:
        doc.add_heading(f"Qualifying findings — verified & ready to report ({len(data['qualifying_hits'])})", level=2)
        for f in data["qualifying_hits"]:
            doc.add_paragraph(f"{f.get('title')} ({f.get('severity')})", style="List Bullet")

    if data["confirmed_chains"]:
        doc.add_heading(f"Attack chains — demonstrated impact ({len(data['confirmed_chains'])})", level=2)
        for i, c in enumerate(data["confirmed_chains"], 1):
            doc.add_heading(f"{i}. {_chain_heading(c)}", level=3)
            if c.get("impact_scenario"):
                p = doc.add_paragraph()
                p.add_run("Impact: ").bold = True
                p.add_run(c["impact_scenario"])
            if c.get("reasoning"):
                doc.add_paragraph(c["reasoning"])
            for q in c.get("evidence_quotes") or []:
                doc.add_paragraph(q, style="List Bullet")
            if c.get("tool_call_proof"):
                doc.add_paragraph().add_run("Tool-call proof").bold = True
                pre = doc.add_paragraph(c["tool_call_proof"])
                for run in pre.runs:
                    run.font.name = "Consolas"
                    run.font.size = Pt(9)

    if data["recon_targets"]:
        doc.add_heading("Recon / Asset Info", level=2)
        table = doc.add_table(rows=1, cols=5)
        table.style = "Light Grid Accent 1"
        header_cells = table.rows[0].cells
        for i, label in enumerate(("Host", "Port", "Service", "Version", "Technologies")):
            header_cells[i].text = label
        for t in data["recon_targets"]:
            row_cells = table.add_row().cells
            row_cells[0].text = _recon_target_line(t)
            row_cells[1].text = str(t["port"]) if t["port"] is not None else "-"
            row_cells[2].text = t["service"] or "-"
            row_cells[3].text = t["version"] or "-"
            row_cells[4].text = ", ".join(t["technologies"]) if t["technologies"] else "-"
        if data["recon_cves"]:
            doc.add_paragraph("CVEs: " + ", ".join(data["recon_cves"]))

    doc.add_heading(f"Findings ({len(data['findings'])})", level=2)
    for i, f in enumerate(data["findings"], 1):
        tag = f" [{f.get('qualifies_for_bounty')}]" if f.get("qualifies_for_bounty") else ""
        doc.add_heading(f"{i}. {f.get('title')} — {f.get('severity')}{tag}", level=3)
        if f.get("original_title"):
            p = doc.add_paragraph()
            p.add_run(f'Originally reported as "{f["original_title"]}" — corrected once exploitation confirmed the real target.').italic = True
        correction_note = _correction_note(f)
        if correction_note:
            p = doc.add_paragraph()
            p.add_run(correction_note).italic = True
        if f.get("description"):
            doc.add_paragraph(f["description"])
        doc.add_paragraph(f"Verification: {f.get('verification')}    Exploited: {f.get('exploited')}")
        if f.get("exploited") and (f.get("extracted_artifact") or f.get("artifact_usage_hint")):
            p = doc.add_paragraph()
            p.add_run(f"Exploited — access confirmed. {f.get('extracted_artifact', '')} {f.get('artifact_usage_hint', '')}".strip()).bold = True
        elif not f.get("exploited") and f.get("advisory_note"):
            doc.add_paragraph(f"Not exploitable: {f['advisory_note']}")
        if f.get("false_positive_reason"):
            doc.add_paragraph(f"Likely false positive: {f['false_positive_reason']}")
        elif is_ungrounded_cve_lookup(f):
            doc.add_paragraph("No confirmed target: matched by product name only.")
        for label, key in (("Reproduction steps", "reproduction_steps"), ("PoC command", "poc_command"), ("Evidence", "evidence")):
            if f.get(key):
                doc.add_paragraph().add_run(label).bold = True
                pre = doc.add_paragraph(f[key])
                for run in pre.runs:
                    run.font.name = "Consolas"
                    run.font.size = Pt(9)

    if data["approvals"]:
        doc.add_heading("Exploit approvals", level=2)
        for a in data["approvals"]:
            doc.add_paragraph(f"{a.get('finding_title')} — {a.get('outcome')} — {a.get('at')}", style="List Bullet")

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def render_zip(data: dict, html_content: str) -> bytes:
    """All formats bundled together -- labeled both by the archive's own filename
    (main.py's export_proof appends "-all-formats") and by a README inside, so opening it makes
    immediately clear this is every format at once, not one file that happens to be zipped."""
    session_id = data["session_id"]
    files = {
        f"asra-proof-{session_id}.html": html_content.encode("utf-8"),
        f"asra-proof-{session_id}.txt": render_txt(data).encode("utf-8"),
        f"asra-proof-{session_id}.md": render_md(data).encode("utf-8"),
        f"asra-proof-{session_id}.pdf": render_pdf(data),
        f"asra-proof-{session_id}.docx": render_docx(data),
        f"asra-proof-{session_id}.doc": render_doc(data),
    }
    readme = (
        "ASRA Proof Report -- all formats bundled together\n"
        "==================================================\n\n"
        f"Target: {data['target']}\n"
        f"Session: {session_id}\n"
        f"Generated: {data['generated_at']}\n\n"
        "This archive contains the SAME proof report in every export format ASRA offers, so you\n"
        "can pick whichever your recipient needs without re-exporting:\n\n"
        + "\n".join(f"  - {name}" for name in files)
        + "\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", readme)
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()
