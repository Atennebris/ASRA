"""build_command() and output parser for trufflehog -- secrets scanning over a source tree,
INCLUDING git commit history when the target is a git repo (a leaked credential removed in a later
commit is still a real, live secret sitting in history -- semgrep/a plain file-tree scan never sees
it, only a real git-aware scan does). Attempts live verification by default (trufflehog's own core
feature -- e.g. an AWS key match gets a real check against AWS's own API) so a real, confirmed-live
credential is distinguished from a pattern match that merely looks like one; this makes real,
if small, outbound requests to whichever third-party service a detected credential belongs to, not
just local pattern matching."""
from __future__ import annotations

import json
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value


def build_trufflehog_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["path"]).strip())
    # A git-cloned target (agent/tools/builders/re_target.py's own clone_or_stage_re_target) has a
    # real .git directory -- scan its FULL history, not just the current working tree, since that's
    # exactly where an already-removed-but-still-leaked secret would otherwise hide. A plain local
    # folder with no .git (an uploaded archive, a bare source dump) falls back to a filesystem scan.
    if (Path(target) / ".git").is_dir():
        return ["trufflehog", "git", f"file://{target}", "--json"]
    return ["trufflehog", "filesystem", target, "--json"]


def parse_trufflehog_output(stdout: str) -> dict:
    """trufflehog's own --json prints one JSON object per line (JSONL), not one big document --
    each line is parsed independently, a malformed/partial line is skipped rather than failing the
    whole parse."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        detector = entry.get("DetectorName")
        if not detector:
            continue
        findings.append({
            "detector": detector,
            "verified": entry.get("Verified"),
            "raw_secret_preview": (entry.get("Raw") or "")[:80],
            "file": (entry.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {}).get("file")
                    or (entry.get("SourceMetadata") or {}).get("Data", {}).get("Git", {}).get("file"),
            "commit": (entry.get("SourceMetadata") or {}).get("Data", {}).get("Git", {}).get("commit"),
        })
    return {"findings": findings}
