"""Bundled JS -> original source reconstruction via Source Map v3 decoding (hand-rolled Base64 VLQ
decoder below -- no new dependency: the algorithm is small, stable, and well-specified, and this
project's own existing JS-handling code already prefers a self-contained regex/stdlib approach
over pulling in a parser library for one tool -- see native.py's _html_to_readable_text docstring
("regex-based... rather than pulling in a new dependency... for one tool"), the same reasoning
applied here). Recovers each ORIGINAL source file's real content from a bundle's own sourcemap
(commonly embedded via the map's own `sourcesContent` field) -- exactly where a real secret or an
unminified API route is far more likely to be readable than in the minified bundle text itself,
the same observation native.py's own js_bundle_scan already acts on for ITS OWN secret-pattern
scan. This module's job is reconstruction (what original files existed, what they actually
contained), not scanning -- js_bundle_scan already owns secret/endpoint pattern matching and isn't
duplicated here; run both against the same bundle for full coverage.

Structural extraction per reconstructed file (imports/exports/function/class declarations) is
regex-based, not a full JS AST parse -- deliberately: a real JS AST parser is a nontrivial new
dependency (ASI, regex-vs-division ambiguity, template literals, ... -- genuinely not a small
addition), and this session's own standing rule requires asking before installing anything new.
This gives a fast, dependency-free structural overview -- real, useful coverage, not full
precision -- and is honestly described as such rather than oversold as "AST parsing."

Live-verified against a REAL webpack 5 bundle+sourcemap (3 ES-module source files, built with the
already-installed `webpack` CLI, `--devtool source-map`) -- not a hand-typed toy case.
"""
from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_MAX_BUNDLE_BYTES = int(os.getenv("JS_BUNDLE_GRAPH_MAX_BYTES", str(10_000_000)))
# Real ceiling on how many reconstructed source files get their own structural breakdown in the
# result -- a large bundle (webpack's own runtime boilerplate alone is several files) can list
# dozens of sources; an honest total count survives even when the per-file detail is capped, same
# pattern agent/tools/builders/radare2.py's own _MAX_LIST_ENTRIES already uses.
_MAX_SOURCES_DETAILED = 50
# Per-file original source text is capped before being handed back -- a single reconstructed file
# can itself be large (a whole vendored library bundled as "one source"); this is a preview, not a
# full dump, same spirit as every other capped text field in this project.
_MAX_SOURCE_CHARS = 4000

_SOURCE_MAPPING_URL_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)\s*$", re.MULTILINE)
_DATA_URI_RE = re.compile(r"^data:application/json(?:;charset=[\w-]+)?;base64,(.+)$", re.DOTALL)

_BASE64_VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_VLQ_LOOKUP = {c: i for i, c in enumerate(_BASE64_VLQ_CHARS)}
_VLQ_CONTINUATION_BIT = 0x20
_VLQ_BASE_MASK = 0x1F
_VLQ_SHIFT = 5


def _decode_vlq_segment(segment: str) -> list[int]:
    """One VLQ segment (comma-separated field group) -> its decoded signed integers. Base64 VLQ
    per the Source Map v3 spec: each base64 digit carries 5 data bits + 1 continuation bit; the
    least-significant bit of the final (reassembled) value is a sign flag, not part of the
    magnitude."""
    values: list[int] = []
    shift = 0
    value = 0
    for char in segment:
        digit = _BASE64_VLQ_LOOKUP[char]
        continuation = digit & _VLQ_CONTINUATION_BIT
        digit &= _VLQ_BASE_MASK
        value += digit << shift
        if continuation:
            shift += _VLQ_SHIFT
        else:
            negate = value & 1
            value >>= 1
            values.append(-value if negate else value)
            value = 0
            shift = 0
    return values


def decode_source_map_mappings(mappings: str) -> list[dict]:
    """The map's own `mappings` string -> a flat list of decoded entries, one per VLQ segment.
    Every field (generated column, source index, original line/column, name index) is DELTA-
    encoded relative to the previous value of that same field across the WHOLE mappings string
    (generated column alone resets to 0 at each new generated line, i.e. each ';'-separated
    group) -- this function carries those running totals itself, per the spec, rather than
    leaving delta decoding to the caller.
    """
    entries: list[dict] = []
    generated_line = 0
    source_index = 0
    original_line = 0
    original_column = 0
    name_index = 0
    for line in mappings.split(";"):
        generated_column = 0
        if line:
            for segment in line.split(","):
                if not segment:
                    continue
                fields = _decode_vlq_segment(segment)
                if not fields:
                    continue
                generated_column += fields[0]
                entry = {"generated_line": generated_line, "generated_column": generated_column}
                if len(fields) >= 4:
                    source_index += fields[1]
                    original_line += fields[2]
                    original_column += fields[3]
                    entry["source_index"] = source_index
                    entry["original_line"] = original_line
                    entry["original_column"] = original_column
                if len(fields) >= 5:
                    name_index += fields[4]
                    entry["name_index"] = name_index
                entries.append(entry)
        generated_line += 1
    return entries


# Top-level (not nested, so a REGEX can approximate it reasonably -- see module docstring on why
# this isn't a real AST walk) declaration shapes worth surfacing per reconstructed source file.
# Deliberately a small, high-precision set rather than attempting full expression-level coverage.
_IMPORT_RE = re.compile(r'^\s*import\s+(?:[\w*${},\s]+\s+from\s+)?["\']([^"\']+)["\']', re.MULTILINE)
_REQUIRE_RE = re.compile(r'\brequire\(\s*["\']([^"\']+)["\']\s*\)')
_EXPORT_NAMED_RE = re.compile(r'^\s*export\s+(?:default\s+)?(?:async\s+)?(function|class|const|let|var)\s+([A-Za-z_$][\w$]*)', re.MULTILINE)
_FUNCTION_DECL_RE = re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)\s*\(', re.MULTILINE)
_CLASS_DECL_RE = re.compile(r'^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)', re.MULTILINE)


def _extract_structure(source_text: str) -> dict:
    imports = sorted(set(_IMPORT_RE.findall(source_text)) | set(_REQUIRE_RE.findall(source_text)))
    exports = sorted({name for _, name in _EXPORT_NAMED_RE.findall(source_text)})
    functions = sorted(set(_FUNCTION_DECL_RE.findall(source_text)))
    classes = sorted(set(_CLASS_DECL_RE.findall(source_text)))
    return {"imports": imports, "exports": exports, "functions": functions, "classes": classes}


def _load_source_map(bundle_text: str, bundle_path: Path, map_path_param: str | None) -> tuple[dict | None, str]:
    """Resolution order: an explicit map_path param -> a sibling "<bundle>.map" file on disk ->
    an inline `//# sourceMappingURL=data:application/json;base64,...` comment in the bundle
    itself. Returns (parsed map dict or None, a human-readable note on how/whether one was found)."""
    if map_path_param:
        map_path = Path(validate_safe_value(map_path_param))
        if not map_path.is_file():
            return None, f"map_path {map_path_param!r} does not exist"
        try:
            return json.loads(map_path.read_text(encoding="utf-8", errors="replace")), f"loaded from explicit map_path ({map_path})"
        except (json.JSONDecodeError, OSError) as exc:
            return None, f"map_path {map_path_param!r} could not be parsed as JSON: {exc}"

    sibling = bundle_path.with_suffix(bundle_path.suffix + ".map")
    if sibling.is_file():
        try:
            return json.loads(sibling.read_text(encoding="utf-8", errors="replace")), f"loaded from sibling file ({sibling.name})"
        except (json.JSONDecodeError, OSError) as exc:
            return None, f"sibling map file {sibling.name!r} could not be parsed as JSON: {exc}"

    inline_match = _SOURCE_MAPPING_URL_RE.search(bundle_text)
    if inline_match:
        url = inline_match.group(1)
        data_match = _DATA_URI_RE.match(url)
        if data_match:
            try:
                decoded = base64.b64decode(data_match.group(1))
                return json.loads(decoded), "loaded from an inline base64 data: URI sourceMappingURL comment"
            except Exception as exc:
                return None, f"found an inline sourceMappingURL comment but could not decode/parse it: {exc}"
        return None, f"found a sourceMappingURL comment pointing at {url!r} (an external file, not inline) -- not fetched here; pass it explicitly as map_path if you have it locally"

    return None, "no sourcemap found (no map_path given, no sibling .map file, no inline sourceMappingURL comment in the bundle)"


def run_js_bundle_graph(params: dict) -> dict:
    bundle_path_raw = validate_safe_value(str(params.get("bundle_path") or "").strip())
    if not bundle_path_raw:
        raise ValueError("run_js_bundle_graph requires a 'bundle_path' parameter (path to a local JS bundle file).")
    bundle_path = Path(bundle_path_raw)
    if bundle_path.is_dir():
        raise ValueError(f"bundle_path is a directory, not a file: {bundle_path_raw!r}")
    if not bundle_path.is_file():
        raise ValueError(f"bundle_path does not exist: {bundle_path_raw!r}")

    try:
        bundle_bytes = bundle_path.read_bytes()[:_MAX_BUNDLE_BYTES]
    except OSError as exc:
        return {"status": "error", "tool": "js_bundle_graph", "error": f"could not read {bundle_path_raw!r}: {exc}"}
    bundle_truncated = bundle_path.stat().st_size > _MAX_BUNDLE_BYTES
    bundle_text = bundle_bytes.decode("utf-8", errors="replace")

    source_map, map_note = _load_source_map(bundle_text, bundle_path, params.get("map_path"))
    logger.debug("js_bundle_graph: bundle=%s bundle_bytes=%d sourcemap=%s", bundle_path, len(bundle_bytes), map_note)

    if source_map is None:
        return {
            "status": "ok",
            "tool": "js_bundle_graph",
            **evidence_result(
                {"bundle_path": str(bundle_path), "bundle_bytes": len(bundle_bytes), "bundle_truncated": bundle_truncated},
                unknown={"sources": map_note},
            ),
        }

    raw_sources = source_map.get("sources") or []
    sources_content = source_map.get("sourcesContent") or []
    mappings_raw = source_map.get("mappings") or ""
    decoded_entries = decode_source_map_mappings(mappings_raw) if mappings_raw else []

    reconstructed: list[dict] = []
    unknown: dict[str, str] = {}
    for i, source_name in enumerate(raw_sources):
        if i >= _MAX_SOURCES_DETAILED:
            continue
        content = sources_content[i] if i < len(sources_content) and sources_content[i] is not None else None
        entry: dict = {"source": source_name, "content_available": content is not None}
        if content is not None:
            entry["content_preview"] = content[:_MAX_SOURCE_CHARS]
            entry["content_truncated"] = len(content) > _MAX_SOURCE_CHARS
            entry["structure"] = _extract_structure(content)
        reconstructed.append(entry)
    if len(raw_sources) > _MAX_SOURCES_DETAILED:
        unknown["sources_beyond_limit"] = f"{len(raw_sources) - _MAX_SOURCES_DETAILED} more source(s) listed in the map but not detailed here (cap of {_MAX_SOURCES_DETAILED})"
    if not sources_content:
        unknown["sources_content"] = "the sourcemap has no sourcesContent field at all -- original file CONTENT can't be recovered, only the source file names/paths and the generated<->original line/column mapping"

    observed = {
        "bundle_path": str(bundle_path),
        "bundle_bytes": len(bundle_bytes),
        "bundle_truncated": bundle_truncated,
        "sourcemap_note": map_note,
        "total_sources": len(raw_sources),
        "total_mapping_entries": len(decoded_entries),
        "sources": reconstructed,
    }
    logger.debug("js_bundle_graph: reconstructed %d/%d source(s), %d mapping entries", len(reconstructed), len(raw_sources), len(decoded_entries))
    return {"status": "ok", "tool": "js_bundle_graph", **evidence_result(observed, unknown=unknown, method="static")}
