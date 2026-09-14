"""Deterministic URL-list decluttering for wayback_urls/common_crawl_urls (agent/tools/native.py).

Same technique s0md3v's uro (github.com/s0md3v/uro, Apache-2.0) pioneered, reimplemented natively
here rather than vendored -- no external dependency, and it slots straight into this project's own
existing "small, deterministic, no extra network traffic" native-tool style (same spirit as
passive_detectors.py).

Real gap this closes: the Wayback/Common Crawl CDX APIs already collapse identical URLs across
capture TIME (collapse=urlkey), but do nothing for URLs that are DIFFERENT strings sharing the SAME
underlying page shape -- /product/1, /product/2, /product/3 ... or a blog with hundreds of
differently-slugged posts. Those were handed to the model completely raw before this existed,
burning context on near-duplicates instead of distinct attack surface.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

# uro's own default extension blacklist -- static assets that are never worth a pentester's
# attention in a URL list built for further crawling/fuzzing.
_STATIC_ASSET_EXTENSIONS = frozenset({
    "css", "png", "jpg", "jpeg", "svg", "ico", "webp", "scss", "tif", "tiff", "ttf", "otf",
    "woff", "woff2", "gif", "pdf", "bmp", "eot", "mp3", "mp4", "avi",
})

# Parameter names known to correlate with LFI/RCE/redirect/SSRF/SQLi-style bugs -- uro's own
# "vuln" filter list (lowercased/deduped here since query param casing varies but the underlying
# concern doesn't). Reused as a free prioritization signal on top of decluttering, not a separate
# scan -- these are the params worth a human/model actually looking at first among the survivors.
_INTERESTING_PARAM_NAMES = frozenset(name.lower() for name in (
    "file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "php_path",
    "doc", "page", "name", "cat", "dir", "action", "board", "date", "detail", "download", "prefix",
    "include", "inc", "locate", "show", "site", "type", "view", "content", "layout", "mod", "conf",
    "daemon", "upload", "log", "ip", "cli", "cmd", "exec", "command", "execute", "ping", "query",
    "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read",
    "function", "req", "feature", "exe", "module", "payload", "run", "print", "callback",
    "checkout", "checkout_url", "continue", "data", "dest", "destination", "domain", "feed",
    "file_name", "file_url", "folder_url", "forward", "from_url", "go", "goto", "host", "html",
    "image_url", "img_url", "load_file", "load_url", "login_url", "logout", "navigation", "next",
    "next_page", "open", "out", "page_url", "port", "redir", "redirect", "redirect_to",
    "redirect_uri", "redirect_url", "reference", "return", "return_path", "return_to", "returnto",
    "return_url", "rt", "rurl", "target", "to", "uri", "url", "val", "validate", "window", "q",
    "s", "search", "lang", "keyword", "keywords", "year", "email", "p", "jsonp", "api_key", "api",
    "password", "emailto", "token", "username", "csrf_token", "unsubscribe_token", "id", "item",
    "page_id", "month", "immagine", "list_type", "terms", "categoryid", "key", "l", "begindate",
    "enddate", "select", "report", "role", "update", "user", "sort", "where", "params", "row",
    "table", "from", "sel", "results", "sleep", "fetch", "order", "column", "field", "delete",
    "string", "number", "filter", "access", "admin", "dbg", "debug", "edit", "grant", "test",
    "alter", "clone", "create", "disable", "enable", "make", "modify", "rename", "reset", "shell",
    "toggle", "adm", "cfg", "img", "filename", "preview", "activity",
))

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
# A long hex-only segment is almost always a hash/session/object id, not distinct human-authored
# content -- same reasoning as the numeric case, just for non-decimal ids.
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


def _has_static_extension(path: str) -> bool:
    last_segment = path.rsplit("/", 1)[-1]
    if "." not in last_segment:
        return False
    return last_segment.rsplit(".", 1)[-1].lower() in _STATIC_ASSET_EXTENSIONS


def _is_placeholder_segment(segment: str) -> bool:
    """A path segment that varies per-item rather than per-page-shape: a numeric/hash id, or a
    hyphen-heavy slug (uro's own >3-hyphen heuristic for a human-written blog/article title)."""
    return bool(_NUMERIC_SEGMENT.match(segment) or _HEX_SEGMENT.match(segment) or segment.count("-") > 3)


def _pattern_key(path: str) -> str:
    """Collapses per-item path segments to a shared placeholder so /product/1 and /product/2 (or
    /blog/some-long-post-title and /blog/another-post-title) group under the same page shape
    instead of counting as distinct attack surface."""
    segments = path.rstrip("/").split("/")
    return "/".join("{n}" if _is_placeholder_segment(seg) else seg for seg in segments)


def declutter_urls(urls: list[str]) -> dict:
    """Drops static-asset URLs and collapses URLs that share both a host+page-shape AND the exact
    same set of query parameter NAMES already seen for that shape -- a URL is only kept if it's the
    first of its shape, or if it introduces a query parameter name that shape hasn't shown yet
    (matching uro's own compare_params semantics: new parameter surface is never collapsed away,
    only repeated ones are).

    Order-preserving (first occurrence of each shape/param-set wins) so callers get a stable,
    reproducible subset rather than an arbitrarily reordered one.
    """
    seen_param_names_by_shape: dict[tuple[str, str], set[str]] = {}
    kept: list[str] = []
    interesting: list[str] = []
    removed_static_asset = 0
    removed_duplicate_shape = 0

    for url in urls:
        parts = urlsplit(url)
        if _has_static_extension(parts.path):
            removed_static_asset += 1
            continue

        param_names = frozenset(name.lower() for name, _ in parse_qsl(parts.query))
        shape_key = (parts.netloc, _pattern_key(parts.path))
        already_covered = seen_param_names_by_shape.get(shape_key)

        if already_covered is not None and param_names <= already_covered:
            removed_duplicate_shape += 1
            continue

        seen_param_names_by_shape[shape_key] = (already_covered or set()) | param_names
        kept.append(url)
        if param_names & _INTERESTING_PARAM_NAMES:
            interesting.append(url)

    return {
        "urls": kept,
        "raw_count": len(urls),
        "kept_count": len(kept),
        "removed_count": removed_static_asset + removed_duplicate_shape,
        "removed_static_asset": removed_static_asset,
        "removed_duplicate_shape": removed_duplicate_shape,
        "interesting_urls": interesting,
    }
