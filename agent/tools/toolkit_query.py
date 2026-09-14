"""HTTPQL-lite: a small structured query language for filtering captured traffic entries
(agent/tools/toolkit_store.py's own schema) -- the same field.operator:value idea Caido's HTTPQL
popularized, scaled down to what this project's traffic entries actually carry. Exists so the
agent (and the operator, via the Site Map's own filter box) can pull a precise slice of a large
capture ("every response with a Set-Cookie missing HttpOnly", "every POST whose body contains
'password'") instead of paging through raw entries and filtering them by eye/in the model's own
context.

Grammar: one or more `field.operator:value` terms joined by AND/OR (AND binds tighter, matching
HTTPQL's own precedence), with parentheses for grouping. A bare value with no spaces needs no
quoting; a value containing spaces must be double-quoted (`"..."`, backslash-escapable).

    req.header.name.eq:"Authorization" AND resp.status.eq:200
    (method.eq:POST OR method.eq:PUT) AND resp.body.cont:"stack trace"

Fields: method, host, path, url, status, source, flags, req.body, resp.body,
req.header.name, req.header.value, resp.header.name, resp.header.value,
req.header["Header-Name"], resp.header["Header-Name"] (header lookup is case-insensitive, same as
HTTP itself).

Operators: eq/neq (exact match), cont/ncont (substring), like/nlike (SQL LIKE, `%`/`_` wildcards),
regex/nregex (Python re.search) -- all case-insensitive except regex, which follows whatever the
pattern itself specifies. Every field except a bracketed header lookup can resolve to MULTIPLE
candidate strings (e.g. every header's value) -- a positive operator matches if ANY candidate
satisfies it; its negated counterpart matches if NONE do.

Known limitation, deliberately not engineered around (YAGNI): a bracketed header name containing a
literal "." (e.g. `req.header["X.Forwarded.For"]`) still parses correctly because the operator is
always the LAST dot-separated segment (str.rsplit(".", 1)) -- but a field path is otherwise plain
text, not a real quote-aware tokenizer, so this only works because operators are a fixed keyword
set that can never itself appear as a legitimate header-name fragment.
"""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlsplit

Predicate = Callable[[dict], bool]

_OPERATORS = {"eq", "neq", "cont", "ncont", "like", "nlike", "regex", "nregex"}
_NEGATED_OPERATORS = {"neq", "ncont", "nlike", "nregex"}

# One token: LPAREN, RPAREN, AND/OR keywords, or a `left:value` term -- `left` has no spaces/parens
# (it's always `field.path.op`, resolved later), `value` is either a double-quoted string (may
# contain spaces, backslash-escaped) or a bare run of non-space/non-paren characters.
_TOKEN_RE = re.compile(
    r'\s*(?:'
    r'(?P<lparen>\()'
    r'|(?P<rparen>\))'
    r'|(?P<and>AND)\b'
    r'|(?P<or>OR)\b'
    r'|(?P<term>[^\s()]+:(?:"(?:[^"\\]|\\.)*"|[^\s()]*))'
    r')'
)


class QuerySyntaxError(ValueError):
    """Raised for a malformed query string -- always carries a human-readable, model-readable
    message (which segment failed and why), never a bare parser internals traceback."""


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return raw


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match or match.end() == pos:
            remainder = text[pos:].strip()
            if not remainder:
                break
            raise QuerySyntaxError(f"unrecognized query syntax starting at: {remainder[:40]!r}")
        pos = match.end()
        if match.group("lparen"):
            tokens.append(("LPAREN", "("))
        elif match.group("rparen"):
            tokens.append(("RPAREN", ")"))
        elif match.group("and"):
            tokens.append(("AND", "AND"))
        elif match.group("or"):
            tokens.append(("OR", "OR"))
        elif match.group("term"):
            tokens.append(("TERM", match.group("term")))
    return tokens


def _header_lookup(headers: dict, name: str) -> str:
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return ""


def _resolve_field_values(entry: dict, field_path: str) -> list[str]:
    """Every candidate string this field path could mean for one entry -- almost always a single
    value, except header.name/header.value, which fan out across every header (see this module's
    own docstring for why that's deliberate)."""
    if field_path == "method":
        return [entry.get("method", "")]
    if field_path == "status":
        return [str(entry.get("response_status", ""))]
    if field_path == "source":
        return [entry.get("source", "")]
    if field_path == "flags":
        return list(entry.get("flags") or [])
    if field_path in ("host", "path", "url"):
        url = entry.get("url", "")
        if field_path == "url":
            return [url]
        parts = urlsplit(url)
        return [parts.hostname or "" if field_path == "host" else parts.path or ""]
    if field_path in ("req.body", "resp.body"):
        return [entry.get("request_body" if field_path == "req.body" else "response_body", "")]

    header_match = re.match(r'^(req|resp)\.header\["(.+)"\]$', field_path)
    if header_match:
        namespace, name = header_match.groups()
        headers = entry.get("request_headers" if namespace == "req" else "response_headers", {})
        return [_header_lookup(headers, name)]

    if field_path in ("req.header.name", "resp.header.name", "req.header.value", "resp.header.value"):
        namespace, _, part = field_path.partition(".header.")
        headers = entry.get("request_headers" if namespace == "req" else "response_headers", {})
        return list(headers.keys()) if part == "name" else list(headers.values())

    raise QuerySyntaxError(
        f"unknown field {field_path!r} -- expected one of: method, host, path, url, status, "
        f'source, flags, req.body, resp.body, req.header.name, req.header.value, '
        f'resp.header.name, resp.header.value, req.header["Name"], resp.header["Name"]'
    )


def _like_to_regex(pattern: str) -> re.Pattern:
    # SQL LIKE: "%" -> any run of characters, "_" -> exactly one character, everything else literal.
    parts = re.split(r"(%|_)", pattern)
    regex_parts = [".*" if part == "%" else "." if part == "_" else re.escape(part) for part in parts]
    return re.compile("^" + "".join(regex_parts) + "$", re.IGNORECASE)


def _base_match(op: str, candidate: str, value: str) -> bool:
    if op in ("eq", "neq"):
        return candidate.lower() == value.lower()
    if op in ("cont", "ncont"):
        return value.lower() in candidate.lower()
    if op in ("like", "nlike"):
        return bool(_like_to_regex(value).match(candidate))
    # regex/nregex
    try:
        return bool(re.search(value, candidate))
    except re.error as exc:
        raise QuerySyntaxError(f"invalid regex {value!r}: {exc}") from exc


def _term_predicate(field_path: str, op: str, value: str) -> Predicate:
    negated = op in _NEGATED_OPERATORS

    def predicate(entry: dict) -> bool:
        candidates = _resolve_field_values(entry, field_path)
        any_match = any(_base_match(op, candidate, value) for candidate in candidates)
        return not any_match if negated else any_match

    return predicate


def _parse_term(raw: str) -> Predicate:
    left, _, quoted_value = raw.partition(":")
    field_path, sep, op = left.rpartition(".")
    if not sep or op not in _OPERATORS:
        raise QuerySyntaxError(
            f"malformed term {raw!r} -- expected field.operator:value, operator one of {sorted(_OPERATORS)}"
        )
    return _term_predicate(field_path, op, _unquote(quoted_value))


class _Parser:
    """Recursive-descent over the flat token list: parse_or -> parse_and (OR parse_and)*,
    parse_and -> parse_atom (AND parse_atom)*, parse_atom -> '(' parse_or ')' | TERM. Explicit
    AND/OR required between terms (no implicit juxtaposition), matching HTTPQL's own grammar."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _expect(self, kind: str) -> tuple[str, str]:
        token = self._peek()
        if token is None or token[0] != kind:
            raise QuerySyntaxError(f"expected {kind}, got {token[1] if token else 'end of query'!r}")
        self.pos += 1
        return token

    def parse(self) -> Predicate:
        predicate = self._parse_or()
        if self._peek() is not None:
            raise QuerySyntaxError(f"unexpected token {self._peek()[1]!r} after a complete query")
        return predicate

    def _parse_or(self) -> Predicate:
        clauses = [self._parse_and()]
        while self._peek() is not None and self._peek()[0] == "OR":
            self.pos += 1
            clauses.append(self._parse_and())
        if len(clauses) == 1:
            return clauses[0]
        return lambda entry: any(clause(entry) for clause in clauses)

    def _parse_and(self) -> Predicate:
        clauses = [self._parse_atom()]
        while self._peek() is not None and self._peek()[0] == "AND":
            self.pos += 1
            clauses.append(self._parse_atom())
        if len(clauses) == 1:
            return clauses[0]
        return lambda entry: all(clause(entry) for clause in clauses)

    def _parse_atom(self) -> Predicate:
        token = self._peek()
        if token is None:
            raise QuerySyntaxError("expected a term or '(', got end of query")
        if token[0] == "LPAREN":
            self.pos += 1
            predicate = self._parse_or()
            self._expect("RPAREN")
            return predicate
        if token[0] == "TERM":
            self.pos += 1
            return _parse_term(token[1])
        raise QuerySyntaxError(f"expected a term or '(', got {token[1]!r}")


def compile_query(text: str) -> Predicate:
    """Parses `text` into a predicate function(entry) -> bool. Raises QuerySyntaxError (a plain,
    readable message -- never a bare traceback) on malformed input; callers should catch it and
    surface `str(exc)` to whoever wrote the query (model or operator) so they can fix it."""
    text = text.strip()
    if not text:
        raise QuerySyntaxError("empty query")
    tokens = _tokenize(text)
    if not tokens:
        raise QuerySyntaxError("empty query")
    return _Parser(tokens).parse()


def filter_entries(entries: list[dict], query_text: str) -> list[dict]:
    """Convenience wrapper: compiles `query_text` once, applies it to every entry. Raises
    QuerySyntaxError the same way compile_query does."""
    predicate = compile_query(query_text)
    return [entry for entry in entries if predicate(entry)]
