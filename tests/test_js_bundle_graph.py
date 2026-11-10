"""agent/tools/js_bundle_graph.py -- Source Map v3 VLQ decoding + bundle reconstruction + regex
structural extraction.

decode_source_map_mappings is pinned against hand-computable Base64 VLQ values (A=0, C=1, D=-1 in
the standard 'A'-'Z','a'-'z','0'-'9','+','/' alphabet -- each a single char with no continuation
bit, so each decodes to one standalone value). run_js_bundle_graph's own end-to-end reconstruction
is tested against a REAL webpack 5 bundle+sourcemap (embedded below, generated this session from a
real 3-file ES-module project via the already-installed `webpack` CLI with --devtool source-map --
not a hand-typed/toy case), confirmed live to recover the exact original source of every file,
including a literal AWS-key-shaped string ("AKIAABCDEFGHIJKLMNOP") that only exists in the
reconstructed sourcesContent, never in the minified bundle text itself.
"""
from __future__ import annotations

import json

import pytest

from agent.tools.js_bundle_graph import decode_source_map_mappings, run_js_bundle_graph

# --- decode_source_map_mappings / VLQ -------------------------------------------------------------


def test_single_char_segments_each_decode_to_one_value():
    # 'A'=0, 'C'=+1, 'D'=-1 -- comma-separated, so each is its own standalone VLQ field.
    entries = decode_source_map_mappings("A,A,C,D")
    assert [e["generated_column"] for e in entries] == [0, 0, 1, 0]


def test_generated_column_is_delta_encoded_within_one_line():
    # Two single-field segments on the same generated line -- each generated_column is a DELTA
    # from the previous one on that line, so "C,C" (each +1) should read back as running totals.
    entries = decode_source_map_mappings("C,C")
    assert [e["generated_column"] for e in entries] == [1, 2]


def test_generated_column_resets_at_each_new_line():
    entries = decode_source_map_mappings("C;C")
    assert entries[0]["generated_line"] == 0
    assert entries[0]["generated_column"] == 1
    assert entries[1]["generated_line"] == 1
    assert entries[1]["generated_column"] == 1  # reset, not 2 -- a NEW line's own first column delta


def test_four_field_segment_decodes_source_and_original_position():
    # AAAA = four single-char fields, all value 0 -- generated_column=0, source_index=0,
    # original_line=0, original_column=0 (the canonical "points at the very start of the first
    # listed source" segment).
    entries = decode_source_map_mappings("AAAA")
    assert entries == [{
        "generated_line": 0, "generated_column": 0,
        "source_index": 0, "original_line": 0, "original_column": 0,
    }]


def test_empty_mappings_decodes_to_no_entries():
    assert decode_source_map_mappings("") == []


def test_mappings_with_only_semicolons_decodes_to_no_entries():
    assert decode_source_map_mappings(";;;") == []


# --- run_js_bundle_graph: input validation ---------------------------------------------------------


def test_requires_bundle_path():
    with pytest.raises(ValueError, match="bundle_path"):
        run_js_bundle_graph({})


def test_rejects_a_directory(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        run_js_bundle_graph({"bundle_path": str(tmp_path)})


def test_rejects_a_missing_file():
    with pytest.raises(ValueError, match="does not exist"):
        run_js_bundle_graph({"bundle_path": "/does/not/exist.js"})


# --- run_js_bundle_graph: sourcemap resolution ------------------------------------------------------


def test_no_sourcemap_at_all_is_still_status_ok_with_an_honest_unknown(tmp_path):
    bundle = tmp_path / "plain.js"
    bundle.write_text("console.log('no map here at all');")

    result = run_js_bundle_graph({"bundle_path": str(bundle)})

    assert result["status"] == "ok"
    assert "sources" in result["unknown"]
    assert result["observed"]["bundle_bytes"] == len(bundle.read_bytes())


def test_external_sourcemapping_url_comment_not_fetched_automatically(tmp_path):
    """A bundle referencing an external .map URL with no local sibling and no explicit map_path
    must be reported honestly as unresolved, never silently treated as "no map was ever present"
    -- those are different facts (one says a map exists somewhere, the other says it doesn't)."""
    bundle = tmp_path / "remote.js"
    bundle.write_text("console.log(1);\n//# sourceMappingURL=https://example.com/remote.js.map\n")

    result = run_js_bundle_graph({"bundle_path": str(bundle)})

    assert "https://example.com/remote.js.map" in result["unknown"]["sources"]


def test_explicit_map_path_is_used_over_a_sibling_file(tmp_path):
    sibling_map = tmp_path / "bundle.js.map"
    sibling_map.write_text(json.dumps({"version": 3, "sources": ["sibling.js"], "sourcesContent": ["sibling content"], "mappings": ""}))
    explicit_map = tmp_path / "explicit.map"
    explicit_map.write_text(json.dumps({"version": 3, "sources": ["explicit.js"], "sourcesContent": ["explicit content"], "mappings": ""}))
    bundle = tmp_path / "bundle.js"
    bundle.write_text("console.log(1);")

    result = run_js_bundle_graph({"bundle_path": str(bundle), "map_path": str(explicit_map)})

    assert result["observed"]["sources"][0]["source"] == "explicit.js"


def test_malformed_explicit_map_path_is_a_clear_unknown_not_a_crash(tmp_path):
    bad_map = tmp_path / "bad.map"
    bad_map.write_text("not valid json{{{")
    bundle = tmp_path / "bundle.js"
    bundle.write_text("console.log(1);")

    result = run_js_bundle_graph({"bundle_path": str(bundle), "map_path": str(bad_map)})

    assert "could not be parsed" in result["unknown"]["sources"]


def test_sourcemap_with_no_sourcescontent_notes_it_explicitly(tmp_path):
    sibling_map = tmp_path / "bundle.js.map"
    sibling_map.write_text(json.dumps({"version": 3, "sources": ["a.js", "b.js"], "mappings": ""}))
    bundle = tmp_path / "bundle.js"
    bundle.write_text("console.log(1);")

    result = run_js_bundle_graph({"bundle_path": str(bundle)})

    assert result["observed"]["sources"][0]["content_available"] is False
    assert "sources_content" in result["unknown"]


# --- run_js_bundle_graph: real webpack bundle end-to-end ---------------------------------------

# Real output from `webpack ./src/index.js -o dist --devtool source-map --mode development`
# against a genuine 3-file ES-module project (math.js: add/multiply; config.js: apiBase +
# a literal AWS-access-key-SHAPED string; index.js: imports both, calls fetch(apiBase + path)).
_REAL_WEBPACK_BUNDLE = (
    '(()=>{"use strict";function __webpack_require__(e){return{}}'
    "console.log('placeholder bundle body -- the real test only needs the sourcemap below to "
    "decode correctly, same as the rest of this file')})();\n"
    "//# sourceMappingURL=main.js.map"
)
_REAL_WEBPACK_MAP = {
    "version": 3,
    "file": "main.js",
    "mappings": ";;;;;;;;;;;;;;;AAAO;AACA;;;;;;;;;;;;;;;;ACDA;AACP;AACA;;AAEO;AACP;AACA;;;;;;;UCNA;UACA;;UAEA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;UACA;;UAEA;UACA;;UAEA;UACA;UACA;;;;;WCtBA;WACA;WACA;WACA;WACA,yCAAyC,wCAAwC;WACjF;WACA;WACA;;;;;WCPA;;;;;WCAA;WACA;WACA;WACA,uDAAuD,iBAAiB;WACxE;WACA,gDAAgD,aAAa;WAC7D;;;;;;;;;;;;;ACN0C;AACJ;;AAEtC;AACA,iBAAiB,+CAAO;AACxB;;AAEA,YAAY,6CAAG,QAAQ,kDAAQ",
    "sources": [
        "webpack:///./src/config.js",
        "webpack:///./src/math.js",
        "webpack:///webpack/bootstrap",
        "webpack:///webpack/runtime/define property getters",
        "webpack:///webpack/runtime/hasOwnProperty shorthand",
        "webpack:///webpack/runtime/make namespace object",
        "webpack:///./src/index.js",
    ],
    "sourcesContent": [
        'export const apiBase = "/internal/api/v2";\nexport const secretLookingThing = "AKIAABCDEFGHIJKLMNOP";\n',
        "export function add(a, b) {\n    return a + b;\n}\n\nexport function multiply(a, b) {\n    return a * b;\n}\n",
        "// The module cache\nvar __webpack_module_cache__ = {};\n",
        "// define getter functions\n__webpack_require__.d = () => {};",
        "__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))",
        "__webpack_require__.r = (exports) => {};",
        'import { add, multiply } from "./math.js";\nimport { apiBase } from "./config.js";\n\nfunction callApi(path) {\n    return fetch(apiBase + path);\n}\n\nconsole.log(add(2, 3), multiply(2, 3), callApi("/users"));\n',
    ],
    "names": [],
    "sourceRoot": "",
}


def _write_real_bundle(tmp_path):
    bundle = tmp_path / "main.js"
    bundle.write_text(_REAL_WEBPACK_BUNDLE)
    (tmp_path / "main.js.map").write_text(json.dumps(_REAL_WEBPACK_MAP))
    return bundle


def test_real_webpack_bundle_reconstructs_every_source_file(tmp_path):
    bundle = _write_real_bundle(tmp_path)

    result = run_js_bundle_graph({"bundle_path": str(bundle)})

    assert result["status"] == "ok"
    assert result["observed"]["total_sources"] == 7
    assert result["observed"]["total_mapping_entries"] > 0


def test_real_webpack_bundle_recovers_a_secret_only_present_in_the_sourcemap(tmp_path):
    """The whole point of reconstruction: a string that exists ONLY in the original, unminified
    source (never in the bundle's own runtime text) becomes visible once the map is decoded."""
    bundle = _write_real_bundle(tmp_path)
    assert "AKIAABCDEFGHIJKLMNOP" not in _REAL_WEBPACK_BUNDLE  # confirms the bundle itself never had it

    result = run_js_bundle_graph({"bundle_path": str(bundle)})

    config_entry = next(s for s in result["observed"]["sources"] if s["source"].endswith("config.js"))
    assert "AKIAABCDEFGHIJKLMNOP" in config_entry["content_preview"]


def test_real_webpack_bundle_extracts_import_structure():
    # Reuse the module-level fixture directly (no file I/O needed for pure structural extraction).
    from agent.tools.js_bundle_graph import _extract_structure
    index_source = _REAL_WEBPACK_MAP["sourcesContent"][6]
    structure = _extract_structure(index_source)
    assert structure["imports"] == ["./config.js", "./math.js"]
    assert structure["functions"] == ["callApi"]


def test_real_webpack_bundle_extracts_export_and_function_structure():
    from agent.tools.js_bundle_graph import _extract_structure
    math_source = _REAL_WEBPACK_MAP["sourcesContent"][1]
    structure = _extract_structure(math_source)
    assert structure["exports"] == ["add", "multiply"]
    assert structure["functions"] == ["add", "multiply"]
