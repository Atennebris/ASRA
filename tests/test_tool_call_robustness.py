"""Unit tests for the weak-model tool-call robustness layer: schema-driven argument coercion
(agent/tools/builders/validators.py) and fuzzy tool-name suggestion (agent/core.py), plus the env
flags gating both -- the conservative fixups for the type/shape slips small models make, pinned down
directly rather than only via a live run.
"""
import agent.core as core
from agent.tools.builders.validators import coerce_arguments_to_schema

_SCHEMA = {
    "type": "object",
    "properties": {
        "flag": {"type": "boolean"},
        "port": {"type": "integer"},
        "ratio": {"type": "number"},
        "host": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
}


# --- coerce_arguments_to_schema: the unambiguous fixups it SHOULD make ----------------------------

def test_coerce_stringified_bool_true():
    coerced, notes = coerce_arguments_to_schema({"flag": "True"}, _SCHEMA)
    assert coerced["flag"] is True
    assert notes


def test_coerce_stringified_bool_false():
    coerced, _ = coerce_arguments_to_schema({"flag": "false"}, _SCHEMA)
    assert coerced["flag"] is False


def test_coerce_stringified_int():
    coerced, _ = coerce_arguments_to_schema({"port": "8080"}, _SCHEMA)
    assert coerced["port"] == 8080 and isinstance(coerced["port"], int)


def test_coerce_stringified_float():
    coerced, _ = coerce_arguments_to_schema({"ratio": "1.5"}, _SCHEMA)
    assert coerced["ratio"] == 1.5 and isinstance(coerced["ratio"], float)


def test_coerce_single_item_list_to_scalar():
    coerced, _ = coerce_arguments_to_schema({"host": ["example.com"]}, _SCHEMA)
    assert coerced["host"] == "example.com"


def test_coerce_scalar_to_single_item_list():
    coerced, _ = coerce_arguments_to_schema({"tags": "xss"}, _SCHEMA)
    assert coerced["tags"] == ["xss"]


def test_coerce_unwraps_one_item_list_then_fixes_its_type():
    coerced, _ = coerce_arguments_to_schema({"port": ["8080"]}, _SCHEMA)
    assert coerced["port"] == 8080 and isinstance(coerced["port"], int)


# --- coerce_arguments_to_schema: what it must LEAVE ALONE -----------------------------------------

def test_coerce_leaves_already_correct_values_untouched():
    args = {"flag": True, "port": 443, "host": "example.com", "tags": ["a", "b"]}
    coerced, notes = coerce_arguments_to_schema(dict(args), _SCHEMA)
    assert coerced == args and notes == []


def test_coerce_leaves_ambiguous_values_untouched():
    # a multi-item list for a scalar, and a non-numeric string for an int -> no safe single answer
    coerced, notes = coerce_arguments_to_schema({"host": ["a", "b"], "port": "not-a-number"}, _SCHEMA)
    assert coerced["host"] == ["a", "b"]
    assert coerced["port"] == "not-a-number"
    assert notes == []


def test_coerce_with_no_schema_is_a_noop():
    args = {"anything": "goes"}
    coerced, notes = coerce_arguments_to_schema(dict(args), None)
    assert coerced == args and notes == []


def test_coerce_leaves_params_absent_from_schema_untouched():
    coerced, notes = coerce_arguments_to_schema({"not_in_schema": "true"}, _SCHEMA)
    assert coerced["not_in_schema"] == "true" and notes == []


def test_arg_coercion_flag_defaults_on_and_disables(monkeypatch):
    monkeypatch.delenv("TOOL_ARG_COERCION", raising=False)
    assert core._tool_arg_coercion_enabled() is True
    monkeypatch.setenv("TOOL_ARG_COERCION", "false")
    assert core._tool_arg_coercion_enabled() is False


# --- _suggest_close_tool_name: hint, never a silent substitution ----------------------------------

def test_fuzzy_suggests_a_close_tool_name(monkeypatch):
    monkeypatch.delenv("TOOL_NAME_FUZZY_CUTOFF", raising=False)
    names = ["http_request", "dns_lookup", "record_target"]
    assert core._suggest_close_tool_name("http_requst", names) == "http_request"


def test_fuzzy_returns_none_for_a_distant_name(monkeypatch):
    monkeypatch.delenv("TOOL_NAME_FUZZY_CUTOFF", raising=False)
    assert core._suggest_close_tool_name("zzzzzzzz", ["http_request", "dns_lookup"]) is None


def test_fuzzy_cutoff_env_tightens_the_match(monkeypatch):
    monkeypatch.setenv("TOOL_NAME_FUZZY_CUTOFF", "0.99")
    # a near-miss that matches at the 0.8 default must fail under a 0.99 cutoff
    assert core._suggest_close_tool_name("http_requst", ["http_request"]) is None


def test_fuzzy_cutoff_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("TOOL_NAME_FUZZY_CUTOFF", "garbage")
    assert core._tool_name_fuzzy_cutoff() == 0.8


def test_fuzzy_match_flag_defaults_on_and_disables(monkeypatch):
    monkeypatch.delenv("TOOL_NAME_FUZZY_MATCH", raising=False)
    assert core._tool_name_fuzzy_match_enabled() is True
    monkeypatch.setenv("TOOL_NAME_FUZZY_MATCH", "off")
    assert core._tool_name_fuzzy_match_enabled() is False
