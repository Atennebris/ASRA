"""build_subfinder_command / parse_subfinder_output.

Real gap this tool closes: crt_sh_lookup only ever sees a subdomain with its own TLS certificate,
subdomain_enum only resolves a short fixed ~50-word prefix list -- a real forgotten
staging/internal host with neither surfaces from either. Subfinder aggregates many independent
passive OSINT sources in one pass.

parse_subfinder_output's shape is confirmed against a real live run:
subfinder -d hackerone.com -silent returned 19 real subdomains, one per line.
"""
from agent.tools.builders.subfinder import build_subfinder_command, parse_subfinder_output


def test_build_command_places_domain_and_silent_flag():
    command = build_subfinder_command({"domain": "example.com"})
    assert command == ["subfinder", "-d", "example.com", "-silent"]


def test_build_command_rejects_an_empty_domain():
    import pytest

    with pytest.raises(ValueError):
        build_subfinder_command({"domain": "   "})


def test_build_command_appends_extra_args():
    command = build_subfinder_command({"domain": "example.com", "extra_args": ["-all"]})
    assert "-all" in command


# Trimmed from a real subfinder v2.14.0 -silent run against hackerone.com.
_REAL_LIVE_OUTPUT = (
    "ns3.hackerone.com\nwww.hackerone.com\nautodiscover.hackerone.com\ndocs.hackerone.com\n"
    "mail2.hackerone.com\nmanaged.hackerone.com\n"
)


def test_parse_real_live_output_returns_a_sorted_deduplicated_flat_list():
    result = parse_subfinder_output(_REAL_LIVE_OUTPUT)
    assert result == {
        "subdomains": [
            "autodiscover.hackerone.com", "docs.hackerone.com", "mail2.hackerone.com",
            "managed.hackerone.com", "ns3.hackerone.com", "www.hackerone.com",
        ]
    }


def test_parse_output_deduplicates_repeated_lines():
    result = parse_subfinder_output("a.example.com\na.example.com\nb.example.com\n")
    assert result["subdomains"] == ["a.example.com", "b.example.com"]


def test_parse_output_ignores_blank_lines():
    result = parse_subfinder_output("a.example.com\n\n\nb.example.com\n")
    assert result["subdomains"] == ["a.example.com", "b.example.com"]


def test_parse_empty_output_returns_an_empty_list():
    assert parse_subfinder_output("") == {"subdomains": []}


def test_parse_output_collapses_large_cdn_edge_node_fan_out():
    """Real, confirmed incident this covers (a real HackerOne session): subfinder against a
    domain backed by a large CDN returned thousands of interchangeable edge-node hostnames
    (e.g. "ipv4-c017-ord003-ix.1.oca.example-cdn.net") differing only in numeric segments -- handing
    the model the full raw list let one subagent burn several tool calls on hosts that don't even
    resolve. A group past the collapse threshold must shrink to a couple of representative samples
    plus a count; ordinary small numbered groups (www1/www2) must pass through untouched."""
    lines = "\n".join(f"ipv4-c{i:03d}-ord003-ix.1.oca.example-cdn.net" for i in range(20))
    result = parse_subfinder_output(lines)
    assert len(result["subdomains"]) == 3  # 2 samples + 1 "... N more" marker
    assert "20 more" not in result["subdomains"][-1]  # 2 samples were pulled out, not all 20
    assert "18 more" in result["subdomains"][-1]
    assert "collapsed" in result["subdomains"][-1]


def test_parse_output_leaves_a_small_numbered_group_untouched():
    result = parse_subfinder_output("www1.example.com\nwww2.example.com\nns1.example.com\n")
    assert result["subdomains"] == ["ns1.example.com", "www1.example.com", "www2.example.com"]


def test_subfinder_is_registered_with_its_own_build_command_and_recon_category():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("subfinder")
    assert spec.build_command is build_subfinder_command
    assert spec.category == "recon"
    assert spec.requires_allowed_target is False
