"""main.py's _tech_icon_meta (Jinja filter "tech_icon_meta") -- classifies a Recon tab technology/
Protection label into what icon to render: a real vendor logo (vendored under
static/icons/tech/<key>.svg) for a recognized product, a shield glyph for a known WAF/CDN vendor
with no vendored logo (agent/core.py's own _WHATWEB_WAF_CDN_PLUGIN_NAMES allowlist -- reused here,
never a second, separately-curated guess), or a generic chip glyph for anything else.
"""
import main


def test_recognized_product_by_its_own_plugin_name_gets_a_logo():
    assert main._tech_icon_meta("WordPress") == {"kind": "logo", "key": "wordpress"}


def test_recognized_product_buried_inside_a_generic_header_value_still_matches():
    # WhatWeb reports some products as their own plugin name ("WordPress"), others inside a
    # generic header's bracketed value ("HTTPServer[nginx/1.18.0]") -- the caller passes name+
    # values joined, so this must match on the whole label, not just the bare grouped name.
    assert main._tech_icon_meta("HTTPServer nginx/1.18.0") == {"kind": "logo", "key": "nginx"}


def test_tomcat_is_not_misclassified_as_plain_apache():
    assert main._tech_icon_meta("Apache-Tomcat 9.0") == {"kind": "logo", "key": "tomcat"}


def test_known_waf_vendor_with_no_vendored_logo_gets_the_shield_fallback():
    assert main._tech_icon_meta("Incapsula (WAF/CDN, whatweb)") == {"kind": "waf", "key": "waf-generic"}


def test_unidentified_waf_still_gets_the_shield_fallback():
    assert main._tech_icon_meta("Unidentified WAF (nuclei global-waf-detect)") == {"kind": "waf", "key": "waf-generic"}


def test_unrecognized_technology_gets_the_generic_fallback():
    assert main._tech_icon_meta("SomeObscurePlugin[1.0]") == {"kind": "generic", "key": "tech-generic"}


def test_a_real_vendored_waf_cdn_still_gets_its_own_logo_not_the_shield():
    assert main._tech_icon_meta("Cloudflare (WAF, nuclei global-waf-detect)") == {"kind": "logo", "key": "cloudflare"}
