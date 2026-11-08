"""scripts/stage_site.py + scripts/check_site.py: the published site and its search metadata."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

from saikou import engine

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_site  # noqa: E402


def _stage(tmp_path, mode="full"):
    out = tmp_path / f"stage-{mode}"
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "stage_site.py"), "--mode", mode,
                           "--out", str(out)], capture_output=True, text=True)
    return proc, out


def _check(out, *extra):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "check_site.py"), str(out), *extra],
                          capture_output=True, text=True)


def _edit(path, old, new, count=1):
    text = path.read_text(encoding="utf-8")
    assert old in text, (path, old)
    path.write_text(text.replace(old, new, count), encoding="utf-8")


@pytest.mark.parametrize("mode", ["full", "interim"])
def test_staged_site_passes(tmp_path, mode):
    proc, _ = _stage(tmp_path, mode)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "search metadata consistent" in proc.stdout


def test_interim_legal_keeps_the_source_line_endings(tmp_path):
    proc, out = _stage(tmp_path, "interim")
    assert proc.returncode == 0, proc.stdout
    source = (ROOT / "site" / "legal.html").read_bytes()
    assert (out / "legal.html").read_bytes().count(b"\r\n") == source.count(b"\r\n")


@pytest.fixture
def full(tmp_path):
    proc, out = _stage(tmp_path)
    assert proc.returncode == 0, proc.stdout
    return out


def _fails_with(out, pattern, *extra):
    proc = _check(out, *extra)
    assert proc.returncode == 1, proc.stdout
    assert re.search(pattern, proc.stdout), proc.stdout


def test_missing_canonical_fails(full):
    _edit(full / "services.html", '<link rel="canonical" href="https://saikou.tech/services.html">\n', "")
    _fails_with(full, r"services\.html: missing <link rel=\"canonical\">")


def test_canonical_must_match_where_the_page_lives(full):
    _edit(full / "nl" / "nis2.html", 'rel="canonical" href="https://saikou.tech/nl/nis2.html"',
          'rel="canonical" href="https://saikou.tech/nis2.html"')
    _fails_with(full, r"nl/nis2\.html: canonical .* published at https://saikou\.tech/nl/nis2\.html")


def test_hreflang_must_be_reciprocal(full):
    _edit(full / "nl" / "index.html", '<link rel="alternate" hreflang="en" href="https://saikou.tech/">\n', "")
    _fails_with(full, r"index\.html: hreflang nl -> nl/index\.html is not reciprocal")


def test_hreflang_language_must_match_the_target(full):
    _edit(full / "nl" / "werkbank.html", '<html lang="nl">', '<html lang="en">')
    _fails_with(full, r"hreflang nl points at nl/werkbank\.html, whose <html lang> is 'en'")


def test_broken_or_padded_json_ld_fails(full):
    _edit(full / "index.html", '"@type": "SoftwareApplication",', '"@type": "SoftwareApplication"')
    _fails_with(full, r"index\.html: JSON-LD does not parse")


def test_json_ld_without_invented_ratings_and_with_the_real_version(full):
    _edit(full / "nl" / "index.html", f'"softwareVersion": "{engine.__version__}",',
          '"softwareVersion": "9.9.9", "aggregateRating": {"ratingValue": "5"},')
    _fails_with(full, r"carries \['aggregateRating'\]")
    _fails_with(full, r"softwareVersion 9\.9\.9 but the engine is")


def test_missing_open_graph_fails(full):
    _edit(full / "legal.html", '<meta property="og:description"', '<meta property="og:nope"')
    _fails_with(full, r"legal\.html: missing meta og:description")


def test_preview_image_must_be_a_staged_png_of_the_stated_size(full):
    _edit(full / "services.html", 'content="https://saikou.tech/assets/og-en.png"', 'content="https://saikou.tech/assets/og-xx.png"')
    _fails_with(full, r"services\.html: og:image https://saikou\.tech/assets/og-xx\.png is not a staged file")
    _edit(full / "nl" / "nis2.html", 'content="https://saikou.tech/assets/og-nl.png"', 'content="../assets/og-nl.png"')
    _fails_with(full, r"nl/nis2\.html: og:image \.\./assets/og-nl\.png is not an absolute https://saikou\.tech/ URL")
    _edit(full / "index.html", '<meta property="og:image:width" content="1200">', '<meta property="og:image:width" content="1201">')
    _fails_with(full, r"index\.html: og:image assets/og-en\.png is 1200x630 but the page states 1201x630")
    _edit(full / "legal.html", '<meta property="og:image:alt"', '<meta property="og:nope"')
    _fails_with(full, r"legal\.html: missing meta og:image:alt")


def test_sitemap_must_cover_every_page(full):
    _edit(full / "sitemap.xml", "<loc>https://saikou.tech/legal.html</loc>", "<loc>https://saikou.tech/gone.html</loc>")
    _fails_with(full, r"sitemap\.xml: https://saikou\.tech/gone\.html is not a staged page")
    _fails_with(full, r"published page https://saikou\.tech/legal\.html is not listed")


def test_not_found_page_links_from_the_root_and_stays_out_of_the_sitemap(full):
    assert (full / "404.html").exists()
    _edit(full / "404.html", 'href="/tools/checker.html">Compare', 'href="/tools/gone.html">Compare')
    _fails_with(full, r"404\.html: broken link /tools/gone\.html")
    _edit(full / "sitemap.xml", "</urlset>", "  <url><loc>https://saikou.tech/404.html</loc></url>\n</urlset>")
    _fails_with(full, r"sitemap\.xml: https://saikou\.tech/404\.html is marked noindex")


def test_protocol_relative_urls_fail(full):
    _edit(full / "legal.html", 'href="https://www.autoriteitpersoonsgegevens.nl"', 'href="//www.autoriteitpersoonsgegevens.nl"')
    _fails_with(full, r"legal\.html: protocol-relative URL //www\.autoriteitpersoonsgegevens\.nl")


def test_full_site_requires_sitemap_and_robots(full):
    (full / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")
    _fails_with(full, r"robots\.txt does not point at sitemap\.xml")
    _fails_with(full, r"robots\.txt disallows the whole site")
    (full / "sitemap.xml").unlink()
    _fails_with(full, r"sitemap\.xml missing", "--require-sitemap")


def test_canonical_links_are_not_third_party_loads(full):
    proc = _check(full)
    assert "third-party resource" not in proc.stdout
    _edit(full / "index.html", '<link rel="canonical"', '<link rel="stylesheet" href="https://cdn.example/x.css">\n<link rel="canonical"')
    _fails_with(full, r"third-party resource loaded: https://cdn\.example/x\.css")


@pytest.mark.parametrize("rel", ["index.html", "nl/index.html"])
def test_mojibake_fails(full, rel):
    # "\xb7" is the middle dot in the demo output; "\xc2\xb7" is how it reads when its UTF-8 bytes
    # are decoded as cp1252, which is what the Windows locale codec did to the published pages.
    _edit(full / rel, "[python \xb7 ast_verified", "[python \xc2\xb7 ast_verified")
    _fails_with(full, rf"{re.escape(rel)}:\d+: text decoded with the wrong codec")


def test_mojibake_in_site_data_fails(full):
    data = full / "assets" / "site-data.js"
    # An apostrophe's UTF-8 bytes read as cp1252.
    data.write_text(data.read_text(encoding="utf-8") + "\n// it\xe2\N{EURO SIGN}\N{TRADE MARK SIGN}s\n", encoding="utf-8")
    _fails_with(full, r"assets/site-data\.js:\d+: text decoded with the wrong codec")


def test_published_url_and_staged_path_round_trip():
    for rel in ("index.html", "nl/index.html", "services.html", "nl/nis2.html", "tools/checker.html"):
        assert check_site.staged_path(check_site.published_url(rel)) == rel
    assert check_site.staged_path("https://example.com/") is None


def test_badge_says_checked_not_secure():
    svg = (ROOT / "site" / "assets" / "fixes-checked-with-saikou.svg").read_text(encoding="utf-8")
    assert "fixes checked with" in svg and 'role="img"' in svg and "<title>" in svg
    assert not re.search(r"\b(secure|safe|certified)\b", re.sub(r"<!--.*?-->", "", svg, flags=re.S), re.I)


@pytest.mark.parametrize("sentence", [
    "Saikou catches every suppression.", "Saikou never misses a marker.", "We guarantee full coverage.",
    "It blocks all suppressions.", "No false positives.", "Saikou mist nooit een marker.",
    "Wij garanderen volledige dekking.", "Saikou vangt elke onderdrukking.",
    "Saikou has to block each marker they honour.", "Saikou blokkeert ieder marker.",
])
def test_unscoped_claims_about_what_the_checks_catch_are_banned(sentence):
    assert check_site.banned_claims("page.html", sentence)


@pytest.mark.parametrize("sentence", [
    "This is not a guarantee.", "There is no guarantee that nothing was missed.",
    "Er is geen garantie dat niets gemist is.",
])
def test_the_same_words_are_fine_when_they_deny_a_promise(sentence):
    assert check_site.banned_claims("page.html", sentence) == []


def test_generated_site_data_is_current():
    """site/assets/site-data.js and the data slots in the home pages come from
    scripts/render_site_data.py; run it after changing the demo, the oracle answers or a measurement."""
    import render_site_data
    assert render_site_data.main(["--check"]) == 0
