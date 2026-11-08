"""Check a staged site before publishing.

    python scripts/check_site.py DIR [--require-sitemap]

Fails (exit 1) on: broken local links or anchors, dead `#` links, third-party
resources (scripts, stylesheets, fonts, images), unreplaced `{{ }}` slots, a missing
<title>/lang, text files that are not UTF-8 or carry mojibake ("Â·"), and any phrase the
project has committed never to claim.

Search metadata is checked too: every page needs a description, a canonical URL that
matches where it is published, and Open Graph / Twitter tags, with an og:image that is a staged
PNG of the stated size; hreflang alternates must
point at staged pages in the stated language and link back; JSON-LD must parse, carry no
ratings or reviews, and name the version the engine reports; sitemap.xml (required with
--require-sitemap) must list exactly the published pages and robots.txt must point at it.
External links are listed so a human can eyeball them; they are not fetched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

BASE = "https://saikou.tech"
ENGINE = Path(__file__).resolve().parent.parent / "saikou" / "engine.py"
SITEMAP_NS = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9", "x": "http://www.w3.org/1999/xhtml"}
REQUIRED_META = ("description", "og:title", "og:description", "og:url", "og:type", "og:image", "og:image:alt",
                 "twitter:card")
NO_INVENTED_PRAISE = {"aggregateRating", "review", "reviews", "reviewRating"}
TEXT_FILES = {".html", ".js", ".css", ".svg", ".xml", ".txt"}
# UTF-8 that was read with another codec ("Â·" for a middle dot, "â€™" for an apostrophe), or a
# character that could not be decoded at all.
MOJIBAKE = re.compile(r"[\xc2\xc3][\x80-\xbf]|\xe2[\x80\N{EURO SIGN}]|\N{REPLACEMENT CHARACTER}")

BANNED = [
    r"mathematical certainty", r"zero[- ]hallucination", r"hallucination risk", r"hallucination[s]? (are )?eliminat",
    r"eliminate ai hallucinations", r"deterministic audit engine", r"world'?s first", r"\bSCI\b", r"SCI™",
    r"model10™", r"100% (secure|safe|certain)", r"guaranteed? (secure|safe)", r"production[- ]ready",
    r"zero data retention", r"never stored", r"ram[- ]sandbox", r"\bcertified\b(?! nothing)",
    # A claim about what the checks catch must carry its scope (tools, versions, languages), which
    # the generated coverage statement does. These are the unscoped forms, English and Dutch.
    r"\bnever misses?\b", r"\bcatch(?:es)? (?:all|every|everything)\b", r"\bdetect(?:s)? (?:all|every|everything)\b",
    r"\bblock(?:s)? (?:all|every|everything|each)\b", r"\b(?:catch(?:es)?|detect(?:s)?) each\b", r"\bno (?:false|missed) (?:positives?|negatives?)\b",
    r"\b100% (?:coverage|detection)\b", r"\b(?:full|complete) coverage\b", r"\bguarantee[sd]?\b",
    r"\bmist nooit\b", r"\bvangt (?:alles|elke|ieder)\b", r"\bblokkeert (?:alles|elke|iedere|ieder)\b",
    r"\bvolledige dekking\b", r"\bgarandeer[td]?\b", r"\bgegarandeerd\b",
]
# Words allowed to appear in a negated or retiring context.
ALLOW_CONTEXT = [r"model10", r"nothing certified", r"certifies nothing", r"not\s+a\s+certificate", r"no certificate",
                 r"geen certificaat", r"certificeert niets", r"no guarantee", r"not a guarantee",
                 r"without guarantee", r"does not guarantee", r"geen garantie", r"niet gegarandeerd",
                 r"zonder garantie", r"garandeert niets", r"not guaranteed",
                 r"a guarantee that nothing was missed", r"een garantie dat niets gemist is"]


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: Set[str] = set()
        self.links: List[Tuple[str, str]] = []      # (tag, url)
        self.resources: List[Tuple[str, str]] = []
        self.title = ""
        self.lang = ""
        self.text: List[str] = []
        self.canonical: Optional[str] = None
        self.alternates: List[Tuple[str, str]] = []  # (hreflang, url)
        self.meta: Dict[str, str] = {}
        self.ldjson: List[str] = []
        self._in_title = False
        self._skip = 0
        self._ld: Optional[List[str]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        a: Dict[str, str] = {k: (v or "") for k, v in attrs}
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "html":
            self.lang = a.get("lang", "")
        if tag == "title":
            self._in_title = True
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script" and a.get("type") == "application/ld+json":
                self._ld = []
        if tag == "a" and "href" in a:
            self.links.append((tag, a["href"]))
        if tag == "link" and "href" in a:
            rel = a.get("rel", "").lower()
            # canonical and hreflang alternates name URLs; the browser loads nothing.
            if rel == "canonical":
                self.canonical = a["href"]
            elif rel == "alternate" and "hreflang" in a:
                self.alternates.append((a["hreflang"], a["href"]))
            else:
                self.resources.append((tag, a["href"]))
        if tag in ("script", "img", "iframe", "source", "video", "audio") and "src" in a:
            self.resources.append((tag, a["src"]))
        if tag == "meta":
            key = a.get("property") or a.get("name")
            if key:
                self.meta[key] = a.get("content", "")
                if key in ("description", "og:title", "og:description", "og:image:alt"):
                    self.text.append(a.get("content", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "script" and self._ld is not None:
            self.ldjson.append("".join(self._ld))
            self._ld = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._ld is not None:
            self._ld.append(data)
        elif not self._skip:
            self.text.append(data)


def noindex(p: Page) -> bool:
    """A page kept out of search (404.html): no canonical, preview or sitemap entry needed."""
    return "noindex" in p.meta.get("robots", "").lower()


def published_url(rel: str) -> str:
    """Where a staged file is served: index.html is its folder."""
    if rel == "index.html":
        return BASE + "/"
    if rel.endswith("/index.html"):
        return f"{BASE}/{rel[: -len('index.html')]}"
    return f"{BASE}/{rel}"


def staged_path(url: str) -> Optional[str]:
    """The staged file a site URL points at, or None for other sites."""
    if not url.startswith(BASE + "/"):
        return None
    path = urlparse(url).path.lstrip("/")
    return path + "index.html" if path == "" or path.endswith("/") else path


def engine_version() -> Optional[str]:
    try:
        m = re.search(r'^__version__\s*=\s*"([^"]+)"', ENGINE.read_text(encoding="utf-8"), re.M)
    except OSError:
        return None
    return m.group(1) if m else None


def keys_in(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from keys_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from keys_in(v)


def banned_claims(rel: str, text: str) -> List[str]:
    errors = []
    for pat in BANNED:
        for m in re.finditer(pat, text, flags=re.I):
            around = text[max(0, m.start() - 60): m.end() + 60].lower()
            if any(re.search(a, around) for a in ALLOW_CONTEXT):
                continue
            errors.append(f"{rel}: banned claim /{pat}/ near: ...{text[max(0, m.start()-30): m.end()+30].strip()}...")
    return errors


def png_size(path: Path) -> Optional[Tuple[int, int]]:
    head = path.read_bytes()[:24]
    if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def check_preview_image(rel: str, p: Page, root: Path) -> List[str]:
    """og:image: an absolute URL on this site (link previews cannot resolve a relative one), a staged
    PNG (previews do not render SVG), and the size the page states."""
    url = p.meta.get("og:image", "").strip()
    if not url:
        return []
    target = staged_path(url)
    if target is None:
        return [f"{rel}: og:image {url} is not an absolute {BASE}/ URL"]
    if not (root / target).is_file():
        return [f"{rel}: og:image {url} is not a staged file"]
    size = png_size(root / target)
    if size is None:
        return [f"{rel}: og:image {target} is not a PNG"]
    stated = (p.meta.get("og:image:width", ""), p.meta.get("og:image:height", ""))
    if stated != (str(size[0]), str(size[1])):
        return [f"{rel}: og:image {target} is {size[0]}x{size[1]} but the page states {stated[0] or '?'}x{stated[1] or '?'}"]
    return []


def check_metadata(rel: str, p: Page, pages: Dict[str, Page], version: Optional[str], root: Path) -> List[str]:
    errors: List[str] = []
    expected = published_url(rel)
    if not p.canonical:
        errors.append(f"{rel}: missing <link rel=\"canonical\">")
    elif p.canonical != expected:
        errors.append(f"{rel}: canonical {p.canonical} but the page is published at {expected}")
    for key in REQUIRED_META:
        if not p.meta.get(key, "").strip():
            errors.append(f"{rel}: missing meta {key}")
    if p.meta.get("og:url") and p.canonical and p.meta["og:url"] != p.canonical:
        errors.append(f"{rel}: og:url {p.meta['og:url']} differs from canonical {p.canonical}")
    errors += check_preview_image(rel, p, root)

    if p.alternates:
        langs = [lang for lang, _ in p.alternates]
        if "x-default" not in langs:
            errors.append(f"{rel}: hreflang alternates without x-default")
        if p.canonical and p.canonical not in [u for _, u in p.alternates]:
            errors.append(f"{rel}: hreflang alternates do not include the page itself")
        for lang, url in p.alternates:
            target = staged_path(url)
            if target is None or target not in pages:
                errors.append(f"{rel}: hreflang {lang} points at {url}, which is not a staged page")
                continue
            other = pages[target]
            if lang != "x-default" and other.lang != lang:
                errors.append(f"{rel}: hreflang {lang} points at {target}, whose <html lang> is {other.lang!r}")
            # The return link must carry this page's own language; an x-default back
            # to it does not count.
            if p.canonical and (p.lang, p.canonical) not in other.alternates:
                errors.append(f"{rel}: hreflang {lang} -> {target} is not reciprocal "
                              f"(no hreflang {p.lang!r} link back)")

    for block in p.ldjson:
        try:
            data = json.loads(block)
        except ValueError as exc:
            errors.append(f"{rel}: JSON-LD does not parse: {exc}")
            continue
        invented = NO_INVENTED_PRAISE & set(keys_in(data))
        if invented:
            errors.append(f"{rel}: JSON-LD carries {sorted(invented)}; no ratings or reviews without real ones")
        if isinstance(data, dict) and "softwareVersion" in data and version and data["softwareVersion"] != version:
            errors.append(f"{rel}: JSON-LD softwareVersion {data['softwareVersion']} but the engine is {version}")
        errors += banned_claims(rel, block)
    return errors


def check_encoding(root: Path) -> List[str]:
    errors: List[str] = []
    for f in sorted(root.rglob("*")):
        if f.suffix not in TEXT_FILES or not f.is_file():
            continue
        rel = f.relative_to(root).as_posix()
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"{rel}: not UTF-8 ({exc.reason} at byte {exc.start})")
            continue
        for m in MOJIBAKE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            errors.append(f"{rel}:{line}: text decoded with the wrong codec near "
                          f"...{text[max(0, m.start() - 30): m.end() + 30].strip()}...")
    return errors


def check_sitemap(root: Path, pages: Dict[str, Page], required: bool) -> List[str]:
    sitemap, robots = root / "sitemap.xml", root / "robots.txt"
    if not sitemap.exists():
        return ["sitemap.xml missing"] if required else []
    errors: List[str] = []
    try:
        tree = ET.parse(sitemap)
    except ET.ParseError as exc:
        return [f"sitemap.xml does not parse: {exc}"]
    listed: Set[str] = set()
    for url in tree.getroot().findall("s:url", SITEMAP_NS):
        loc = (url.findtext("s:loc", default="", namespaces=SITEMAP_NS) or "").strip()
        target = staged_path(loc)
        if target is None or target not in pages:
            errors.append(f"sitemap.xml: {loc} is not a staged page")
        elif noindex(pages[target]):
            errors.append(f"sitemap.xml: {loc} is marked noindex")
        listed.add(loc)
        for link in url.findall("x:link", SITEMAP_NS):
            href = link.get("href", "")
            if staged_path(href) not in pages:
                errors.append(f"sitemap.xml: alternate {href} of {loc} is not a staged page")
    published = {pages[rel].canonical or published_url(rel) for rel in pages if not noindex(pages[rel])}
    for missing in sorted(published - listed):
        errors.append(f"sitemap.xml: published page {missing} is not listed")
    try:
        robots_text = robots.read_text(encoding="utf-8")
    except OSError:
        return errors + ["robots.txt missing (it should point at sitemap.xml)"]
    if f"Sitemap: {BASE}/sitemap.xml" not in robots_text:
        errors.append("robots.txt does not point at sitemap.xml")
    if re.search(r"^Disallow:\s*/\s*$", robots_text, re.M):
        errors.append("robots.txt disallows the whole site")
    return errors


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check a staged site before publishing.")
    ap.add_argument("dir")
    ap.add_argument("--require-sitemap", action="store_true",
                    help="fail when sitemap.xml is missing (the full site must have one)")
    args = ap.parse_args(argv)
    root = Path(args.dir).resolve()
    pages: Dict[str, Page] = {}
    errors: List[str] = []
    for f in sorted(root.rglob("*.html")):
        p = Page()
        p.feed(f.read_text(encoding="utf-8"))
        pages[f.relative_to(root).as_posix()] = p

    version = engine_version()
    externals: Set[str] = set()
    for rel, p in pages.items():
        f = root / rel
        if not p.title.strip():
            errors.append(f"{rel}: missing <title>")
        if not p.lang:
            errors.append(f"{rel}: missing <html lang>")
        raw = f.read_text(encoding="utf-8")
        if "{{" in raw or "}}" in raw.replace("}}}", ""):
            if re.search(r"\{\{[^}]*\}\}", raw):
                errors.append(f"{rel}: unreplaced {{{{ }}}} slot")

        for tag, url in p.links + p.resources:
            if url in ("", "#"):
                errors.append(f"{rel}: dead link href={url!r}")
                continue
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https"):
                if (tag, url) in p.resources:
                    errors.append(f"{rel}: third-party resource loaded: {url}")
                else:
                    externals.add(url)
                continue
            if parsed.scheme == "mailto":
                continue
            if parsed.netloc:
                errors.append(f"{rel}: protocol-relative URL {url}; write the scheme")
                continue
            if parsed.scheme:
                errors.append(f"{rel}: unexpected scheme in {url}")
                continue
            if parsed.path.startswith("/"):
                # Root-relative (404.html, served at any depth): resolve against the site root.
                target = (root / unquote(parsed.path).lstrip("/")).resolve()
            else:
                target = (f.parent / unquote(parsed.path)).resolve() if parsed.path else f
            if parsed.path.endswith("/") and target.is_dir():
                target = target / "index.html"
            if parsed.path and not target.exists():
                errors.append(f"{rel}: broken link {url}")
            elif parsed.fragment and target.suffix == ".html":
                key = target.relative_to(root).as_posix() if root in target.parents else None
                if key in pages and parsed.fragment not in pages[key].ids:
                    errors.append(f"{rel}: missing anchor #{parsed.fragment} in {target.name}")

        if not noindex(p):
            errors += check_metadata(rel, p, pages, version, root)
        elif not p.meta.get("description", "").strip():
            errors.append(f"{rel}: missing meta description")
        errors += banned_claims(rel, " ".join(p.text))

    errors += check_sitemap(root, pages, args.require_sitemap)
    errors += check_encoding(root)

    print(f"checked {len(pages)} page(s) in {root}")
    if externals:
        print("external links (not fetched; eyeball them):")
        for u in sorted(externals):
            print("   ", u)
    if errors:
        print("\nFAILED:")
        for e in errors:
            print("   ", e)
        return 1
    print("OK: links resolve, no third-party loads, no banned claims, search metadata consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
