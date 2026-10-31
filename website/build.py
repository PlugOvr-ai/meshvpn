#!/usr/bin/env python3
"""Builds the meshvpn website: pages/**/*.html (content only) -> public/ (complete pages).

Each page starts with a meta comment:  <!--meta {"title": "...", "description": "...", "nav": "features"} -->
In the content, {{root}} is the path to the site root ("" or "../"), so links work from any folder and from
file:// as well as from a web server. No dependencies: python3 build.py
"""
import html
import json
import pathlib
import re
import shutil

HERE = pathlib.Path(__file__).parent
PAGES, OUT = HERE / "pages", HERE / "public"
SITE = "https://meshvpn.plugovr.ai"  # canonical address (change once the site has its final home)

NAV = [
    ("features", "features.html", "Features"),
    ("use-cases", "use-cases.html", "Use cases"),
    ("tutorials", "tutorials/index.html", "Tutorials"),
    ("pricing", "pricing.html", "Pricing"),
    ("download", "download.html", "Download"),
]

LOGO = """<svg viewBox="0 0 32 32" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="2.2">
<path d="M7 9 L25 9 L16 25 Z"/><path d="M7 9 L16 17 L25 9 M16 17 L16 25" opacity=".45"/></g>
<g fill="var(--accent)"><circle cx="7" cy="9" r="3.6"/><circle cx="25" cy="9" r="3.6"/><circle cx="16" cy="25" r="3.6"/></g>
<circle cx="16" cy="17" r="2.6" fill="var(--amber)"/></svg>"""

SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"/></svg>'
MENU = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 6h18M3 12h18M3 18h18"/></svg>'


def head(meta, root, path):
    t = meta["title"]
    full = t if t.startswith("meshvpn") else f"{t} · meshvpn"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{html.escape(full)}</title>
<meta name="description" content="{html.escape(meta['description'])}">
<link rel="canonical" href="{SITE}/{path}">
<meta property="og:title" content="{html.escape(full)}">
<meta property="og:description" content="{html.escape(meta['description'])}">
<meta property="og:type" content="website">
<link rel="icon" href="{root}assets/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@100..125,500..900&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap">
<link rel="stylesheet" href="{root}assets/site.css">
<script src="{root}assets/site.js"></script>
</head>
<body>
"""


def header(nav, root):
    cur = ' aria-current="page"'
    links = "".join(
        f'<a href="{root}{href}"{cur if key == nav else ""}>{label}</a>' for key, href, label in NAV
    )
    return f"""<header class="site-head"><div class="wrap">
<a class="brand" href="{root}index.html">{LOGO}<span>meshvpn</span></a>
<button class="menu-btn" type="button" aria-label="Menu" aria-expanded="false">{MENU}</button>
<nav class="nav" aria-label="Main">{links}<a class="gh" href="https://github.com/PlugOvr-ai/meshvpn">GitHub</a>
<button class="theme-btn" type="button" aria-label="Switch light/dark">{SUN}</button></nav>
</div></header>
<main>
"""


def footer(root):
    return f"""</main>
<footer class="site-foot"><div class="wrap">
<div class="stack"><a class="brand" href="{root}index.html">{LOGO}<span>meshvpn</span></a>
<p class="muted">A mesh VPN without a coordination server, and device booking for labs, test benches and AI clusters. Made by PlugOvr.ai in Berlin.</p></div>
<div><h4>Product</h4><ul>
<li><a href="{root}features.html">Features</a></li><li><a href="{root}use-cases.html">Use cases</a></li>
<li><a href="{root}pricing.html">Pricing</a></li><li><a href="{root}download.html">Download</a></li></ul></div>
<div><h4>Learn</h4><ul>
<li><a href="{root}tutorials/index.html">Tutorials</a></li>
<li><a href="{root}tutorials/first-network.html">Your first network</a></li>
<li><a href="{root}tutorials/test-bench.html">Book a test bench</a></li>
<li><a href="https://github.com/PlugOvr-ai/meshvpn#readme">Reference (README)</a></li></ul></div>
<div><h4>Company</h4><ul>
<li><a href="{root}security.html">Security</a></li>
<li><a href="https://licenses.plugovr.ai/terms">License terms</a></li>
<li><a href="mailto:sales@plugovr.ai">sales@plugovr.ai</a></li>
<li><a href="mailto:security@plugovr.ai">security@plugovr.ai</a></li></ul></div>
<div class="fine"><span>© 2026 PlugOvr.ai</span><span>meshvpn core: Apache License 2.0</span><span>meshvpn enterprise: commercial license</span></div>
</div></footer>
</body>
</html>
"""


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(HERE / "assets", OUT / "assets")
    pages = sorted(PAGES.rglob("*.html"))
    for src in pages:
        rel = src.relative_to(PAGES)
        root = "../" * (len(rel.parts) - 1)
        text = src.read_text()
        m = re.match(r"\s*<!--meta (\{.*?\}) -->\s*", text, re.S)
        if not m:
            raise SystemExit(f"{rel}: no meta comment")
        meta = json.loads(m.group(1))
        body = text[m.end():].replace("{{root}}", root)
        page = head(meta, root, rel.as_posix()) + header(meta.get("nav", ""), root) + body + footer(root)
        dst = OUT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(page)
    # Every local link must lead somewhere.
    bad = []
    for f in OUT.rglob("*.html"):
        for href in re.findall(r'href="([^"#:]+?\.(?:html|css|svg))(?:#[^"]*)?"', f.read_text()):
            if not (f.parent / href).resolve().exists():
                bad.append(f"{f.relative_to(OUT)} -> {href}")
    if bad:
        raise SystemExit("broken links:\n  " + "\n  ".join(bad))
    print(f"{len(pages)} pages in {OUT}")


if __name__ == "__main__":
    build()
