#!/usr/bin/env python3
"""cisco-grabber: keep a local, current library of Cisco Secure Firewall datasheets.

Cisco publishes each firewall family's datasheet as its own HTML page (with a
PDF copy). This script finds those pages from the sources in sources.yaml,
saves the datasheet body as clean HTML (the extractor's input) plus the PDF,
and records everything in manifest.json.

Usage:
    python cisco_grabber.py --list-only     # show what was found
    python cisco_grabber.py                 # download new/changed datasheets
    python cisco_grabber.py --force         # re-save everything
    python cisco_grabber.py --no-pdf        # skip the PDF copies
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import yaml
from bs4 import BeautifulSoup, Comment

BASE = "https://www.cisco.com"
# Cisco's CDN rejects some user agents (including a spoofed browser UA without
# matching headers). This descriptive UA with a contact URL is accepted.
USER_AGENT = "cisco-ds-grabber/1.0 (+https://github.com/jclark1978/cisco-ds-grabber)"
HREF_RE = re.compile(r'href="([^"#]+)', re.I)
DATE_RE = re.compile(r"Updated:\s*([A-Z][a-z]+ \d{1,2}, \d{4})")
KEEP_ATTRS = {"class", "colspan", "rowspan", "href", "name"}


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"})
    return s


def get(s: requests.Session, url: str, tries: int = 3) -> requests.Response | None:
    for i in range(tries):
        try:
            r = s.get(url, timeout=45)
        except requests.RequestException as e:
            print(f"  warning: {url}: {e.__class__.__name__}", flush=True)
            r = None
        if r is not None and r.status_code == 200:
            return r
        if r is not None and r.status_code == 404:
            print(f"  warning: {url}: HTTP 404", flush=True)
            return None
        time.sleep(2 * (i + 1))
    if r is not None:
        print(f"  warning: {url}: HTTP {r.status_code}", flush=True)
    return None


def norm(url: str) -> str:
    p = urlparse(url)
    return f"https://www.cisco.com{p.path}"


def wanted(url: str, cfg: dict) -> bool:
    path = urlparse(url).path
    inc = [re.compile(p, re.I) for p in cfg.get("include", [])]
    exc = [re.compile(p, re.I) for p in cfg.get("exclude", [])]
    return any(p.search(path) for p in inc) and not any(p.search(path) for p in exc)


def links(html: str, page: str) -> list[str]:
    out = []
    for h in HREF_RE.findall(html):
        h = re.sub(r"^/content/cdc/+", "/", h)  # hub links some pages as /content/cdc//site/...
        out.append(urljoin(page, h))
    return out


def discover(s: requests.Session, cfg: dict) -> list[str]:
    found: list[str] = []
    follow = [re.compile(p, re.I) for p in cfg.get("follow", [])]
    pages = []
    for hub in cfg.get("hub_pages", []):
        r = get(s, hub)
        if not r:
            continue
        pages.append((hub, r.text))
        for u in dict.fromkeys(links(r.text, hub)):
            if urlparse(u).netloc.endswith("cisco.com") and any(p.search(urlparse(u).path) for p in follow):
                r2 = get(s, norm(u))
                if r2:
                    pages.append((norm(u), r2.text))
                time.sleep(0.5)
    for url in cfg.get("crawl_pages", []):
        r = get(s, url)
        if r:
            pages.append((url, r.text))
        time.sleep(0.5)
    for url, html in pages:
        hits = [norm(u) for u in links(html, url) if wanted(u, cfg)]
        print(f"  {url}: {len(set(hits))} datasheet links", flush=True)
        found += hits
    found += [norm(u) for u in cfg.get("extra_pages", [])]
    return list(dict.fromkeys(found))


def file_name(url: str, cfg: dict) -> str:
    path = urlparse(url).path
    for key, name in (cfg.get("names") or {}).items():
        if key in path:
            return name
    return Path(path).stem


def clean_body(soup: BeautifulSoup):
    """The datasheet body with scripts, styles and volatile attributes removed."""
    body = soup.find(id="eot-doc-wrapper")
    if body is None:
        return None
    for t in body.find_all(["script", "style", "noscript", "img", "svg", "iframe", "button", "input"]):
        t.decompose()
    for c in body.find_all(string=lambda x: isinstance(x, Comment)):
        c.extract()
    for t in body.find_all(True):
        t.attrs = {k: v for k, v in t.attrs.items() if k in KEEP_ATTRS}
    return body


def page_info(s: requests.Session, url: str, cfg: dict) -> dict:
    info = {"name": file_name(url, cfg), "page_url": url, "title": None, "last_updated": None,
            "pdf_url": None, "body": None}
    r = get(s, url)
    if not r:
        info["error"] = "page not reachable"
        return info
    soup = BeautifulSoup(r.text, "lxml")
    h1 = soup.find("h1")
    if h1:
        info["title"] = " ".join(h1.get_text(" ").split())
    m = DATE_RE.search(soup.get_text(" "))
    if m:
        try:
            info["last_updated"] = datetime.strptime(m.group(1), "%B %d, %Y").date().isoformat()
        except ValueError:
            pass
    stem = Path(urlparse(url).path).stem
    for a in soup.find_all("a", href=True):
        if a["href"].split("?")[0].endswith(f"/{stem}.pdf"):
            info["pdf_url"] = norm(urljoin(url, a["href"]))
            break
    body = clean_body(soup)
    if body is None or not body.find("table"):
        info["error"] = "no datasheet body or tables found"
        return info
    html = (f"<!-- {info['title']} | {url} | Updated {info['last_updated']} -->\n"
            + str(body) + "\n")
    info["body"] = html.encode("utf-8")
    return info


def load_manifest(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"generated": None, "source": BASE, "datasheets": {}}


def archive(dest: Path, stamp: str) -> None:
    if dest.exists():
        a = dest.parent / "_archive"
        a.mkdir(exist_ok=True)
        dest.rename(a / f"{dest.stem}_{stamp}{dest.suffix}")


def sync(s, infos, out_dir: Path, manifest_path: Path, force=False, pdf=True) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_dir = out_dir / "pdf"
    manifest = load_manifest(manifest_path)
    entries = manifest["datasheets"]
    stats = {"new": [], "updated": [], "unchanged": [], "failed": []}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for info in infos:
        name = info["name"]
        prev, dest = entries.get(name), out_dir / f"{name}.html"
        if info.get("error"):
            print(f"  FAILED  {name}: {info['error']}", file=sys.stderr)
            stats["failed"].append(name)
            continue
        digest = hashlib.sha256(info["body"]).hexdigest()
        pdf_dest = pdf_dir / f"{name}.pdf"
        changed = force or not prev or prev.get("sha256") != digest or not dest.exists()
        if changed:
            stamp = (prev or {}).get("last_updated") or ((prev or {}).get("downloaded") or "old")[:10]
            if prev and dest.exists() and prev.get("sha256") != digest:
                archive(dest, stamp)
                stats["updated"].append(name)
                print(f"  UPDATED {name}")
            elif not prev:
                stats["new"].append(name)
                print(f"  NEW     {name}")
            else:
                stats["unchanged"].append(name)
            dest.write_bytes(info["body"])
        else:
            stats["unchanged"].append(name)
        entry = dict(prev or {})
        entry.update({
            "title": info["title"] or name,
            "url": info["page_url"],
            "pdf_url": info["pdf_url"],
            "last_updated": info["last_updated"],
            "file": f"{name}.html",
            "sha256": digest,
            "bytes": len(info["body"]),
        })
        if changed and (not prev or prev.get("sha256") != digest):
            entry["downloaded"] = now
        # PDF copy: fetched when the page changed or the copy is missing.
        if pdf and info["pdf_url"] and (changed or not pdf_dest.exists()):
            r = get(s, info["pdf_url"])
            if r and r.content.startswith(b"%PDF"):
                pdf_digest = hashlib.sha256(r.content).hexdigest()
                if entry.get("pdf_sha256") != pdf_digest or not pdf_dest.exists():
                    pdf_dir.mkdir(exist_ok=True)
                    if pdf_dest.exists():
                        archive(pdf_dest, (prev or {}).get("last_updated") or "old")
                    pdf_dest.write_bytes(r.content)
                    entry["pdf_sha256"] = pdf_digest
                    entry["pdf_file"] = f"pdf/{name}.pdf"
            else:
                print(f"  warning: {name}: PDF not downloaded", file=sys.stderr)
        entries[name] = entry
        time.sleep(0.5)

    if stats["new"] or stats["updated"] or not manifest.get("generated"):
        manifest["generated"] = now
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    write_index(entries, out_dir / "INDEX.md")
    return stats


def write_index(entries: dict, path: Path) -> None:
    rows = sorted(entries.items())
    lines = ["# Datasheet index", "",
             f"{len(rows)} Cisco Secure Firewall datasheets from {BASE}.", "",
             "| Datasheet | Updated (Cisco) | HTML | PDF |", "|---|---|---|---|"]
    for name, e in rows:
        pdf = f"[pdf]({e['pdf_file']})" if e.get("pdf_file") else "n/a"
        lines.append(f"| [{e['title']}]({e['url']}) | {e.get('last_updated') or 'n/a'} | [{e['file']}]({e['file']}) | {pdf} |")
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", default="sources.yaml")
    ap.add_argument("--out", default="datasheets")
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-pdf", action="store_true")
    a = ap.parse_args()

    cfg = yaml.safe_load(Path(a.sources).read_text())
    s = session()
    print("Discovering datasheet pages ...", flush=True)
    urls = discover(s, cfg)
    print(f"{len(urls)} datasheet pages", flush=True)
    if not urls:
        print("ERROR: no datasheet pages found; the source pages may have changed.", file=sys.stderr)
        return 2
    infos = []
    for u in urls:
        infos.append(page_info(s, u, cfg))
        time.sleep(0.5)
    if a.list_only:
        for i in infos:
            print(f"  {i.get('last_updated') or '----------'}  {i['name']:28} {i.get('title') or ''}"
                  f" {('ERROR ' + i['error']) if i.get('error') else ''}")
        return 0
    stats = sync(s, infos, Path(a.out), Path(a.manifest), force=a.force, pdf=not a.no_pdf)
    print(f"Done: {len(stats['new'])} new, {len(stats['updated'])} updated, "
          f"{len(stats['unchanged'])} unchanged, {len(stats['failed'])} failed")
    if stats["failed"]:
        print("Failed: " + ", ".join(stats["failed"]), file=sys.stderr)
    return 0 if (stats["new"] or stats["updated"] or stats["unchanged"]) else 1


if __name__ == "__main__":
    sys.exit(main())
