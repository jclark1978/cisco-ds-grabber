#!/usr/bin/env python3
"""cisco-extract: pull the captioned spec tables out of saved Cisco datasheet HTML.

Each table becomes a span-aware grid: every grid cell remembers which source
cell it came from, so a value spread across several columns (colspan) or rows
(rowspan) can be told apart from separate values. Superscript markers are
split from the text and footnotes are collected:

  - plain markers (1, 2, *) refer to footnotes printed right after the table
  - bracketed markers ([1], [2]) are document-wide endnotes

Tables are classified by caption: perf (performance / scalability) or hardware,
with the software image (ftd / asa) taken from the caption. Everything else
(compliance, ordering, feature lists) is skipped.

Usage:
    python cisco_extract.py datasheets/secure-firewall-3100.html   # dump tables
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString

MARKER_RE = re.compile(r"^(\[\d{1,2}\]|\d{1,2}|\*{1,3}|†{1,2}|‡)$")
TRAILING_MARKER_RE = re.compile(r"\s*(\[\d{1,2}\])\s*$")
FOOT_CLASSES = {"pDefault", "MsoFootnoteText", "pNumList1CMT"}
FOOT_RE = re.compile(r"^\s*(\[(\d{1,2})\]|(\d{1,2})\.?|(\*{1,3}|†|‡))\s+(\S.*)$")
HEADER_COMMENT_RE = re.compile(r"<!-- (.*?) \| (\S+) \| Updated (\S+) -->")

SKIP_CAPTION = re.compile(
    r"regulatory|compliance|productid|productnumber|ordering|accessor|sustainab|keycapab|generalcap|"
    r"accesscontrol|intrusiondetection|networkingcap|securityfeat|supportedci|suggest|modelssummary|"
    r"specificationhighlights|licensetier|deployment|instancesupport|instancetypes|hypervisor|anyconnect|orderable|"
    r"networkingstandards|softwarefeatures|ciscosecurefirewallisa3000models|catalyst|standaloneasac",
    re.I)
PERF_CAPTION = re.compile(r"perform|scalab|capabilitieson|specificationsfor\d", re.I)
HW_CAPTION = re.compile(r"hardware|physical|interfaces", re.I)


def squash(s: str) -> str:
    return re.sub(r"\s+", "", s or "")


def cell_text(cell) -> tuple[str, list[str]]:
    """Cell text with footnote markers split out. Line breaks become ' | '."""
    markers: list[str] = []
    for sup in cell.find_all("sup"):
        t = sup.get_text(strip=True)
        if MARKER_RE.match(t):
            markers.append(t)
        sup.replace_with(NavigableString(" " if MARKER_RE.match(t) else t))
    for br in cell.find_all("br"):
        br.replace_with(NavigableString(" | "))
    for blk in cell.find_all(["p", "li", "div"]):
        blk.insert_before(NavigableString(" | "))
    text = " ".join(cell.get_text(" ").split())
    text = re.sub(r"(\s*\|\s*)+", " | ", text).strip(" |")
    text = text.replace("●", "").replace("◦", "")
    text = re.sub(r"\s*\|\s*\|\s*", " | ", " ".join(text.split())).strip(" |")
    while True:  # plain-text [n] markers left at the end ("TLS Decryption [1]")
        m = TRAILING_MARKER_RE.search(text)
        if not m:
            break
        markers.insert(0, m.group(1))
        text = text[: m.start()].strip()
    return text, markers


def build_grid(table) -> list[list[dict]]:
    """Expand rowspan/colspan. Each grid cell: text, markers, cid, r0, c0, rs, cs."""
    out: list[list[dict]] = []
    carry: dict[int, tuple[dict, int]] = {}
    cid = 0
    for r_i, tr in enumerate(table.find_all("tr")):
        if tr.find_parent("table") is not table:
            continue
        row: list[dict] = []
        cells = iter(tr.find_all(["td", "th"], recursive=False))
        ci = 0
        while True:
            while ci in carry:
                src, left = carry[ci]
                row.append(src)
                if left <= 1:
                    del carry[ci]
                else:
                    carry[ci] = (src, left - 1)
                ci += 1
            c = next(cells, None)
            if c is None:
                break
            text, markers = cell_text(c)
            cs = max(1, int(c.get("colspan") or 1))
            rs = max(1, int(c.get("rowspan") or 1))
            src = {"text": text, "markers": markers, "cid": cid, "r0": len(out), "c0": ci, "rs": rs, "cs": cs}
            cid += 1
            for _ in range(cs):
                row.append(src)
                if rs > 1:
                    carry[ci] = (src, rs - 1)
                ci += 1
        out.append(row)
    width = max((len(r) for r in out), default=0)
    for r in out:  # pad short rows
        while len(r) < width:
            r.append({"text": "", "markers": [], "cid": -1, "r0": -1, "c0": len(r), "rs": 1, "cs": 1})
    return out


def caption_of(table) -> str | None:
    prev = table.find_previous(lambda x: x.name == "table" or "pTableCaptionCMT" in (x.get("class") or []))
    if prev is None or prev.name == "table":
        return None
    return " ".join(prev.get_text(" ").split())


def classify(caption: str) -> tuple[str | None, str | None]:
    sq = squash(caption)
    if SKIP_CAPTION.search(sq):
        return None, None
    kind = "perf" if PERF_CAPTION.search(sq) else "hardware" if HW_CAPTION.search(sq) else None
    image = None
    if kind == "perf":
        if re.search(r"\bASA\b|AdaptiveSecurityAppliance|ASAVirtual", caption) or re.search(r"specificationsfor\d", sq, re.I):
            image = "asa"
        elif re.search(r"ThreatDefense|FTD|\(TD\)|FTDc", sq, re.I):
            image = "ftd"
    return kind, image


def caption_details(caption: str) -> dict:
    """Platform and software notes printed in the caption (virtual datasheets)."""
    d = {}
    m = re.search(r"\(([^()]*(?:ESXi|AWS|Azure|GCP|OCI|Alibaba|Docker|Kubernetes)[^()]*)\)", caption)
    if m:
        d["platform"] = m.group(1).strip()
    m = re.search(r"later-\s*(.+)$", caption)  # ASAv: "Specifications for 9.20 and later- AWS"
    if m:
        d["platform"] = m.group(1).strip()
    m = re.search(r"(version\s+[\d.]+\+?[^:]*|\d+\.\d+ and later)", caption, re.I)
    if m:
        d["software_note"] = m.group(1).strip(" :")
    return d


def parse_footnote(el) -> tuple[str, str] | None:
    txt = " ".join(el.get_text(" ").split())
    m = FOOT_RE.match(txt)
    if not m:
        return None
    if m.group(2):
        key = f"[{m.group(2)}]"
    else:
        key = m.group(3) or m.group(4)
    return key, m.group(5).strip()


def extract(path: Path) -> dict:
    html = path.read_text(encoding="utf-8")
    soup = BeautifulSoup(html, "lxml")
    meta = {"file": path.name, "title": None, "url": None, "updated": None}
    m = HEADER_COMMENT_RE.search(html[:2000])
    if m:
        meta.update(title=m.group(1), url=m.group(2), updated=None if m.group(3) == "None" else m.group(3))

    tables, by_el = [], {}
    for t_i, t in enumerate(soup.find_all("table")):
        if t.find_parent("table"):
            continue
        cap = caption_of(t)
        entry = {"index": t_i, "caption": cap, "kind": None, "image": None, "footnotes": {}}
        if cap:
            entry["kind"], entry["image"] = classify(cap)
            entry.update(caption_details(cap))
            num = re.match(r"Table\s+(\d+)", cap)
            entry["number"] = int(num.group(1)) if num else None
        entry["grid"] = build_grid(t)
        tables.append(entry)
        by_el[id(t)] = entry

    # Footnotes: bracketed ones are document-wide; plain ones belong to the
    # table printed just before them.
    global_notes: dict[str, str] = {}
    for el in soup.find_all(["p", "div"]):
        if not FOOT_CLASSES & set(el.get("class") or []) or el.find_parent("table"):
            continue
        fn = parse_footnote(el)
        if not fn:
            continue
        key, text = fn
        if key.startswith("["):
            global_notes.setdefault(key, text)
            continue
        prev = el.find_previous("table")
        while prev is not None and prev.find_parent("table") is not None:
            prev = prev.find_parent("table")
        if prev is not None and id(prev) in by_el:
            by_el[id(prev)]["footnotes"].setdefault(key, text)
    meta["footnotes"] = global_notes
    meta["tables"] = tables
    return meta


def dump(meta: dict) -> None:
    print(f"# {meta['title']}  ({meta['updated']})  {meta['url']}")
    for t in meta["tables"]:
        if not t["kind"]:
            continue
        print(f"\n== [{t['kind']}/{t['image']}] {t['caption']}  {t.get('platform') or ''} {t.get('software_note') or ''}")
        for row in t["grid"]:
            print("   " + " || ".join((c["text"][:40] + (f" ^{','.join(c['markers'])}" if c["markers"] else "")) for c in row))
        for k, v in t["footnotes"].items():
            print(f"   fn {k}: {v[:100]}")
    for k, v in meta["footnotes"].items():
        print(f"global fn {k}: {v[:100]}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        meta = extract(Path(p))
        if "--json" in sys.argv:
            print(json.dumps(meta, indent=1)[:5000])
        else:
            dump(meta)
