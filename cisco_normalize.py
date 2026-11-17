#!/usr/bin/env python3
"""cisco-normalize: turn the extracted Cisco datasheet tables into model records.

Reads datasheets/*.html (via cisco_extract) and labels.yaml, writes:

  data/models.json          all records
  data/models/<id>.json     one record per model
  data/index.json           model_id -> summary
  data/models.csv           one row per model and software image
  reports/extraction.txt    what was read from each datasheet
  reports/unmapped_labels.txt

Cisco publishes separate numbers per software image (Threat Defense = FTD,
ASA). They are stored apart in specs_by_image and must not be mixed.

Usage:
    python cisco_normalize.py            # convert
    python cisco_normalize.py --check    # convert, fail if results look wrong
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from cisco_extract import extract

DEFAULT_COLUMN_RE = r"^\d{3,4}[A-Z]{0,3}(\s*/\s*\d{3,4}[A-Z]{0,3})?$"
NULLS = {"", "-", "–", "na", "n/a", "tbd", "none", "not supported", "not available"}
IMAGE_NAMES = {"ftd": "Threat Defense (FTD)", "asa": "ASA", "mx": "Meraki MX"}


# ---------------------------------------------------------------- parsing

def num(s: str) -> float:
    return float(s.replace(",", ""))


def clean_number(x: float):
    return int(x) if float(x).is_integer() else round(x, 3)


def parse_throughput(raw: str):
    m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(Tbps|Gbps|Gbp|Mbps|Kbps|G|M)\b", raw, re.I)
    if not m:
        return None
    v, unit = num(m.group(1)), m.group(2).lower()
    mult = {"tbps": 1e6, "gbps": 1000, "gbp": 1000, "g": 1000, "mbps": 1, "m": 1, "kbps": 0.001}[unit]
    return clean_number(v * mult)


def parse_count(raw: str):
    m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(million|mil|thousand|m|k)?(?![a-z])", raw, re.I)
    if not m:
        return None
    v = num(m.group(1))
    unit = (m.group(2) or "").lower()
    v *= {"million": 1e6, "mil": 1e6, "m": 1e6, "thousand": 1e3, "k": 1e3}.get(unit, 1)
    return clean_number(v)


def parse_contexts(raw: str):
    nums = re.findall(r"\d[\d,]*", raw)
    if len(nums) >= 2:
        return {"included": int(num(nums[0])), "max": int(num(nums[1]))}
    return None


def parse_number(raw: str):
    m = re.search(r"-?\d[\d,]*(?:\.\d+)?", raw)
    return clean_number(num(m.group(0))) if m else None


def parse_value(raw: str, ptype: str):
    if raw.strip().lower().rstrip(".") in NULLS:
        return None
    if ptype == "throughput":
        return parse_throughput(raw)
    if ptype == "count":
        return parse_count(raw)
    if ptype == "contexts":
        return parse_contexts(raw)
    if ptype == "number":
        return parse_number(raw)
    return raw


# ------------------------------------------------------- hardware derived

def dims_mm(raw: str, label: str):
    order = "hwd"
    m = re.search(r"\(\s*([HWD])\s*x\s*([HWD])\s*x\s*([HWD])\s*\)", label, re.I)
    if m:
        order = "".join(m.groups()).lower()
    trip = r"(\d+(?:\.\d+)?)\s*(?:[a-z]*\s*)?x\s*(\d+(?:\.\d+)?)\s*(?:[a-z]*\s*)?x\s*(\d+(?:\.\d+)?)"
    m = re.search(trip + r"\s*mm", raw, re.I)
    factor = 1
    if not m:
        m = re.search(trip + r"\s*cm", raw, re.I)
        factor = 10
    if not m:
        factor = 10
        m = re.search(r"(\d+(?:\.\d+)?)\s*cm\s*[a-z]?\s*x\s*(\d+(?:\.\d+)?)\s*cm\s*[a-z]?\s*x\s*(\d+(?:\.\d+)?)\s*cm", raw, re.I)
    if not m:
        m = re.search(trip, raw, re.I)
        factor = 25.4
    if not m:
        return None
    vals = [round(float(v) * factor, 1) for v in m.groups()]
    d = dict(zip(order, vals))
    return {"h": d.get("h"), "w": d.get("w"), "d": d.get("d")}


def weight_kg(raw: str):
    m = re.search(r"(\d+(?:\.\d+)?)\s*kgs?\b", raw, re.I)
    if m:
        return float(m.group(1))
    m = re.search(r"(\d+(?:\.\d+)?)\s*lbs?\b", raw, re.I)
    return round(float(m.group(1)) * 0.4536, 2) if m else None


def watts(raw: str):
    m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(?:W\b|Watts?)", raw, re.I)
    return clean_number(num(m.group(1))) if m else None


def temp_c(raw: str):
    m = re.search(r"(-?\d+)\s*°?\s*C?\s*(?:to|–)\s*(-?\d+)\s*°\s*C|\(\s*(-?\d+)\s*°?\s*C?\s*to\s*(-?\d+)\s*°?\s*C\s*\)", raw)
    if not m:
        return None
    a, b = (m.group(1), m.group(2)) if m.group(1) is not None else (m.group(3), m.group(4))
    return [int(a), int(b)]


def rack_units(texts: list[str]):
    for t in texts:
        m = re.search(r"(\d)\s*(?:RU\b|U\b|U rack|Rack Units?)", t, re.I)
        if m:
            return int(m.group(1))
    return None


def for_model(raw: str, code: str) -> str:
    """Pick this model's part of a cell written as '4215: ... | 4245: ...'."""
    parts = re.split(r"\s*\|\s*(?=[\w/\-]+:\s)", raw)
    tagged = [(re.match(r"([\w/\-]+):\s*(.*)", p, re.S), p) for p in parts]
    if len(parts) < 2 or not all(m for m, _ in tagged):
        return raw
    for m, _ in tagged:
        if code and code.upper() in [x.upper() for x in m.group(1).split("/")]:
            return m.group(2)
    return raw


def derive_hardware(hw: dict, code: str = "") -> dict:
    out = {}
    f = {k: for_model(v["raw"], code) for k, v in hw.items() if isinstance(v, dict) and "raw" in v}
    if "dimensions" in f:
        d = dims_mm(f["dimensions"], hw["dimensions"]["label"])
        if d and all(d.values()) and d["h"] > d["w"] and d["h"] > d["d"]:
            # A firewall is never taller than it is wide or deep: the source printed
            # the numbers in a different order than its label says.
            d = {"h": d["w"], "w": d["h"], "d": d["d"]}
            out["dimensions_note"] = ("Source numbers do not follow the label's order "
                                      f"({hw['dimensions']['label']}); height and width swapped.")
        out["dimensions_mm"] = d
    ru = rack_units([f.get("form_factor", ""), f.get("rack_mount", "")])
    out["rack_units"] = ru
    ff = (f.get("form_factor") or "").lower()
    out["desktop"] = bool(re.search(r"compact|desktop|wall mount", ff)) if ff else None
    if "weight" in f:
        out["weight_kg"] = weight_kg(f["weight"])
    if "power_max" in f:
        out["power_max_w"] = watts(f["power_max"])
    if "power_load" in f:  # Meraki "Power load (idle/max)": 5W/14W
        m = re.search(r"(\d+(?:\.\d+)?)\s*W?\s*/\s*(\d+(?:\.\d+)?)\s*W", f["power_load"])
        if m:
            out["power_idle_w"] = clean_number(float(m.group(1)))
            out["power_max_w"] = clean_number(float(m.group(2)))
    if "power_load_with_poe" in f:
        m = re.search(r"/\s*(\d+(?:\.\d+)?)\s*W", f["power_load_with_poe"])
        if m:
            out["power_max_with_poe_w"] = clean_number(float(m.group(1)))
    if "power_typical" in f:
        out["power_typical_w"] = watts(f["power_typical"])
    if "psu_output_power" in f:
        out["psu_output_w"] = watts(f["psu_output_power"])
    if "operating_temp" in f:
        out["operating_temp_c"] = temp_c(f["operating_temp"])
    if "mtbf" in f:
        n = re.search(r"(\d[\d,]{4,})\s*hours", f["mtbf"], re.I)
        out["mtbf_hours"] = int(num(n.group(1))) if n else None
    for k in ("interfaces", "wan_interfaces", "convertible_interfaces", "transceiver_slots", "network_modules", "interfaces_max", "management_ports",
              "storage", "poe", "power_supply", "power_redundancy", "cooling", "noise"):
        if k in f:
            out[k] = f[k]
    return {k: v for k, v in out.items() if v is not None}


# ------------------------------------------------------------ table logic

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def unique_cells(cells: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in cells:
        if c["cid"] not in seen:
            seen.add(c["cid"])
            out.append(c)
    return out


def pick(cells: list[dict]) -> tuple[str, list[str], bool]:
    """Majority value across a model's columns. Returns text, markers, conflict."""
    texts = [c["text"] for c in cells if c["text"]]
    if not texts:
        return "", [], False
    best = Counter(texts).most_common(1)[0][0]
    markers = []
    for c in cells:
        if c["text"] == best:
            markers += [m for m in c["markers"] if m not in markers]
    return best, markers, len(set(texts)) > 1


def header_layout(t: dict, cfg: dict, all_models: list[str] | None):
    """Return (label_cols, header_row_index, data_start, column map, aux, title_markers)."""
    g = t["grid"]
    col_re = re.compile(cfg.get("column_re", DEFAULT_COLUMN_RE), re.I)
    aux_re = re.compile(cfg["aux_header_re"], re.I) if cfg.get("aux_header_re") else None
    width = len(g[0])
    hdr = None
    for i, row in enumerate(g[:3]):
        lc = row[0]["cs"]
        if lc < width and any(col_re.search(c["text"]) for c in unique_cells(row[lc:])):
            hdr = i
            break
    label_cols = g[hdr][0]["cs"] if hdr is not None else (g[0][0]["cs"] if g and g[0] else 1)
    if label_cols >= width:
        label_cols = 1
    value_cells = lambda row: unique_cells(row[label_cols:])
    title_markers = []
    if hdr is None:  # label | value table
        for c in g[0]:
            title_markers += c["markers"]
        return label_cols, 0, 1, None, {}, title_markers
    for row in g[:hdr]:
        for c in row:
            title_markers += [m for m in c["markers"] if m not in title_markers]
    colmap = []  # (models, span columns)
    for c in value_cells(g[hdr]):
        if not c["text"]:
            continue
        span = list(range(c["c0"], min(width, c["c0"] + c["cs"])))
        colmap.append((c["text"], span))
    start = hdr + 1
    aux = {}
    while start < len(g) and aux_re and (aux_re.search(g[start][0]["text"]) or g[start][0]["text"] == g[hdr][0]["text"]):
        aux_row = g[start]
        for text, span in colmap:
            aux[text] = aux_row[span[0]]["text"]
        start += 1
    return label_cols, hdr, start, colmap, aux, title_markers


def resolve_notes(markers, table_notes, global_notes) -> list[str]:
    out = []
    for m in markers:
        key = m.strip()
        txt = None
        if key.startswith("["):
            txt = global_notes.get(key) or table_notes.get(key.strip("[]"))
        else:
            txt = table_notes.get(key) or global_notes.get(f"[{key}]")
        if txt and txt not in out:
            out.append(txt)
    return out


def table_rows(t: dict, label_cols: int, start: int):
    """Yield (label, label_markers, row_cells_list) handling row-spanning label blocks."""
    g = t["grid"]
    r = start
    while r < len(g):
        row = g[r]
        labels = unique_cells(row[:label_cols])
        label = " / ".join(dict.fromkeys(c["text"].replace(" | ", " ") for c in labels if c["text"]))
        lmarks = [m for c in labels for m in c["markers"]]
        first = row[0]
        if label_cols == 1 and first["rs"] > 1 and first["r0"] == r:
            block = g[r:r + first["rs"]]
            yield label, lmarks, block
            r += first["rs"]
            continue
        if first["r0"] != r and label_cols == 1 and first["rs"] > 1:
            r += 1  # inside a block already yielded
            continue
        yield label, lmarks, [row]
        r += 1


class Builder:
    def __init__(self, labels: dict):
        self.labels = labels
        self.records: dict[str, dict] = {}
        self.order: list[str] = []
        self.unmapped: Counter = Counter()
        self.report: list[str] = []
        self.summaries: list = []

    # -- records
    def record(self, ds: str, cfg: dict, meta: dict, model: str, extra: dict | None = None) -> dict:
        printed = model
        for pat, repl in cfg.get("rename", []):
            model = re.sub(pat, repl, model)
        name = f"{cfg.get('model_prefix', '')}{model}".strip()
        mid = slug(name)
        if mid not in self.records:
            rec = {
                "vendor": "Cisco",
                "model": name,
                "model_id": mid,
                "family": cfg.get("family"),
                "series": cfg.get("series"),
                "form_factor": "virtual" if cfg.get("virtual") else "appliance",
                "source": {
                    "title": meta["title"],
                    "url": meta["url"],
                    "pdf_url": meta.get("pdf_url"),
                    "file": f"datasheets/{meta['file']}",
                    "library_last_updated": meta["updated"],
                    "sha256": meta.get("sha256"),
                },
                "default_image": None,
                "images": [],
                "specs_by_image": {},
                "other_by_image": {},
                "hardware": None if cfg.get("virtual") else {},
                "vm": None,
                "footnotes": {},
            }
            for rule in cfg.get("series_rules", []):
                if re.search(rule["re"], name):
                    rec["series"] = rule["series"]
                    break
            if cfg.get("virtual_re") and re.search(cfg["virtual_re"], name):
                rec["form_factor"] = "virtual"
                rec["hardware"] = None
                rec["vm"] = {"platform": None, "size": name.split()[-1]}
            if printed != model and cfg.get("rename"):
                rec["printed_as"] = printed
            note = (cfg.get("model_notes") or {}).get(printed)
            if note:
                rec["note"] = note
            if extra:
                rec.update(extra)
            self.records[mid] = rec
            self.order.append(mid)
        return self.records[mid]

    def map_label(self, kind: str, image: str | None, label: str):
        rules = self.labels["perf"].get(image or "ftd", []) if kind == "perf" else self.labels["hardware"]
        for rule in rules:
            if re.search(rule["re"], label, re.I):
                return rule
        return None

    # -- one datasheet
    def datasheet(self, path: Path, manifest: dict):
        ds = path.stem
        cfg = (self.labels.get("datasheets") or {}).get(ds) or {}
        if cfg.get("exclude"):
            self.report.append(f"{ds}: excluded in labels.yaml")
            return
        meta = extract(path)
        m = manifest.get(ds, {})
        meta["pdf_url"] = m.get("pdf_url")
        meta["sha256"] = m.get("sha256")
        ut = cfg.get("untitled_tables")
        if ut:
            col_re = re.compile(cfg.get("column_re", DEFAULT_COLUMN_RE), re.I)
            k = 0
            for t in meta["tables"]:
                g = t["grid"]
                if t["caption"] is None and g and any(col_re.search(c["text"]) for c in unique_cells(g[0][1:])):
                    k += 1
                    t["caption"] = f"Spec table {k} (uncaptioned)"
                    t["kind"], t["image"] = ut["kind"], ut.get("image")
        used = [t for t in meta["tables"] if t["kind"]]
        self.summaries.append((ds, cfg, meta, [t for t in meta["tables"] if is_summary(t)]))
        self.report.append(f"\n{ds}  ({meta['title']}, updated {meta['updated']})")
        if not used:
            self.report.append("  WARNING: no spec tables found")
        # model list: every model column across tables
        ds_models: list[str] = []
        for t in used:
            _, _, _, colmap, _, _ = header_layout(t, cfg, None)
            for text, _ in colmap or []:
                if not cfg.get("virtual"):
                    for mdl in (cfg.get("columns") or {}).get(text, [text]):
                        if mdl not in ds_models:
                            ds_models.append(mdl)
        for mdl in cfg.get("single_column_models", []):
            if mdl not in ds_models:
                ds_models.append(mdl)
        if not cfg.get("virtual"):
            for mdl in ds_models:
                self.record(ds, cfg, meta, mdl)
        for t in used:
            n = self.table(ds, cfg, meta, t, ds_models)
            self.report.append(f"  {t['kind']:8} {t['image'] or '-':4} {n:4} values  {t['caption'][:110]}")

    def table(self, ds, cfg, meta, t, ds_models) -> int:
        label_cols, hdr, start, colmap, aux, title_markers = header_layout(t, cfg, ds_models)
        kind, image = t["kind"], t["image"]
        tnotes, gnotes = t["footnotes"], meta["footnotes"]
        table_wide = resolve_notes(title_markers, tnotes, gnotes)
        table_ref = re.match(r"(Table \d+|Spec table \d+)", t["caption"] or "")
        table_ref = table_ref.group(1) if table_ref else t["caption"]
        software = None
        if kind in ("perf", "mixed"):
            software = IMAGE_NAMES.get(image, image)
            if t.get("software_note"):
                software += f", {t['software_note']}"

        # target models and their columns
        targets: list[tuple[dict, list[int] | None]] = []
        if colmap is None:
            scope = ds_models
            for rule in cfg.get("table_scope", []):
                if re.search(rule["caption"], t["caption"], re.I):
                    scope = rule["models"]
            for mdl in scope:
                targets.append((self.record(ds, cfg, meta, mdl), None))
        else:
            for text, span in colmap:
                if cfg.get("virtual"):
                    rec = self.virtual_record(ds, cfg, meta, t, text, aux.get(text))
                    targets.append((rec, span))
                else:
                    for mdl in (cfg.get("columns") or {}).get(text, [text]):
                        targets.append((self.record(ds, cfg, meta, mdl), span))

        count = 0
        feature_re = re.compile(self.labels.get("feature_rows", "^$"), re.I)
        for label, lmarks, rows in table_rows(t, label_cols, start):
            if not label:
                continue
            values = [c for r in rows for c in unique_cells(r[label_cols:])]
            if all((not c["text"]) or c["text"] == label for c in values):
                continue  # section heading or empty row
            block = len(rows) > 1
            nested = block and any(re.search(n, label, re.I) for n in cfg.get("nested_rows", []))
            row_kind = kind
            if kind == "mixed":
                rule = self.map_label("perf", image, label)
                row_kind = "perf"
                if rule is None:
                    rule = self.map_label("hardware", None, label)
                    row_kind = "hardware" if rule or not re.search(self.labels.get("feature_rows", "^$"), label, re.I) else "perf"
            else:
                rule = self.map_label(kind, image, label)
            only = re.search(r"\(([\w\-]+) models? only\)", label, re.I)
            for rec, span in targets:
                if only and span is None and not rec["model"].upper().endswith(only.group(1).upper()):
                    continue  # "(1220CX model only)" in a table shared by several models
                if block and span is not None and not nested:
                    # label spans several rows: join this model's value from each row
                    parts, marks, conflict = [], [], False
                    for r in rows:
                        txt, mk, cf = pick([r[i] for i in span if i < len(r)])
                        if txt and txt != label and txt not in parts:
                            parts.append(txt)
                        marks += mk
                        conflict = conflict or cf
                    raw = " | ".join(parts)
                elif block or span is None:
                    parts = []
                    for r in rows:
                        cells = [c for c in unique_cells(r[label_cols:]) if c["text"] and c["text"] != label]
                        txt = " | ".join(dict.fromkeys(c["text"] for c in cells))
                        if txt:
                            parts.append(txt)
                    raw = "; ".join(parts)
                    marks = [m for r in rows for c in unique_cells(r[label_cols:]) for m in c["markers"]]
                    conflict = False
                else:
                    raw, marks, conflict = pick([rows[0][i] for i in span if i < len(rows[0])])
                if not raw:
                    continue
                notes = resolve_notes(lmarks + marks, tnotes, gnotes)
                notes += [n for n in table_wide if n not in notes]
                if conflict:
                    notes.append("Source table columns disagree for this model; majority value used.")
                if rec.get("vm") is not None and re.search(r"cloud platforms", label, re.I):
                    rec["vm"]["platform"] = raw
                self.store(rec, row_kind, image, label, rule, raw, notes, table_ref, software, feature_re,
                           shared=span is None and len(targets) > 1)
                count += 1
            for rec, _ in targets:
                for mk in lmarks:
                    txt = resolve_notes([mk], tnotes, gnotes)
                    if txt:
                        rec["footnotes"][f"{table_ref} {mk}"] = txt[0]
        return count

    def virtual_record(self, ds, cfg, meta, t, col_text, aux_text):
        platform = t.get("platform") or "unknown"
        m = re.search(r"(\d+)\s*x\s*vCPU", col_text, re.I)
        vm = {"platform": platform, "vcpu": int(m.group(1)) if m else None,
              "instance_type": aux_text or None, "license_tier": None}
        if re.search(r"ASAv", col_text):
            name = re.search(r"ASAv[\w\-]*", col_text).group(0)
            tier = re.match(r"\s*([\d.]+\s*[MG])\b", col_text)
            vm["license_tier"] = tier.group(1).replace(" ", "") if tier else None
            label = f"{name} ({platform})"
        elif m:
            label = f"{m.group(1)} vCPU ({platform})"
        else:
            label = f"{col_text} ({platform})"
            vm["instance_type"] = vm["instance_type"] or col_text
        rec = self.record(ds, cfg, meta, label, {"vm": vm})
        if vm["instance_type"] and not rec["vm"].get("instance_type"):
            rec["vm"]["instance_type"] = vm["instance_type"]
        return rec

    def store(self, rec, kind, image, label, rule, raw, notes, table_ref, software, feature_re, shared=False):
        if kind == "hardware":
            hw = rec["hardware"] if rec["hardware"] is not None else rec.setdefault("hardware_raw", {})
            raw_d = hw.setdefault("raw", {})
            raw_d[label] = raw if label not in raw_d else f"{raw_d[label]} | {raw}"
            if rule:
                f = rule["field"]
                entry = {"raw": raw, "label": label, "table": table_ref, "notes": notes}
                if shared:
                    entry["shared"] = True  # from a table that covers several models with one value
                if f in hw and hw[f]["label"] == label and hw[f]["table"] == table_ref:
                    hw[f]["raw"] += f" | {raw}"
                elif f not in hw or (hw[f].get("shared") and not shared):
                    hw[f] = entry  # per-model tables win over shared feature tables
            elif not feature_re.search(label) and not re.search(self.labels.get("hardware_raw_only", "^$"), label, re.I):
                self.unmapped[f"hardware: {label}"] += 1
            return
        if image not in rec["images"]:
            rec["images"].append(image)
        if rule is None or rule.get("type") == "text" and feature_re.search(label):
            other = rec["other_by_image"].setdefault(image, {})
            other[label] = raw if label not in other else f"{other[label]} | {raw}"
            if rule is None and not feature_re.search(label):
                self.unmapped[f"{image}: {label}"] += 1
            return
        specs = rec["specs_by_image"].setdefault(image, {})
        f = rule["field"]
        if f in specs:
            if specs[f]["label"] == label and specs[f]["table"] == table_ref:
                specs[f]["raw"] += f" | {raw}"
            else:  # same field from another row/table: keep first, record the other
                rec["other_by_image"].setdefault(image, {})[label] = raw
            return
        value = parse_value(raw, rule["type"])
        entry = {"value": value, "raw": raw, "label": label, "table": table_ref,
                 "software": software, "notes": notes}
        if rule["type"] == "throughput":
            entry["unit"] = "Mbps"
        specs[f] = entry

    def finish(self):
        out = []
        for mid in self.order:
            rec = self.records[mid]
            if rec["hardware"] is not None:
                code = rec["model"].split()[-1]
                derived = derive_hardware(rec["hardware"], code)
                fields = {k: v for k, v in rec["hardware"].items() if k != "raw"}
                rec["hardware"] = {**derived, "fields": fields, "raw": rec["hardware"].get("raw", {})}
                if not fields and not rec["hardware"]["raw"]:
                    rec["hardware"] = None
            if "hardware_raw" in rec:  # hardware rows on a virtual datasheet
                rec.setdefault("other_by_image", {})["hardware"] = rec.pop("hardware_raw").get("raw", {})
            rec["default_image"] = "ftd" if "ftd" in rec["images"] else (rec["images"][0] if rec["images"] else None)
            rec["images"].sort(key=lambda i: 0 if i == "ftd" else 1)
            out.append(rec)
        series_order = list(dict.fromkeys(r["series"] for r in out))

        def natural(r):
            vm = r["vm"] or {}
            nums = [int(x) for x in re.findall(r"\d+", r["model"])]
            return (series_order.index(r["series"]), vm.get("platform") or "", vm.get("vcpu") or 0,
                    nums[:1] or [10 ** 9], r["model"])
        return sorted(out, key=natural)


# ------------------------------------------------------------ cross-check

# Summary table column -> (image, field). The summary tables at the top of some
# datasheets repeat a few headline numbers; comparing them with the detailed
# tables catches extraction errors (and Cisco's own inconsistencies).
SUMMARY_COLUMNS = [
    (r"^firewall", "asa", "fw_throughput_mbps"),
    (r"^throughput: threat defense", "ftd", "fw_avc_throughput_mbps"),
    (r"ngfw|fw\+avc\+ips|^threat defense$", "ftd", "ngfw_throughput_mbps"),
    (r"ips", "ftd", "ips_throughput_mbps"),
    (r"^tls", "ftd", "tls_throughput_mbps"),
]


def is_summary(t: dict) -> bool:
    g = t["grid"]
    if not g or not g[0]:
        return False
    first = g[0][0]["text"]
    cap = squash_l(t.get("caption") or "")
    return (t["caption"] is None and first == "Model") or "modelssummary" in cap or "specificationhighlights" in cap


def squash_l(s: str) -> str:
    return re.sub(r"\s+", "", s).lower()


def crosscheck(builder: "Builder") -> list[str]:
    lines, match, differ = [], 0, 0
    for ds, cfg, meta, tables in builder.summaries:
        for t in tables:
            g = t["grid"]
            hdr = [c["text"] for c in g[0]]
            for row in g[1:]:
                name = row[0]["text"]
                name = re.sub(r"^FPR-", "", name)
                name = {"SM-56 x 3": "3x SM-56"}.get(name, name)
                mid = slug(f"{cfg.get('model_prefix', '')}{name}")
                rec = builder.records.get(mid)
                if rec is None:
                    lines.append(f"  {ds}: summary model '{row[0]['text']}' not found in detailed tables")
                    continue
                for i, h in enumerate(hdr[1:], start=1):
                    for pat, img, field in SUMMARY_COLUMNS:
                        if re.search(pat, h, re.I):
                            sv = parse_throughput(row[i]["text"])
                            spec = rec["specs_by_image"].get(img, {}).get(field)
                            dv = spec["value"] if spec else None
                            if sv is None:
                                break
                            if dv == sv:
                                match += 1
                            else:
                                differ += 1
                                lines.append(f"  DIFF {rec['model']}: summary '{h}' = {row[i]['text']} vs {img} {field} = "
                                             f"{spec['raw'] if spec else 'missing'}")
                            break
    return [f"Summary tables vs detailed tables: {match} match, {differ} differ", *lines]


# ---------------------------------------------------------------- outputs

CSV_FIELDS = [
    ("fw_avc_throughput_mbps", "ftd"), ("ngfw_throughput_mbps", "ftd"), ("ips_throughput_mbps", "ftd"),
    ("avc_ips_throughput_mbps", "ftd"), ("tls_throughput_mbps", "ftd"), ("ipsec_throughput_mbps", None),
    ("fw_throughput_mbps", "asa"), ("fw_throughput_multiprotocol_mbps", "asa"),
    ("concurrent_sessions", None), ("new_sessions_per_sec", None), ("vpn_peers_max", None),
]


def write_outputs(records: list[dict], data: Path, reports: Path, builder: Builder):
    data.mkdir(parents=True, exist_ok=True)
    (data / "models").mkdir(exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    for old in (data / "models").glob("*.json"):
        if old.stem not in {r["model_id"] for r in records}:
            old.unlink()
    (data / "models.json").write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n")
    index = {}
    for r in records:
        (data / "models" / f"{r['model_id']}.json").write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n")
        index[r["model_id"]] = {"model": r["model"], "series": r["series"], "family": r["family"],
                                "form_factor": r["form_factor"], "images": r["images"],
                                "file": f"data/models/{r['model_id']}.json"}
    (data / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n")

    with open(data / "models.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        cols = [f for f, _ in CSV_FIELDS]
        w.writerow(["model_id", "model", "series", "form_factor", "image", "platform", *cols,
                    "rack_units", "power_max_w", "weight_kg", "source_updated"])
        for r in records:
            hw = r["hardware"] or {}
            for img in r["images"]:
                specs = r["specs_by_image"].get(img, {})
                row = [r["model_id"], r["model"], r["series"], r["form_factor"], img,
                       (r["vm"] or {}).get("platform", "")]
                for f, only in CSV_FIELDS:
                    v = specs.get(f, {}).get("value") if (only is None or only == img) else None
                    row.append("" if v is None else v)
                row += [hw.get("rack_units", ""), hw.get("power_max_w", ""), hw.get("weight_kg", ""),
                        r["source"]["library_last_updated"] or ""]
                w.writerow(row)

    lines = [f"{len(records)} models from {len({r['source']['file'] for r in records})} datasheets", *builder.report, ""]
    by_series = defaultdict(list)
    for r in records:
        by_series[r["series"]].append(r["model"])
    lines.append("Models by series:")
    for s, ms in by_series.items():
        lines.append(f"  {s}: {', '.join(ms)}")
    (reports / "extraction.txt").write_text("\n".join(lines) + "\n")
    (reports / "crosscheck.txt").write_text("\n".join(crosscheck(builder)) + "\n")
    un = sorted(builder.unmapped.items())
    (reports / "unmapped_labels.txt").write_text(
        (f"{len(un)} unmapped labels (kept under other_by_image / hardware.raw)\n" if un else "0 unmapped labels\n")
        + "".join(f"{k}  ({v} values)\n" for k, v in un))


def check(records: list[dict]) -> list[str]:
    problems = []
    if len(records) < 30:
        problems.append(f"only {len(records)} models")
    for r in records:
        if not r["specs_by_image"]:
            problems.append(f"{r['model']}: no performance specs")
        for img, specs in r["specs_by_image"].items():
            for f, s in specs.items():
                if f.endswith("_mbps") and s["value"] is None and s["raw"].strip().lower() not in NULLS:
                    problems.append(f"{r['model']} {img} {f}: could not parse '{s['raw']}'")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasheets", default="datasheets")
    ap.add_argument("--labels", default="labels.yaml")
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--data", default="data")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()

    labels = yaml.safe_load(Path(a.labels).read_text())
    manifest = json.loads(Path(a.manifest).read_text())["datasheets"] if Path(a.manifest).exists() else {}
    b = Builder(labels)
    for p in sorted(Path(a.datasheets).glob("*.html")):
        b.datasheet(p, manifest)
    records = b.finish()
    write_outputs(records, Path(a.data), Path(a.reports), b)
    print(f"{len(records)} models written to {a.data}/; {sum(b.unmapped.values())} unmapped values "
          f"({len(b.unmapped)} labels)")
    if a.check:
        problems = check(records)
        for p in problems:
            print(f"CHECK: {p}", file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
