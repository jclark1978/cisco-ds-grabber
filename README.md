# cisco-ds-grabber

Keeps a current local library of Cisco Secure Firewall datasheets and converts their spec tables to JSON, in the same record shape as [ds-grabber](https://github.com/jclark1978/ds-grabber) (Fortinet) and [palo-ds-grabber](https://github.com/jclark1978/palo-ds-grabber) (Palo Alto).

## What's covered

| Datasheet | Models | Converted |
|---|---|---|
| Secure Firewall 200 | 220, 240P | yes |
| Secure Firewall 1200 | 1210CE, 1210CP, 1220CX, 1230, 1240, 1250 | yes |
| Secure Firewall 3100 | 3105, 3110, 3120, 3130, 3140 | yes |
| Secure Firewall 4100 | 4112, 4115, 4125, 4145 | yes |
| Secure Firewall 4200 | 4215, 4225, 4245 | yes |
| Secure Firewall 6100 | 6120, 6130, 6160, 6170 | yes |
| Firepower 1000 | 1010, 1010E, 1120, 1140, 1150 | yes |
| Firepower 9300 | SM-40, SM-48, SM-56, 3x SM-56 | yes |
| Secure Firewall ISA3000 | ISA3000-2C2F, ISA3000-4C | yes |
| Threat Defense Virtual | 4 to 64 vCPU on ESXi/KVM/OpenStack, AWS, Azure, GCP, OCI, Alibaba | yes (`vm` records) |
| ASA Virtual | ASAv5 to ASAv100 and ASAv-U, per platform | yes (`vm` records) |
| Meraki MX | MX67, MX67W, MX67C, MX68, MX68W, MX68CW, MX75, MX85, MX95, MX105, MX250, MX450 | yes |
| Cisco 8000 Secure Routers running MX | C8110L, C8111, C8111-C, C8121, C8121-W, C8121-CW, C8235, C8355, C8455 (-G2-MX) | yes |
| Meraki vMX | Small, Medium, Large | yes (virtual) |
| Threat Defense Container | | downloaded only |

105 models. Meraki Z-Series teleworker gateways are not included (their current datasheets are on documentation.meraki.com in a different format). Whether a family is still sold isn't recorded; check Cisco's end-of-sale notices (Firepower 1000 and 4100 are older lines).

## What you get

```
datasheets/
  secure-firewall-3100.html   # the datasheet body as published (extractor input)
  pdf/secure-firewall-3100.pdf
  INDEX.md                    # title, Cisco's "Updated" date, links
  _archive/                   # previous versions
manifest.json                 # page URL, PDF URL, updated date, sha256
data/
  models.json                 # all records
  models/<model_id>.json      # one per model
  index.json                  # model_id -> summary
  models.csv                  # one row per model and software image
reports/
  extraction.txt              # tables read from each datasheet
  crosscheck.txt              # summary tables vs detailed tables
  unmapped_labels.txt
```

## Software images: read this before comparing

Cisco publishes separate numbers for each software image on the same hardware:

- **FTD** (Secure Firewall Threat Defense): the NGFW image. Throughput is "FW + AVC", "FW + AVC + IPS", "NGIPS", all at 1024B.
- **ASA**: the classic firewall image. Throughput is stateful inspection at 1500B UDP (or "multiprotocol").

- **MX** (Meraki MX firmware): Meraki MX, the Cisco 8000 Secure Routers sold as -MX models, and vMX. Meraki publishes firewall, advanced security services (IDS/AMP/Malware Analytics), site-to-site VPN throughput and VPN tunnels, with little test detail.

Records keep them apart in `specs_by_image.ftd`, `.asa` and `.mx`. The same field name in both images is not the same test (FTD IPsec is 1024B TCP with Fastpath; ASA IPsec is 450B UDP L2L). Every value keeps Cisco's printed `label`, the `software` it was measured on, the `table` it came from, and footnote text in `notes`. `default_image` is `ftd` when the model has FTD numbers. The 6120 and 6130 only have ASA numbers in Cisco's datasheet.

## Record shape

```json
{
  "vendor": "Cisco",
  "model": "Secure Firewall 3110",
  "model_id": "secure-firewall-3110",
  "family": "Secure Firewall",
  "series": "Secure Firewall 3100",
  "form_factor": "appliance",
  "source": {"title": "...", "url": "...", "pdf_url": "...", "file": "datasheets/secure-firewall-3100.html",
             "library_last_updated": "2026-10-06", "sha256": "..."},
  "default_image": "ftd",
  "images": ["ftd", "asa"],
  "specs_by_image": {
    "ftd": {"ngfw_throughput_mbps": {"value": 17000, "raw": "17.0 Gbps", "unit": "Mbps",
            "label": "Throughput: FW + AVC + IPS (1024B)", "table": "Table 2",
            "software": "Threat Defense (FTD)", "notes": []}},
    "asa": {"fw_throughput_mbps": {"value": 18000, "raw": "18.0 Gbps", "...": "..."}}
  },
  "other_by_image": {"ftd": {"Centralized management": "..."}},
  "hardware": {"rack_units": 1, "dimensions_mm": {"h": 44.0, "w": 433.0, "d": 508.0}, "weight_kg": 10.5,
               "psu_output_w": 400, "operating_temp_c": [0, 40], "interfaces": "...",
               "fields": {"...": {"raw": "...", "label": "...", "table": "Table 4"}}, "raw": {"Label": "text"}},
  "vm": null,
  "footnotes": {"Table 2 1": "Throughput measured with 50% TLS 1.2 traffic ..."}
}
```

Meraki fields (`mx`): `fw_throughput_mbps`, `ngfw_throughput_mbps` (vMX prints "NGFW"), `advanced_security_throughput_mbps`, `ipsec_throughput_mbps` (site-to-site VPN), `vpn_tunnels_max`, `recommended_use`. Meraki hardware adds `wan_interfaces`, `convertible_interfaces`, `power_idle_w`, `power_max_with_poe_w`.

Virtual records have `form_factor: "virtual"`, `hardware: null` and `vm: {platform, vcpu, instance_type, license_tier}`.

Fields: FTD `fw_avc_throughput_mbps`, `ngfw_throughput_mbps`, `ips_throughput_mbps`, `avc_ips_throughput_mbps`, `tls_throughput_mbps`, `ipsec_throughput_mbps`, `ipsec_throughput_projected_mbps`, `concurrent_sessions`, `new_sessions_per_sec`, `vpn_peers_max`, `vrf_max`, `instances_max`, plus HA/clustering text. ASA `fw_throughput_mbps`, `fw_throughput_multiprotocol_mbps`, `ipsec_throughput_mbps`, `concurrent_sessions`, `new_sessions_per_sec`, `vpn_peers_max`, `security_contexts {included, max}`, `fw_latency_us`, and for ASAv `ravpn_sessions_max`, `vlans_max`, `vcpu`, `memory`. Mapping lives in `labels.yaml`.

## Run it locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python cisco_grabber.py --list-only    # preview
python cisco_grabber.py                # download
python cisco_normalize.py --check      # convert
python cisco_extract.py datasheets/secure-firewall-3100.html   # see the raw tables
```

## How it works

1. **Discover** (`sources.yaml`): read the Secure Firewall hub page and each family page it links, the datasheet-listing pages of older lines, and a few extra pages. Keep links to `/c/en/us/products/collateral/security/...-ds.html` or `datasheet-c78-*.html`.
2. **Save**: store the datasheet body (`#eot-doc-wrapper`) with scripts and volatile attributes stripped, so a rerun only changes files when Cisco changes the datasheet. The PDF is downloaded alongside. Replaced versions move to `_archive/`.
3. **Extract** (`cisco_extract.py`): captioned HTML tables become span-aware grids (each cell knows the source cell it came from), with superscript markers split out. Plain-number footnotes belong to the table just before them; bracketed `[n]` notes are document-wide.
4. **Normalize** (`cisco_normalize.py` + `labels.yaml`): find the model header row, map labels to fields, parse units, attach footnotes, derive hardware fields, cross-check against the summary tables.

Quirks handled: model columns covering several models ("1010 / 1010E", the 1200's "1210" = 1210CE and 1210CP), header cells spanning extra empty columns, labels spanning several rows (joined per model), a small table nested inside the 6100's interface row, one cell listing several models' weights, "(1220CX model only)" rows, a misaligned header in the 1200 1U hardware table (majority value used, flagged in `notes`), and Meraki's uncaptioned tables that mix performance and hardware rows. The C8110L-G2-MX dimensions are printed in a different order than their "w x d x h" label; height and width are swapped and `hardware.dimensions_note` says so.

Known source inconsistency: the 1200 summary table's "Firewall Throughput" and "IPS" columns disagree with the detailed tables for 1220CX, 1230, 1240 and 1250 (`reports/crosscheck.txt`). The detailed tables are used.

## Cisco's CDN

Cisco's CDN blocks some clients: a browser user agent sent without matching browser headers gets HTTP 403. The grabber sends a descriptive user agent with this repo's URL, which is accepted. If the GitHub Action starts failing with 403 (the CDN may also judge by IP range), run the grabber locally and commit.

## GitHub Actions

`.github/workflows/grab.yml` runs every Monday: download, convert with `--check`, commit only on change. Run it by hand from the **Actions** tab.
