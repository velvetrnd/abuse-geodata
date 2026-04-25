# abuse-geodata

Automated threat intelligence aggregation pipeline. Collects public abuse feeds daily, normalizes them, and builds output files for Xray, sing-box, and ipset/iptables.

## Architecture

```
sources/*.yml → fetch.py → data/*-{ip,domain}.txt → build.py → output/
```

- `sources/*.yml` — declarative category configs with feed URLs, formats, parsing rules
- `scripts/fetch.py` — downloads feeds, normalizes to plain IP/domain lists into `data/`
- `scripts/build.py` — builds output formats from normalized data into `output/`
- `.github/workflows/build.yml` — daily CI at 03:00 UTC, creates timestamped GitHub Release

## Output formats

- `geoip.dat`, `geosite.dat` — Xray/V2Ray routing (built via Loyalsoldier/geoip binary)
- `geoip.db` — sing-box MMDB
- `srs/*.srs` — sing-box rule-sets (per-category + bundles)
- `txt/*.txt` — plain text IP/domain lists for ipset/iptables/hosts

## Bundles

- `bundle-strict` — only categories without `high_false_positive` or `large_dataset` flags
- `bundle-full` — all categories

## Categories (8)

| Category | Type | Flags | Sources |
|---|---|---|---|
| sinkhole | ip | — | brakmic/Sinkholes |
| malware-c2 | mixed | — | Feodo Tracker, ET, URLhaus |
| tor-exit | ip | controversial | Tor Project |
| spam | ip | — | Spamhaus DROP/EDROP |
| dga | domain | high_fp, volatile, large | Bambenek |
| brute-force | ip | volatile | blocklist.de |
| cryptojacking | mixed | — | NiceHash |
| phishing | domain | volatile | OpenPhish, PhishTank |

## Dependencies

- Python 3.12 + PyYAML
- `tools/geoip` — Loyalsoldier/geoip (auto-downloaded in CI)
- `tools/sing-box` — sing-box CLI (auto-downloaded in CI)

## Local build

```bash
pip install pyyaml
python scripts/fetch.py
python scripts/build.py
```

Requires `tools/geoip` and `tools/sing-box` binaries in `tools/`.

## Adding a category

1. Create `sources/category-{name}.yml` with name, description, type, flags, sources
2. fetch.py and build.py pick it up automatically via glob
