#!/usr/bin/env python3
"""
test.py – validates built output files.

Checks:
  - All expected files exist and are non-empty
  - txt files contain only valid IPs or domains
  - srs files decompile successfully (sing-box)
  - geoip.db has valid MMDB structure
  - geoip.dat / geosite.dat have minimum size
  - Every source category produced expected outputs
"""

import ipaddress
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent.parent
SOURCES_DIR = ROOT / "sources"
OUTPUT_DIR = ROOT / "output"
TOOLS_DIR = ROOT / "tools"
DATA_DIR = ROOT / "data"
SRS_DIR = OUTPUT_DIR / "srs"
TXT_DIR = OUTPUT_DIR / "txt"

DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9\-]{1,63}(?<!-)(\.[a-zA-Z0-9\-]{1,63})+$")

MIN_DAT_SIZE = 1024
MIN_MMDB_SIZE = 256

errors: list[str] = []
warnings: list[str] = []


def error(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"  WARN: {msg}", file=sys.stderr)


def check_file_exists(path: Path, min_size: int = 1) -> bool:
    if not path.exists():
        error(f"{path.relative_to(ROOT)} missing")
        return False
    size = path.stat().st_size
    if size < min_size:
        error(f"{path.relative_to(ROOT)} too small ({size} bytes, expected >= {min_size})")
        return False
    return True


def load_categories() -> list[dict]:
    cats = []
    for path in sorted(SOURCES_DIR.glob("category-*.yml")):
        with open(path, encoding="utf-8") as f:
            cats.append(yaml.safe_load(f))
    return cats


def validate_txt_files() -> None:
    print("\n[txt] validating text lists")
    for txt in sorted(TXT_DIR.glob("abuse-category-*.txt")):
        name = txt.stem
        is_ip = name.endswith("-ip")
        lines = [line.strip() for line in txt.read_text(encoding="utf-8").splitlines() if line.strip()]

        if not lines:
            error(f"txt/{txt.name} is empty")
            continue

        bad = 0
        for line in lines:
            if is_ip:
                try:
                    ipaddress.ip_network(line, strict=False)
                except ValueError:
                    bad += 1
            else:
                if not DOMAIN_RE.match(line):
                    bad += 1

        if bad > 0:
            pct = bad / len(lines) * 100
            if pct > 5:
                error(f"txt/{txt.name}: {bad}/{len(lines)} ({pct:.1f}%) invalid entries")
            else:
                warn(f"txt/{txt.name}: {bad}/{len(lines)} ({pct:.1f}%) invalid entries")
        else:
            print(f"  OK txt/{txt.name}: {len(lines)} entries")


def validate_srs_files() -> None:
    print("\n[srs] validating sing-box rule-sets")
    singbox = TOOLS_DIR / "sing-box"
    if not singbox.exists():
        warn("tools/sing-box not found, skipping .srs validation")
        return

    for srs in sorted(SRS_DIR.glob("*.srs")):
        if not check_file_exists(srs):
            continue
        result = subprocess.run(
            [str(singbox), "rule-set", "decompile", str(srs)],
            capture_output=True, text=True,
        )
        json_out = srs.with_suffix(".json")
        if result.returncode != 0:
            error(f"srs/{srs.name} failed to decompile: {result.stderr.strip()}")
        else:
            if json_out.exists():
                try:
                    data = json.loads(json_out.read_text())
                    rules = data.get("rules", [])
                    total = sum(len(r.get("ip_cidr", [])) + len(r.get("domain", [])) for r in rules)
                    print(f"  OK srs/{srs.name}: {total} entries")
                except (json.JSONDecodeError, KeyError):
                    warn(f"srs/{srs.name} decompiled but JSON is unexpected")
                finally:
                    json_out.unlink(missing_ok=True)
            else:
                print(f"  OK srs/{srs.name}: decompiled successfully")


def validate_mmdb() -> None:
    print("\n[mmdb] validating geoip.db")
    mmdb = OUTPUT_DIR / "abuse-geoip.db"
    if not check_file_exists(mmdb, MIN_MMDB_SIZE):
        return

    data = mmdb.read_bytes()
    marker = b"\xab\xcd\xefMaxMind.com"
    if marker not in data:
        error("geoip.db: MMDB metadata marker not found")
        return

    idx = data.rfind(marker)
    meta_start = idx + len(marker)
    if meta_start + 20 > len(data):
        error("geoip.db: MMDB metadata too short")
        return

    print(f"  OK abuse-geoip.db: {len(data):,} bytes, MMDB structure valid")


def validate_dat_files() -> None:
    print("\n[dat] validating .dat files")
    for name in ("abuse-geoip.dat", "abuse-geosite.dat"):
        path = OUTPUT_DIR / name
        if check_file_exists(path, MIN_DAT_SIZE):
            size = path.stat().st_size
            print(f"  OK {name}: {size:,} bytes")


def validate_category_coverage(cats: list[dict]) -> None:
    print("\n[coverage] checking category outputs")
    for cat in cats:
        name = cat["name"]
        cat_type = cat.get("type", "mixed")

        if cat_type in ("ip", "mixed"):
            ip_txt = TXT_DIR / f"abuse-{name}-ip.txt"
            ip_srs = SRS_DIR / f"abuse-{name}-ip.srs"
            if not ip_txt.exists():
                warn(f"{name}: no IP output (txt)")
            elif not ip_srs.exists():
                warn(f"{name}: has IP txt but no .srs")

        if cat_type in ("domain", "mixed"):
            dom_txt = TXT_DIR / f"abuse-{name}-domain.txt"
            dom_srs = SRS_DIR / f"abuse-{name}-domain.srs"
            if not dom_txt.exists():
                warn(f"{name}: no domain output (txt)")
            elif not dom_srs.exists():
                warn(f"{name}: has domain txt but no .srs")


def validate_consistency() -> None:
    print("\n[consistency] cross-checking txt ↔ srs entry counts")
    for txt in sorted(TXT_DIR.glob("abuse-category-*.txt")):
        srs = SRS_DIR / f"{txt.stem}.srs"
        if not srs.exists():
            continue
        txt_count = sum(1 for line in txt.read_text().splitlines() if line.strip())
        srs_size = srs.stat().st_size
        if txt_count > 100 and srs_size < 100:
            warn(f"{txt.stem}: {txt_count} txt entries but .srs only {srs_size} bytes")
        else:
            print(f"  OK {txt.stem}: {txt_count} entries, srs {srs_size:,} bytes")


def main():
    cats = load_categories()

    validate_dat_files()
    validate_mmdb()
    validate_txt_files()
    validate_srs_files()
    validate_category_coverage(cats)
    validate_consistency()

    print(f"\n{'=' * 50}")
    if errors:
        print(f"FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        for e in errors:
            print(f"  ✗ {e}")
        for w in warnings:
            print(f"  ! {w}")
        sys.exit(1)
    elif warnings:
        print(f"PASSED with {len(warnings)} warning(s)")
        for w in warnings:
            print(f"  ! {w}")
    else:
        print("PASSED: all checks OK")


if __name__ == "__main__":
    main()
