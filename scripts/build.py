#!/usr/bin/env python3
"""
build.py – builds all output formats from normalized data/ txt files.

Requires:
  - geoip builder binary:  ./tools/geoip   (Loyalsoldier/geoip)
  - sing-box binary:       ./tools/sing-box

Outputs to output/:
  geoip.dat
  geosite.dat
  geoip.db          (MaxMind mmdb for sing-box)
  srs/category-*.srs
  txt/category-*.txt  (copies of normalized lists)
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
SOURCES_DIR = ROOT / "sources"
OUTPUT_DIR = ROOT / "output"
TOOLS_DIR = ROOT / "tools"
SRS_DIR = OUTPUT_DIR / "srs"
TXT_DIR = OUTPUT_DIR / "txt"

for d in (OUTPUT_DIR, SRS_DIR, TXT_DIR):
    d.mkdir(parents=True, exist_ok=True)


def run(cmd: list, cwd=None, check=True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def load_categories() -> list[dict]:
    cats = []
    for path in sorted(SOURCES_DIR.glob("category-*.yml")):
        with open(path, encoding="utf-8") as f:
            cats.append(yaml.safe_load(f))
    return cats


def tag_name(category_name: str) -> str:
    """
    Preserve full category name as tag so Xray config matches:
      geoip:category-sinkhole  →  tag = CATEGORY-SINKHOLE
    Loyalsoldier/geoip stores tags case-insensitively; Xray lookups
    are also case-insensitive, so CATEGORY-SINKHOLE matches category-sinkhole.
    """
    return category_name.upper()


def copy_txt(cats: list[dict]) -> None:
    print("\n[txt] copying normalized lists")
    for f in DATA_DIR.glob("category-*.txt"):
        dst = TXT_DIR / f.name
        shutil.copy2(f, dst)
        print(f"  {f.name}")


def build_geodat(
    cats: list[dict],
    data_type: str,          # "ip" or "domain"
    output_type: str,        # "v2rayGeoIPDat" or "v2rayGeositeDat"
    output_name: str,        # "geoip.dat" or "geosite.dat"
    extra_outputs: list[dict] | None = None,
) -> None:
    """
    Generic builder for geoip.dat and geosite.dat via Loyalsoldier/geoip tool.

    For domain entries the tool expects one domain per line with optional
    attribute prefixes (full:, domain:, keyword:, regexp:).
    Plain domain names are treated as 'domain:' match by default.
    """
    label = output_name
    print(f"\n[{label}] building")

    geoip_bin = TOOLS_DIR / "geoip"
    if not geoip_bin.exists():
        print(f"  SKIP: tools/geoip not found", file=sys.stderr)
        return

    type_filter = ("ip", "mixed") if data_type == "ip" else ("domain", "mixed")
    suffix = f"-{data_type}.txt"

    config: dict = {"input": [], "output": []}

    for cat in cats:
        if cat.get("type", "mixed") not in type_filter:
            continue
        name = cat["name"]
        txt = DATA_DIR / f"{name}{suffix}"
        if not txt.exists():
            continue
        config["input"].append({
            "type": "text",
            "action": "add",
            "args": {
                "name": tag_name(name),
                "uri": str(txt),
            },
        })

    if not config["input"]:
        print(f"  SKIP: no input files found for {label}", file=sys.stderr)
        return

    config["output"].append({
        "type": output_type,
        "action": "output",
        "args": {"outputDir": str(OUTPUT_DIR), "outputName": output_name},
    })
    for extra in (extra_outputs or []):
        config["output"].append(extra)

    cfg_path = OUTPUT_DIR / f"{output_name}-config.json"
    cfg_path.write_text(json.dumps(config, indent=2))

    result = run([str(geoip_bin), "convert", "--config", str(cfg_path)], cwd=ROOT, check=False)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr}", file=sys.stderr)
    else:
        out_files = [output_name] + [e["args"]["outputName"] for e in (extra_outputs or [])]
        print(f"  OK → {', '.join('output/' + f for f in out_files)}")


def build_geosite(cats: list[dict]) -> None:
    print("\n[geosite.dat] building")
    dlc_bin = TOOLS_DIR / "dlc"
    if not dlc_bin.exists():
        print("  SKIP: tools/dlc not found", file=sys.stderr)
        return

    type_filter = ("domain", "mixed")
    with tempfile.TemporaryDirectory() as tmpdir:
        datadir = Path(tmpdir)
        found = False
        for cat in cats:
            if cat.get("type", "mixed") not in type_filter:
                continue
            name = cat["name"]
            txt = DATA_DIR / f"{name}-domain.txt"
            if not txt.exists():
                continue
            shutil.copy2(txt, datadir / name)
            found = True

        if not found:
            print("  SKIP: no domain files found", file=sys.stderr)
            return

        result = run(
            [str(dlc_bin),
             "--datapath", str(datadir),
             "--outputdir", str(OUTPUT_DIR),
             "--outputname", "geosite.dat"],
            check=False,
        )
        if result.returncode != 0:
            print(f"  ERROR: {result.stderr}", file=sys.stderr)
        else:
            print("  OK → output/geosite.dat")


def build_srs(cats: list[dict]) -> None:
    """
    Build sing-box rule-set (.srs) files.
    One .srs per category per type (ip / domain).
    Also builds bundle-strict and bundle-full aggregates.
    """
    print("\n[srs] building sing-box rule-sets")
    singbox_bin = TOOLS_DIR / "sing-box"
    if not singbox_bin.exists():
        print("  SKIP: tools/sing-box not found", file=sys.stderr)
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        bundle_strict_ip: set[str] = set()
        bundle_strict_domain: set[str] = set()
        bundle_full_ip: set[str] = set()
        bundle_full_domain: set[str] = set()

        for cat in cats:
            name = cat["name"]
            flags = cat.get("flags", {})
            is_noisy = any(
                flags.get(k, {}).get("value", False)
                for k in ("high_false_positive", "large_dataset")
            )

            for suffix, rule_key in (("-ip", "ip_cidr"), ("-domain", "domain")):
                txt = DATA_DIR / f"{name}{suffix}.txt"
                if not txt.exists():
                    continue

                entries = {
                    line.strip()
                    for line in txt.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                }
                if not entries:
                    continue

                if rule_key == "ip_cidr":
                    bundle_full_ip.update(entries)
                    if not is_noisy:
                        bundle_strict_ip.update(entries)
                else:
                    bundle_full_domain.update(entries)
                    if not is_noisy:
                        bundle_strict_domain.update(entries)

                _compile_srs(
                    singbox_bin, tmp,
                    srs_name=f"{name}{suffix}",
                    rule_key=rule_key,
                    entries=entries,
                )

        for bundle_suffix, ips, domains in (
            ("-strict", bundle_strict_ip, bundle_strict_domain),
            ("-full", bundle_full_ip, bundle_full_domain),
        ):
            for entries, rule_key, ext in (
                (ips, "ip_cidr", "ip"),
                (domains, "domain", "domain"),
            ):
                if not entries:
                    continue
                _compile_srs(
                    singbox_bin, tmp,
                    srs_name=f"category-bundle{bundle_suffix}-{ext}",
                    rule_key=rule_key,
                    entries=entries,
                )


def _compile_srs(
    singbox_bin: Path,
    tmp: Path,
    srs_name: str,
    rule_key: str,
    entries: set[str],
) -> None:
    json_path = tmp / f"{srs_name}.json"
    srs_path = SRS_DIR / f"{srs_name}.srs"

    json_path.write_text(json.dumps({
        "version": 1,
        "rules": [{rule_key: sorted(entries)}],
    }, indent=2))

    result = run(
        [str(singbox_bin), "rule-set", "compile", str(json_path), "-o", str(srs_path)],
        check=False,
    )
    if result.returncode != 0:
        print(f"  ERROR {srs_name}: {result.stderr}", file=sys.stderr)
    else:
        print(f"  OK → srs/{srs_name}.srs ({len(entries)} entries)")


def verify_outputs() -> bool:
    required = [
        OUTPUT_DIR / "geoip.dat",
        OUTPUT_DIR / "geosite.dat",
    ]
    missing = [f for f in required if not f.exists()]
    if missing:
        print("\nERROR: required output files missing:", file=sys.stderr)
        for f in missing:
            print(f"  {f}", file=sys.stderr)
        return False
    return True


def main():
    cats = load_categories()
    copy_txt(cats)

    build_geodat(
        cats,
        data_type="ip",
        output_type="v2rayGeoIPDat",
        output_name="geoip.dat",
        extra_outputs=[{
            "type": "maxmindMMDB",
            "action": "output",
            "args": {"outputDir": str(OUTPUT_DIR), "outputName": "geoip.db"},
        }],
    )

    build_geosite(cats)

    build_srs(cats)

    if not verify_outputs():
        sys.exit(1)

    print("\nBuild complete.")


if __name__ == "__main__":
    main()
