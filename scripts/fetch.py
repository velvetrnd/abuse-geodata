#!/usr/bin/env python3
"""
fetch.py – downloads all sources defined in sources/*.yml
and normalizes them to plain IP/domain lists in data/

Output structure:
  data/category-sinkhole-ip.txt
  data/category-malware-c2-ip.txt
  data/category-malware-c2-domain.txt
  ...
"""

import csv
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from io import StringIO
from pathlib import Path

import yaml

SOURCES_DIR = Path(__file__).parent.parent / "sources"
DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9\-]{1,63}(?<!-)(\.[a-zA-Z0-9\-]{1,63})+$")

FETCH_RETRIES = 3
FETCH_RETRY_DELAY = 5
MAX_RESPONSE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_SCHEMES = ("https://", "http://")


def _safe_path(base: Path, untrusted: str) -> Path:
    resolved = (base / untrusted).resolve()
    if not resolved.is_relative_to(base.resolve()):
        raise ValueError(f"path traversal blocked: {untrusted}")
    return resolved


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_domain(s: str) -> bool:
    return bool(DOMAIN_RE.match(s)) and ".." not in s


def extract_domain_from_url(raw: str) -> str | None:
    # strip scheme
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", "", raw)
    # strip path, query, fragment
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    # strip port – but only if not an IPv6 address (wrapped in [])
    if raw.startswith("["):
        return None
    raw = raw.split(":")[0]
    return raw if is_valid_domain(raw) else None


def fetch_url(url: str) -> str | None:
    if not any(url.startswith(s) for s in ALLOWED_SCHEMES):
        print(f"  ERROR: blocked URL scheme: {url}", file=sys.stderr)
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "abuse-geodata/1.0"})
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            print(f"  fetching {url} (attempt {attempt})")
            with urllib.request.urlopen(req, timeout=30) as resp:
                chunks = []
                total = 0
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_RESPONSE_SIZE:
                        print(f"  ERROR: response too large (>{MAX_RESPONSE_SIZE} bytes): {url}", file=sys.stderr)
                        return None
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"  WARN attempt {attempt}/{FETCH_RETRIES}: {e}", file=sys.stderr)
            if attempt < FETCH_RETRIES:
                time.sleep(FETCH_RETRY_DELAY)
    print(f"  ERROR: all {FETCH_RETRIES} attempts failed for {url}", file=sys.stderr)
    return None


def parse_text(
    content: str,
    comment_char: str = "#",
    extract: str = None,
    field: int = 0,
    separator: str = None,
) -> list[str]:
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        if comment_char in line:
            line = line[: line.index(comment_char)].strip()
        if not line:
            continue
        parts = line.split(separator)
        if field >= len(parts):
            print(f"  WARN: field {field} out of range in line: {line!r}", file=sys.stderr)
            continue
        token = parts[field]

        if extract == "domain":
            domain = extract_domain_from_url(token)
            if domain:
                results.append(domain)
        else:
            results.append(token)
    return results


def parse_csv(
    content: str, column: str, extract: str = None,
    filter_column: str = None, filter_value: str = None,
) -> list[str]:
    results = []
    lines = content.splitlines()
    header = None
    data_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("# ").strip()
            if candidate.startswith('"') and column in candidate:
                header = candidate
            continue
        data_lines.append(line)
    csv_text = (header + "\n" if header else "") + "\n".join(data_lines)
    reader = csv.DictReader(StringIO(csv_text))
    for row in reader:
        if column not in row:
            continue
        if filter_column and row.get(filter_column, "").strip().strip('"') != filter_value:
            continue
        token = row[column].strip().strip('"')
        if extract == "domain":
            domain = extract_domain_from_url(token)
            if domain:
                results.append(domain)
        elif extract == "ip_from_port":
            ip = token.rsplit(":", 1)[0]
            results.append(ip)
        else:
            results.append(token)
    return results


def parse_hosts(content: str, filter_re: str = None) -> list[str]:
    results = []
    pat = re.compile(filter_re, re.IGNORECASE) if filter_re else None
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1]
            if domain in ("localhost", "localhost.localdomain", "broadcasthost"):
                continue
            if pat and not pat.search(domain):
                continue
            if is_valid_domain(domain):
                results.append(domain)
    return results


def classify(
    entries: list[str], type_override: str = None
) -> tuple[list[str], list[str]]:
    ips, domains = [], []
    for entry in entries:
        if type_override == "ip":
            if is_valid_ip(entry):
                ips.append(entry)
        elif type_override == "domain":
            if is_valid_domain(entry):
                domains.append(entry)
        else:
            if is_valid_ip(entry):
                ips.append(entry)
            elif is_valid_domain(entry):
                domains.append(entry)
    return ips, domains


def sort_ips(ips: list[str]) -> list[str]:
    def key(s: str):
        try:
            net = ipaddress.ip_network(s, strict=False)
            return (net.version, net.network_address, net.prefixlen)
        except ValueError:
            return (0, ipaddress.ip_address("0.0.0.0"), 0)

    return sorted(ips, key=key)


def load_local(path: Path) -> str | None:
    if not path.exists():
        print(f"  ERROR: local file not found: {path}", file=sys.stderr)
        return None
    return path.read_text(encoding="utf-8")


def process_source(src: dict) -> tuple[list[str], list[str]]:
    fmt = src.get("format", "text")

    if fmt == "local":
        url = src["url"]
        filename = url.removeprefix("local://")
        content = load_local(_safe_path(SOURCES_DIR, filename))
    else:
        content = fetch_url(src["url"])

    if content is None:
        return [], []

    extract = src.get("extract")
    type_override = src.get("type_override")
    comment_char = src.get("comment_char", "#")
    field = int(src.get("field", 0))
    separator = src.get("separator")
    filter_re = src.get("filter")

    if fmt in ("text", "local"):
        entries = parse_text(
            content, comment_char=comment_char, extract=extract, field=field,
            separator=separator,
        )
    elif fmt == "csv":
        entries = parse_csv(
            content, column=src["column"], extract=extract,
            filter_column=src.get("filter_column"),
            filter_value=src.get("filter_value"),
        )
    elif fmt == "hosts":
        entries = parse_hosts(content, filter_re=filter_re)
    else:
        print(f"  WARN: unknown format '{fmt}'", file=sys.stderr)
        entries = []

    return classify(entries, type_override=type_override)


def process_category(path: Path) -> tuple[str, int]:
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"  ERROR: failed to parse {path.name}: {e}", file=sys.stderr)
        return path.stem, 0

    name = cfg["name"]
    if "/" in name or "\\" in name or ".." in name:
        print(f"  ERROR: invalid category name: {name}", file=sys.stderr)
        return path.stem, 0
    cat_type = cfg.get("type", "mixed")
    print(f"\n[{name}]")

    all_ips: set[str] = set()
    all_domains: set[str] = set()

    for src in cfg.get("sources", []):
        src_name = src.get("name", src["url"])
        print(f"  source: {src_name}")
        ips, domains = process_source(src)
        print(f"    +{len(ips)} IPs, +{len(domains)} domains")
        all_ips.update(ips)
        all_domains.update(domains)

    exclude_file = cfg.get("exclude_from")
    if exclude_file:
        exc_path = _safe_path(SOURCES_DIR, exclude_file)
        exc_content = load_local(exc_path)
        if exc_content:
            exc_entries = set(parse_text(exc_content))
            before = len(all_ips) + len(all_domains)
            all_ips -= exc_entries
            all_domains -= exc_entries
            excluded = before - len(all_ips) - len(all_domains)
            if excluded:
                print(f"  excluded {excluded} entries via {exclude_file}")

    if all_ips and cat_type in ("ip", "mixed"):
        out = DATA_DIR / f"{name}-ip.txt"
        out.write_text("\n".join(sort_ips(list(all_ips))) + "\n", encoding="utf-8")
        print(f"  wrote {len(all_ips)} IPs → {out.name}")

    if all_domains and cat_type in ("domain", "mixed"):
        out = DATA_DIR / f"{name}-domain.txt"
        out.write_text("\n".join(sorted(all_domains)) + "\n", encoding="utf-8")
        print(f"  wrote {len(all_domains)} domains → {out.name}")

    return name, len(all_ips) + len(all_domains)


STALE_THRESHOLD = 3
STATUS_FILE = DATA_DIR / ".fetch-status.json"


def load_status() -> dict:
    if STATUS_FILE.exists():
        try:
            return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_status(status: dict) -> None:
    STATUS_FILE.write_text(json.dumps(status, indent=2), encoding="utf-8")


def check_stale(status: dict) -> None:
    stale = {k: v for k, v in status.items() if v >= STALE_THRESHOLD}
    if not stale:
        return
    print(f"\n{'=' * 60}", file=sys.stderr)
    print("WARNING: the following categories returned 0 entries", file=sys.stderr)
    print(f"for {STALE_THRESHOLD}+ consecutive runs. Sources may be dead.", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)
    for name, days in sorted(stale.items()):
        print(f"  {name}: {days} consecutive empty fetches", file=sys.stderr)


def main():
    yml_files = sorted(SOURCES_DIR.glob("category-*.yml"))
    if not yml_files:
        print("No source files found in sources/", file=sys.stderr)
        sys.exit(1)

    status = load_status()

    for path in yml_files:
        name, total = process_category(path)
        if total > 0:
            status[name] = 0
        else:
            status[name] = status.get(name, 0) + 1

    active = {path.stem for path in yml_files}
    status = {k: v for k, v in status.items() if k in active}

    save_status(status)
    check_stale(status)

    print("\nDone.")


if __name__ == "__main__":
    main()
