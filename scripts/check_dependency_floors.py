#!/usr/bin/env python3
"""Fail-closed floor check for known ORES-OTEL RustSec advisories.

This is not a replacement for the mandatory cargo audit --deny warnings gate.
"""
from __future__ import annotations
import argparse
import re
import sys
import tomllib
from pathlib import Path

VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
MINIMUMS = {
    "rmcp": (3, 9, 0),
    "quinn-proto": (0, 11, 19),
    "rustls": (0, 23, 46),
    "rustls-webpki": (0, 103, 16),
}

def parse_version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise ValueError(f"non-string version {value!r}")
    match = VERSION.fullmatch(value)
    if match is None:
        raise ValueError(f"non-stable or invalid version {value!r}; require reviewed stable lock")
    return tuple(map(int, match.groups()))

def find_violations(lock_bytes: bytes) -> list[str]:
    try:
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"Cargo.lock is unreadable or malformed: {exc}"]
    if not isinstance(lock, dict) or not isinstance(lock.get("package"), list):
        return ["Cargo.lock must contain a [[package]] array"]
    errors: list[str] = []
    known: set[tuple[str, tuple[int, int, int]]] = set()
    present: set[str] = set()
    for item in lock["package"]:
        if not isinstance(item, dict):
            errors.append("Cargo.lock package must be a table")
            continue
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not name:
            errors.append("Cargo.lock package is missing its name")
            continue
        present.add(name)
        if name not in MINIMUMS and name not in {"quinn-udp", "webpki-roots", "pin-utils", "tokio"}:
            continue
        try:
            parsed = parse_version(version)
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
            continue
        key = (name, parsed)
        if key in known:
            errors.append(f"duplicate package identity: {name}@{version}")
        known.add(key)
        if name in MINIMUMS and parsed < MINIMUMS[name]:
            floor = ".".join(map(str, MINIMUMS[name]))
            errors.append(f"{name}@{version}: requires >= {floor} (all copies)")
        if name == "quinn-udp" and (parsed < (0, 5, 16) or (0, 6, 0) <= parsed < (0, 6, 3)):
            errors.append(f"quinn-udp@{version}: requires >=0.5.16,<0.6.0 or >=0.6.3")
        if name == "webpki-roots" and parsed[0] == 1 and parsed < (1, 0, 10):
            errors.append(f"webpki-roots@{version}: requires >=1.0.10 on the 1.x line")
        if name == "pin-utils":
            errors.append(f"pin-utils@{version}: unmaintained dependency must be eliminated")
        if name == "tokio" and parsed <= (1, 47, 1):
            errors.append(f"tokio@{version}: known I/O safety advisory; upgrade and re-audit")
    if "rmcp" not in present:
        errors.append("missing rmcp package: check lock completeness")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    args = parser.parse_args()
    try:
        contents = args.lockfile.read_bytes()
    except OSError as exc:
        print(f"[security-floor] cannot read lock: {exc}", file=sys.stderr)
        return 2
    errors = find_violations(contents)
    for error in errors:
        print(f"[security-floor] FAIL: {error}", file=sys.stderr)
    if errors:
        print(f"[security-floor] {len(errors)} violations; remediation required", file=sys.stderr)
        return 1
    print("[security-floor] known floors clear; full cargo audit --deny warnings still required")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
