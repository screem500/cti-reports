#!/usr/bin/env python3
"""
stix2ioc.py — Extract a plain-text IOC file from a STIX 2.1 bundle.

Companion to ioc2stix.py. Use it to recover the text source for bundles
that were written by hand, then regenerate a spec-valid bundle:

    python3 stix2ioc.py old_stix.json -o iocs_name.txt
    python3 ioc2stix.py iocs_name.txt          # writes iocs_name_stix.json

Values are pulled out of the STIX patterns, grouped by observable type,
and annotated with each indicator's name/description as an inline comment.

Zero dependencies. Python 3.8+.
"""

import argparse
import json
import os
import re
import sys
from collections import OrderedDict

VAL = re.compile(r"(\w[\w-]*):(?:value|hashes\.'?([\w-]+)'?)\s*=\s*'([^']+)'")
NT_HOST = re.compile(r"network-traffic:dst_ref\.value\s*=\s*'([^']+)'")
NT_PORT = re.compile(r"network-traffic:dst_port\s*=\s*(\d+)")

SECTION_FOR = OrderedDict([
    ("domain-name", "Domains"),
    ("url", "URLs"),
    ("ipv4-addr", "IP addresses"),
    ("ipv6-addr", "IP addresses"),
    ("network-traffic", "C2 endpoints"),
    ("email-addr", "Email addresses"),
    ("file", "Hashes"),
    ("other", "Other"),
])


def extract(pattern):
    """Return (kind, value) from a STIX pattern, or (None, None)."""
    host = NT_HOST.search(pattern)
    if host:
        port = NT_PORT.search(pattern)
        return "network-traffic", f"{host.group(1)}:{port.group(1)}" if port else host.group(1)

    m = VAL.search(pattern)
    if not m:
        return None, None
    obj, hash_alg, value = m.group(1), m.group(2), m.group(3)
    if obj == "file":
        return "file", value
    return obj, value


def main():
    ap = argparse.ArgumentParser(
        description="Extract a plain-text IOC file from a STIX 2.1 bundle.")
    ap.add_argument("input")
    ap.add_argument("-o", "--output", help="default: <input>.txt next to it")
    ap.add_argument("--title", help="override the report title in the header")
    ap.add_argument("--analyst", help="override the analyst line")
    ap.add_argument("--date", help="override the compiled date (YYYY-MM-DD)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        bundle = json.load(fh)

    objects = bundle.get("objects", [])
    title = args.title
    analyst = args.analyst
    date = args.date

    for o in objects:
        if not title and o.get("type") in ("report", "grouping"):
            title = o.get("name")
        if not analyst and o.get("type") == "identity":
            analyst = o.get("name")
        if not date and o.get("type") == "indicator":
            created = o.get("created", "")
            if len(created) >= 10:
                date = created[:10]

    buckets = OrderedDict((s, []) for s in SECTION_FOR.values())
    seen = set()
    skipped = []

    for o in objects:
        if o.get("type") != "indicator":
            continue
        kind, value = extract(o.get("pattern", ""))
        if not value:
            skipped.append(o.get("pattern", "")[:80])
            continue
        # a placeholder alias is not a usable indicator
        if re.search(r"REDACTED|HOST-\d|محجوب", value, re.I):
            skipped.append(f"redacted placeholder: {value}")
            continue
        if value.lower() in seen:
            continue
        seen.add(value.lower())

        note = o.get("description") or o.get("name") or ""
        note = note.strip()
        if note == value:
            note = ""
        section = SECTION_FOR.get(kind, SECTION_FOR["other"])
        buckets[section].append((value, note))

    out = args.output or re.sub(r"(_stix)?\.json$", "", args.input) + ".txt"
    lines = []
    lines.append(f"# IOCs — {title or os.path.basename(args.input)}")
    header = []
    if date:
        header.append(f"Compiled: {date}")
    if analyst:
        header.append(f"Analyst: {analyst}")
    if header:
        lines.append("# " + " | ".join(header))
    lines.append("# Defensive research purposes only.")
    lines.append("")

    total = 0
    for section, items in buckets.items():
        if not items:
            continue
        lines.append(f"== {section} ==")
        width = max(len(v) for v, _ in items)
        for value, note in items:
            if note:
                lines.append(f"{value.ljust(width)}  ({note})")
            else:
                lines.append(value)
            total += 1
        lines.append("")

    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")

    print(f"{args.input}: {total} indicators -> {out}")
    for s in skipped:
        print(f"    skipped: {s}")
    if skipped:
        print("    (redacted placeholders are intentionally not carried over)")


if __name__ == "__main__":
    main()
