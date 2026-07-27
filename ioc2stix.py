#!/usr/bin/env python3
"""
ioc2stix.py — Convert plain-text IOC files to STIX 2.1 bundles.  (v2)

Usage:
    python3 ioc2stix.py iocs_kikimora.txt
    python3 ioc2stix.py 00*/iocs_*.txt --dry-run
    python3 ioc2stix.py iocs.txt -o out.json

Handled automatically:
  - defanged values: [.]  (.)  [:]  [dot]  hxxp
  - hashes (SHA-256 / SHA-1 / MD5), URLs, domains, IPv4, CIDR, email
  - host:port  -> network-traffic pattern
  - bare owner/repo inside a GitHub/repository section -> github URL
  - markdown table rows: each cell is tried
  - REDACTED entries: counted and reported, never emitted
  - prose sections (reported to / notes / assessment / references): skipped

Zero dependencies. Python 3.8+.
IDs are deterministic (UUIDv5), so re-running produces a stable file.
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV4_CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
IPV4_PORT = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](-?[a-zA-Z0-9_])*\.)+[a-zA-Z]{2,}$")
DOMAIN_PORT = re.compile(r"^([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,}):(\d{1,5})$")
REPO_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
SECTION = re.compile(r"^==\s*(.+?)\s*==$")

SKIP_SECTION = re.compile(
    r"report(ed|ing)?\b|abuse|notes?\b|assessment|context|contact|"
    r"reference|timeline|summary|attribution|recommendation|ttps?\b|"
    r"observations?|conclusion|disclosure",
    re.I,
)
GITHUB_SECTION = re.compile(r"github|repositor|repos?\b|account", re.I)

REDACTED = re.compile(r"REDACTED|محجوب|\bHOST-\d|\[redacted\]", re.I)
PROSE = re.compile(r"^[-*\u2022]\s|^\d+\.\s")
CONTACT = re.compile(
    r"\bCERT\b|\bNCSA\b|\babuse\b|trust\s*&\s*safety|registrar|"
    r"\bmCERT\b|\bCSIRT\b|report-abuse|hosting provider",
    re.I,
)


def scrub(text):
    """Remove redaction markers from a free-text comment, keep the alias."""
    if not text:
        return text
    # drop bracketed markers: [REDACTED], [\u0645\u062d\u062c\u0648\u0628 - REDACTED]
    text = re.sub(r"\[[^\]]*(REDACTED|\u0645\u062d\u062c\u0648\u0628)[^\]]*\]", "", text,
                  flags=re.I)
    # drop any bare marker left over
    text = re.sub(r"\b(REDACTED|\u0645\u062d\u062c\u0648\u0628)\b", "", text, flags=re.I)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip(" |-\u2014")


def refang(value):
    v = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    v = v.replace("[dot]", ".").replace("(dot)", ".")
    v = re.sub(r"^h[xt]{2}p", "http", v, flags=re.I)
    return v


def esc(s):
    return s.replace("\\", "\\\\").replace("'", "\\'")


def classify(value, section=""):
    """Return the first (pattern, kind) match, or (None, None)."""
    out = classify_all(value, section)
    return out[0] if out else (None, None)


def classify_all(value, section=""):
    """Return a list of (pattern, kind). host:port yields two indicators:
    the port-specific network-traffic pattern AND the bare host, so that
    consumers doing plain IP/domain blocking still match."""
    v = refang(value.strip().strip(",;"))
    if not v:
        return []

    if HEX64.match(v):
        return [(f"[file:hashes.'SHA-256' = '{v.lower()}']", "file")]
    if HEX40.match(v):
        return [(f"[file:hashes.'SHA-1' = '{v.lower()}']", "file")]
    if HEX32.match(v):
        return [(f"[file:hashes.MD5 = '{v.lower()}']", "file")]

    if v.lower().startswith(("http://", "https://")):
        return [(f"[url:value = '{esc(v)}']", "url")]

    m = IPV4_PORT.match(v)
    if m:
        ip, port = m.group(1), int(m.group(2))
        return [
            ("[network-traffic:dst_ref.type = 'ipv4-addr' AND "
             f"network-traffic:dst_ref.value = '{ip}' AND "
             f"network-traffic:dst_port = {port}]", "network-traffic"),
            (f"[ipv4-addr:value = '{ip}']", "ipv4-addr"),
        ]

    m = DOMAIN_PORT.match(v)
    if m:
        host, port = m.group(1).lower(), int(m.group(2))
        return [
            ("[network-traffic:dst_ref.type = 'domain-name' AND "
             f"network-traffic:dst_ref.value = '{host}' AND "
             f"network-traffic:dst_port = {port}]", "network-traffic"),
            (f"[domain-name:value = '{host}']", "domain-name"),
        ]

    if IPV4_CIDR.match(v) or IPV4.match(v):
        return [(f"[ipv4-addr:value = '{v}']", "ipv4-addr")]
    if EMAIL.match(v):
        return [(f"[email-addr:value = '{esc(v)}']", "email-addr")]

    if "/" in v:
        host = v.split("/", 1)[0]
        if DOMAIN.match(host):
            return [(f"[url:value = 'https://{esc(v)}']", "url")]
        if REPO_PATH.match(v) and GITHUB_SECTION.search(section):
            return [(f"[url:value = 'https://github.com/{esc(v)}']", "url")]
        return []

    if DOMAIN.match(v):
        return [(f"[domain-name:value = '{v.lower()}']", "domain-name")]
    return []


def det_id(prefix, seed):
    return f"{prefix}--{uuid.uuid5(NAMESPACE, seed)}"


def split_value_comment(line):
    parts = re.split(r"\s{2,}|\t", line, maxsplit=1)
    value = parts[0].strip()
    comment = parts[1].strip() if len(parts) > 1 else ""
    m = re.match(r"^(\S+)\s*\((.+)\)$", value)
    if m:
        value, comment = m.group(1), (m.group(2) + " " + comment).strip()
    m = re.match(r"^\((.+)\)$", comment)
    if m:
        comment = m.group(1).strip()
    return value, comment


def parse(path, extra_skip=()):
    extra = [x.lower() for x in extra_skip]
    meta = {"title": None, "compiled": None, "analyst": None}
    entries = []
    stats = {"redacted": [], "prose": 0, "contacts": 0, "skipped_sections": set()}
    section = "Uncategorized"

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            if line.startswith("##"):
                section = line.lstrip("#").strip()
                continue

            if line.startswith("#"):
                text = line.lstrip("#").strip()
                low = text.lower()
                if meta["title"] is None and ("investigation" in low or "iocs" in low):
                    meta["title"] = re.sub(r"^IOCs\s*[\u2014\-\u2013:]\s*", "", text).strip()
                m = re.search(r"compiled:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.I)
                if m:
                    meta["compiled"] = m.group(1)
                m = re.search(r"analyst:\s*([^|]+)", text, re.I)
                if m:
                    meta["analyst"] = m.group(1).strip()
                continue

            m = SECTION.match(line)
            if m:
                section = m.group(1)
                continue

            if SKIP_SECTION.search(section) or section.lower() in extra:
                stats["skipped_sections"].add(section)
                continue

            if PROSE.match(line):
                stats["prose"] += 1
                continue

            if CONTACT.search(line) and not classify(line.split()[0], section)[0]:
                stats["contacts"] += 1
                continue

            if raw[:1] in " \t" and line.startswith("|") and entries:
                extra = " | ".join(
                    scrub(c.strip()) for c in line.strip("|").split("|") if c.strip()
                )
                prev = entries[-1]
                prev["comment"] = (prev["comment"] + " | " + extra).strip(" |")
                continue

            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                hit = False
                for cell in cells:
                    if REDACTED.search(cell):
                        continue
                    if classify(cell, section)[0]:
                        rest = " | ".join(
                            scrub(c) for c in cells if c != cell and c.strip()
                        )
                        entries.append({"value": cell, "comment": rest,
                                        "section": section})
                        hit = True
                        break
                if hit:
                    continue
                if any(REDACTED.search(c) for c in cells):
                    stats["redacted"].append(line)
                else:
                    entries.append({"value": line, "comment": "",
                                    "section": section})
                continue

            value, comment = split_value_comment(line)
            if REDACTED.search(value):
                stats["redacted"].append(line)
                continue
            entries.append({"value": value, "comment": scrub(comment),
                            "section": section})

    return meta, entries, stats


def make_indicator(ind_id, identity_id, created, entry, pattern, kind):
    ind = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind_id,
        "created_by_ref": identity_id,
        "created": created,
        "modified": created,
        "name": (entry["comment"] or entry["value"])[:200],
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "labels": [entry["section"].lower(), kind],
        "object_marking_refs": [TLP_CLEAR],
    }
    if entry["comment"]:
        ind["description"] = entry["comment"]
    return ind


def build(meta, entries, source_name):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    created = f"{meta['compiled']}T00:00:00.000Z" if meta["compiled"] else now
    title = meta["title"] or source_name
    analyst = meta["analyst"] or "Independent analyst"

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": det_id("identity", f"identity:{analyst}"),
        "created": created,
        "modified": created,
        "name": analyst,
        "identity_class": "individual",
    }

    objects, refs, unparsed = [identity], [], []

    for e in entries:
        matches = classify_all(e["value"], e["section"])
        if not matches:
            unparsed.append(e["value"])
            continue
        for pattern, kind in matches:
            ind_id = det_id("indicator", f"{title}|{pattern}")
            if ind_id in refs:
                continue
            objects.append(make_indicator(
                ind_id, identity["id"], created, e, pattern, kind))
            refs.append(ind_id)

    if refs:
        objects.append({
            "type": "grouping",
            "spec_version": "2.1",
            "id": det_id("grouping", f"grouping:{title}"),
            "created_by_ref": identity["id"],
            "created": created,
            "modified": created,
            "name": title,
            "context": "suspicious-activity",
            "object_refs": refs,
            "object_marking_refs": [TLP_CLEAR],
        })

    bundle = {"type": "bundle", "id": det_id("bundle", f"bundle:{title}"),
              "objects": objects}
    return bundle, len(refs), unparsed


def main():
    ap = argparse.ArgumentParser(description="Convert IOC text files to STIX 2.1.")
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-o", "--output")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--show-redacted", action="store_true",
                    help="print the redacted lines that were held back")
    ap.add_argument("--skip-section", action="append", default=[],
                    metavar="NAME",
                    help="skip an extra section by name (repeatable)")
    args = ap.parse_args()

    if args.output and len(args.inputs) > 1:
        sys.exit("error: -o cannot be used with multiple inputs")

    for path in args.inputs:
        if not os.path.isfile(path):
            print(f"skip (not a file): {path}", file=sys.stderr)
            continue

        meta, entries, stats = parse(path, args.skip_section)
        bundle, count, unparsed = build(meta, entries, os.path.basename(path))

        bits = [f"{count} indicators"]
        if stats["redacted"]:
            bits.append(f"{len(stats['redacted'])} redacted (held back)")
        if stats["prose"]:
            bits.append(f"{stats['prose']} prose lines")
        if stats["contacts"]:
            bits.append(f"{stats['contacts']} contacts")
        if stats["skipped_sections"]:
            bits.append(f"{len(stats['skipped_sections'])} prose sections")
        if unparsed:
            bits.append(f"{len(unparsed)} UNPARSED")
        print(f"{path}: " + ", ".join(bits))

        for s in sorted(stats["skipped_sections"]):
            print(f"    skipped section: {s}")
        if args.show_redacted:
            for r in stats["redacted"]:
                print(f"    redacted: {r}")
        for u in unparsed:
            print(f"    UNPARSED: {u}")

        if args.dry_run:
            continue

        out = args.output or re.sub(r"\.txt$", "", path) + "_stix.json"
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"    wrote {out}")


if __name__ == "__main__":
    main()
