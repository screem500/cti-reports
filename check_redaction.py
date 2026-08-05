#!/usr/bin/env python3
"""
check_redaction.py — Redaction-integrity scanner for cti-reports.

Rule: any identifier that is redacted in a report must not appear
ANYWHERE else in the repository (raw files, screenshots excluded by
extension, IOCs, STIX, README).

Usage:
    python3 check_redaction.py            # run from repo root
Exit code 0 = clean, 1 = leak found.
"""
import os
import sys

# ── Identifiers that must NEVER appear in the repo ──────────────────
# Add every redacted victim/host identifier here.
BANNED = [
    # 003 — UAE-HOST-01 victim identity
    "agilemtech",
    # 004/002 — QA-HOST-01 victim identity + its de-anonymizing artifacts
    "blueweqatar",
    "3886420",
    "3886411",
    "5.9.143.30",
    # policy wording that must stay generic
    "Admin By Request",
    # corrected terminology (old versions must not linger)
    "DigiCert",
    # orphan indicator removed 2026-08-01 (001 report + 002 IOCs)
    "45.138.16.162",
]

SKIP_DIRS = {".git"}
TEXT_EXTS = {
    ".md", ".txt", ".json", ".csv", ".yml", ".yaml", ".py", ".sh",
    ".stix", ".ioc", ".html", ".xml", ".log",
}


def scan(root="."):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn == "check_redaction.py":
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext not in TEXT_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for n, line in enumerate(f, 1):
                        for term in BANNED:
                            if term.lower() in line.lower():
                                hits.append((path, n, term))
            except OSError:
                pass
    return hits


if __name__ == "__main__":
    hits = scan(sys.argv[1] if len(sys.argv) > 1 else ".")
    if not hits:
        print("CLEAN — no redacted identifier appears anywhere in the repo.")
        sys.exit(0)
    print(f"LEAKS FOUND: {len(hits)}")
    for path, n, term in hits:
        print(f"  {path}:{n}  ->  {term}")
    sys.exit(1)
