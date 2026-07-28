#!/usr/bin/env python3
"""
check_redactions.py — Enforce the repository disclosure policy.

Run manually:
    python3 check_redactions.py            # check staged files
    python3 check_redactions.py --all      # check the whole working tree

Install as a git hook so it runs before every commit:
    ln -sf ../../check_redactions.py .git/hooks/pre-commit
    chmod +x check_redactions.py

Two checks:

  1. FORBIDDEN STRINGS — any real identifier that must never appear.
     Maintain the list in .redactions (one string per line, # for comments).
     The file itself is excluded from scanning.

  2. HEADER CONSISTENCY — every alias used in a report body
     (UAE-HOST-01, QA-HOST-01, ...) must also be declared in that
     report's `Redactions:` header field.

Exit code 1 blocks the commit.
"""

import os
import re
import subprocess
import sys

ALIAS = re.compile(r"\b[A-Z]{2,4}-HOST-\d+\b")
REDACTIONS_FILE = ".redactions"
TEXT_EXT = {".md", ".txt", ".json", ".yml", ".yaml", ".csv"}
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def load_forbidden():
    if not os.path.exists(REDACTIONS_FILE):
        return []
    out = []
    with open(REDACTIONS_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    return out


def staged_files():
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [f for f in res.stdout.splitlines() if f]


def all_files():
    out = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            out.append(os.path.relpath(os.path.join(root, name), "."))
    return out


def readable(path):
    if os.path.basename(path) == REDACTIONS_FILE:
        return False
    ext = os.path.splitext(path)[1].lower()
    if ext and ext not in TEXT_EXT:
        return False
    if not os.path.isfile(path):
        return False
    # extensionless: only scan if it looks like text
    if not ext:
        try:
            with open(path, 'rb') as fh:
                if b'\0' in fh.read(4096):
                    return False
        except OSError:
            return False
    return True


def check_forbidden(paths, forbidden):
    if not forbidden:
        return []
    hits = []
    for path in paths:
        if not readable(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for n, line in enumerate(fh, 1):
                    low = line.lower()
                    for term in forbidden:
                        if term.lower() in low:
                            hits.append((path, n, term))
        except OSError:
            continue
    return hits


def check_headers(paths):
    problems = []
    for path in paths:
        if not path.endswith(".md") or not os.path.isfile(path):
            continue
        if not re.search(r"report_(ar|en)\.md$", path):
            continue
        try:
            txt = open(path, encoding="utf-8").read()
        except OSError:
            continue
        m = re.search(r"^Redactions:\s*(.+)$", txt, re.M)
        if not m:
            if ALIAS.search(txt):
                problems.append((path, "no Redactions: field, but aliases appear"))
            continue
        body = txt.split("---", 2)[-1]
        present = set(ALIAS.findall(body))
        declared = set(ALIAS.findall(m.group(1)))
        missing = present - declared
        if missing:
            problems.append(
                (path, "used in body but not declared: " + ", ".join(sorted(missing)))
            )
    return problems


def main():
    check_all = "--all" in sys.argv
    paths = all_files() if check_all else staged_files()
    if not paths:
        print("check_redactions: nothing to check")
        return 0

    forbidden = load_forbidden()
    if not forbidden:
        print(f"check_redactions: warning — {REDACTIONS_FILE} is missing or empty; "
              "forbidden-string check is inactive")

    hits = check_forbidden(paths, forbidden)
    problems = check_headers(paths)

    if hits:
        print("\nBLOCKED — forbidden string found:\n")
        for path, n, term in hits:
            print(f"  {path}:{n}  contains a redacted identifier")
        print("\n  Remove or replace it with the alias before committing.")
        print("  (the matched term is not printed here on purpose)\n")

    if problems:
        print("\nBLOCKED — Redactions header does not match report body:\n")
        for path, msg in problems:
            print(f"  {path}\n      {msg}")
        print()

    if hits or problems:
        return 1

    print(f"check_redactions: OK ({len(paths)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
