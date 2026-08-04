#!/usr/bin/env python3
"""
verify_claim.py — availability checker for DDoS claims (stdlib only).

Runs N HTTP checks against a target over time and prints a verdict.
A claim is only supported if checks fail DURING the claimed window —
run this while the claim is fresh, and corroborate with a second
vantage point (e.g. https://check-host.net) before marking VERIFIED.

Usage:
    python3 verify_claim.py example.com
    python3 verify_claim.py https://example.gov.sa/portal --checks 6 --interval 300
    python3 verify_claim.py example.com --out results_SA-BANK-01.csv

Verdicts:
    REACHABLE    — all/most checks OK        -> contradicts a DDoS claim
    UNREACHABLE  — all/most checks failed    -> supports the claim (needs 2nd vantage)
    FLAPPING     — mixed results             -> possible partial impact, keep CLAIMED
"""
import argparse
import csv
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "war-tracker-verify/1.0 (research; claims verification)"}


def check_once(url, timeout):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=UA)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read(512)
            return r.status, int((time.time() - t0) * 1000), ""
    except urllib.error.HTTPError as e:
        # HTTP error = server IS responding (e.g. 403 from a WAF still means "up")
        return e.code, int((time.time() - t0) * 1000), ""
    except Exception as e:
        return "", int((time.time() - t0) * 1000), type(e).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="domain or URL")
    ap.add_argument("--checks", type=int, default=6)
    ap.add_argument("--interval", type=int, default=300, help="seconds between checks")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--out", help="append results to this CSV file")
    a = ap.parse_args()

    url = a.target if a.target.startswith("http") else f"https://{a.target}"
    ok, fail, rows = 0, 0, []

    for i in range(a.checks):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        code, ms, err = check_once(url, a.timeout)
        good = code != "" and (200 <= int(code) < 500)
        ok, fail = ok + good, fail + (not good)
        state = "UP" if good else "DOWN"
        print(f"[{i+1}/{a.checks}] {ts}  {state}  code={code or '-'}  {ms}ms  {err}")
        rows.append([ts, a.target, state, code, ms, err])
        if i < a.checks - 1:
            time.sleep(a.interval)

    ratio = ok / (ok + fail)
    verdict = "REACHABLE" if ratio >= 0.8 else "UNREACHABLE" if ratio <= 0.2 else "FLAPPING"
    print(f"\nVERDICT: {verdict}  ({ok}/{ok+fail} checks up)")
    if verdict == "UNREACHABLE":
        print("NOTE: supports the DDoS claim ONLY with a second vantage point.")
    elif verdict == "REACHABLE":
        print("NOTE: contradicts a DDoS claim made for this window (log DEBUNKED).")

    if a.out:
        write_header = False
        try:
            open(a.out).close()
        except FileNotFoundError:
            write_header = True
        with open(a.out, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["timestamp_utc", "target", "state", "http_code",
                            "response_ms", "error"])
            w.writerows(rows)
        print(f"results appended to {a.out}")


if __name__ == "__main__":
    main()
