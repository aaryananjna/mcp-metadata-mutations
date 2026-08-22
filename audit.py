#!/usr/bin/env python3
"""
Audit a single transition type by pulling the actual before/after values.

Any detector that fires on thousands of pairs deserves this treatment before
its count goes in a writeup. A count is not evidence. The underlying strings
are evidence.

    python3 audit.py --snapshot 2026-08-22 --transition package_identifier_changed
    python3 audit.py --snapshot 2026-08-22 --transition repo_owner_changed --sample 20

Prints a breakdown of WHY the detector fired, plus a random sample of raw
before/after values so you can eyeball them yourself.
"""

import argparse
import random
import sqlite3
from collections import Counter

from store import Store
from diff import transitions


def pkg_pairs(server):
    return [
        (p.get("registryType"), p.get("identifier"), p.get("version"))
        for p in (server.get("packages") or [])
    ]


def classify_identifier_change(a, b):
    """Explain a package_identifier_changed firing.

    Returns a label. The interesting one is 'real_rename': the package name
    genuinely changed. Everything else is an artifact of how the identifier
    field is used and should be excluded from supply chain counts.
    """
    ids_a = {i for _, i, _ in pkg_pairs(a) if i}
    ids_b = {i for _, i, _ in pkg_pairs(b) if i}
    va, vb = a.get("version", ""), b.get("version", "")

    a_urls = any(i.startswith("http") for i in ids_a)
    b_urls = any(i.startswith("http") for i in ids_b)

    if a_urls or b_urls:
        # Identifier is a download URL, not a package name. If the only
        # difference is the version substring, this is a routine release.
        stripped_a = {i.replace(va, "{V}") for i in ids_a}
        stripped_b = {i.replace(vb, "{V}") for i in ids_b}
        if stripped_a == stripped_b:
            return "artifact_version_in_url"
        return "url_changed_beyond_version"

    # Plain package names. Same test: does the version string appear in them?
    stripped_a = {i.replace(va, "{V}") for i in ids_a}
    stripped_b = {i.replace(vb, "{V}") for i in ids_b}
    if stripped_a == stripped_b:
        return "artifact_version_in_name"

    if len(ids_a) != len(ids_b):
        return "package_count_changed"

    return "real_rename"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--transition", required=True)
    ap.add_argument("--sample", type=int, default=10)
    args = ap.parse_args()

    store = Store(args.data)
    store.db.row_factory = sqlite3.Row
    rows = store.db.execute(
        """SELECT server_name, version, content_hash, published_at
           FROM observations WHERE snapshot_date=?
           ORDER BY server_name, published_at, version""",
        (args.snapshot,),
    ).fetchall()

    by_server = {}
    for r in rows:
        by_server.setdefault(r["server_name"], []).append(r)

    hits, reasons = [], Counter()
    for name, chain in by_server.items():
        for prev, cur in zip(chain, chain[1:]):
            a = store.get_blob(prev["content_hash"])
            b = store.get_blob(cur["content_hash"])
            if args.transition not in transitions(a, b):
                continue
            reason = (
                classify_identifier_change(a, b)
                if args.transition == "package_identifier_changed"
                else "-"
            )
            reasons[reason] += 1
            hits.append((name, prev["version"], cur["version"], a, b, reason))

    print(f"transition: {args.transition}")
    print(f"total firings: {len(hits)}")
    if args.transition == "package_identifier_changed":
        print("\nwhy it fired:")
        for reason, n in reasons.most_common():
            pct = 100.0 * n / max(1, len(hits))
            print(f"  {reason:32s} {n:7d}  ({pct:5.1f}%)")
        real = reasons.get("real_rename", 0) + reasons.get("url_changed_beyond_version", 0)
        print(f"\n  defensible count (excluding artifacts): {real}")

    print(f"\nrandom sample of {min(args.sample, len(hits))}:")
    random.seed(0)
    for name, v1, v2, a, b, reason in random.sample(hits, min(args.sample, len(hits))):
        print(f"\n  {name}  {v1} -> {v2}   [{reason}]")
        print(f"    before: {pkg_pairs(a)}")
        print(f"    after : {pkg_pairs(b)}")
        if args.transition == "repo_owner_changed":
            print(f"    repo before: {(a.get('repository') or {}).get('url')}")
            print(f"    repo after : {(b.get('repository') or {}).get('url')}")


if __name__ == "__main__":
    main()