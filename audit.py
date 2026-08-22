#!/usr/bin/env python3
"""
Audit a transition type by pulling the actual before/after values.

Any detector that fires on more than a handful of pairs gets this treatment
before its count goes in a writeup. A count is a hypothesis. The underlying
strings are the evidence.

    python3 audit.py --snapshot 2026-08-22 --transition repo_owner_changed
    python3 audit.py --snapshot 2026-08-22 --transition package_identifier_changed
    python3 audit.py --snapshot 2026-08-22 --transition repo_owner_changed \
        --bucket diverged_from_namespace --sample 40
    python3 audit.py --snapshot 2026-08-22 --placeholders
    python3 audit.py --snapshot 2026-08-22 --transition repo_owner_changed \
        --github-token ghp_xxx        # adds User vs Organization
"""

import argparse
import json
import random
from collections import Counter

from classify import classify_owner_change, is_placeholder, owner, owner_kind
from diff import transitions
from store import Store


def pkg_pairs(server):
    return [(p.get("registryType"), p.get("identifier"), p.get("version"))
            for p in (server.get("packages") or [])]


def classify_identifier_change(a, b):
    """Explain a package_identifier_changed firing. The only interesting label
    is 'real_rename'. Everything else is an artifact of how the identifier field
    is used, chiefly OCI tags and MCPB download URLs with the version baked into
    the string, and must be excluded from supply chain counts."""
    ids_a = {i for _, i, _ in pkg_pairs(a) if i}
    ids_b = {i for _, i, _ in pkg_pairs(b) if i}
    va, vb = a.get("version", ""), b.get("version", "")
    urls = any(i.startswith("http") for i in ids_a | ids_b)

    sa = {i.replace(va, "{V}") for i in ids_a}
    sb = {i.replace(vb, "{V}") for i in ids_b}
    if sa == sb:
        return "artifact_version_in_url" if urls else "artifact_version_in_name"
    if urls:
        return "url_changed_beyond_version"
    if len(ids_a) != len(ids_b):
        return "package_count_changed"
    return "real_rename"


REAL = {
    "package_identifier_changed": {"real_rename", "url_changed_beyond_version"},
    "repo_owner_changed": {"diverged_from_namespace", "unrelated"},
}


def chain_pairs(store, snapshot):
    rows = store.states_at(snapshot)
    by_server = {}
    for r in rows:
        by_server.setdefault(r["server_name"], []).append(r)
    for name, chain in by_server.items():
        for prev, cur in zip(chain, chain[1:]):
            yield name, prev, cur


def cmd_transition(store, args):
    hits, buckets = [], Counter()
    for name, prev, cur in chain_pairs(store, args.snapshot):
        a = store.get_blob(prev["content_hash"])
        b = store.get_blob(cur["content_hash"])
        if args.transition not in transitions(a, b):
            continue
        if args.transition == "package_identifier_changed":
            bucket = classify_identifier_change(a, b)
            note = ""
        elif args.transition == "repo_owner_changed":
            bucket, note = classify_owner_change(
                name, (a.get("repository") or {}).get("url"),
                (b.get("repository") or {}).get("url"))
        else:
            bucket, note = "-", ""
        buckets[bucket] += 1
        hits.append((name, prev["version"], cur["version"], a, b, bucket, note))

    print("transition: %s" % args.transition)
    print("total firings: %d" % len(hits))
    if len(buckets) > 1:
        print("\nsubclassification:")
        for bucket, n in buckets.most_common():
            mark = " <-- SIGNAL" if bucket in REAL.get(args.transition, set()) else ""
            print("  %-28s %6d  (%5.1f%%)%s"
                  % (bucket, n, 100.0 * n / max(1, len(hits)), mark))
        real = sum(n for k, n in buckets.items() if k in REAL.get(args.transition, set()))
        if REAL.get(args.transition):
            print("\n  defensible count: %d  (%.1f%% of raw)"
                  % (real, 100.0 * real / max(1, len(hits))))

    shown = [h for h in hits if not args.bucket or h[5] == args.bucket]
    if args.github_token and args.transition == "repo_owner_changed":
        print("\nresolving GitHub owner types (cached)...")
        for _, _, _, a, b, _, _ in shown:
            for rec in (a, b):
                lg = owner((rec.get("repository") or {}).get("url"))
                if lg:
                    owner_kind(lg, args.github_token)

    print("\nsample of %d%s:" % (min(args.sample, len(shown)),
                                 " from bucket %r" % args.bucket if args.bucket else ""))
    random.seed(0)
    for name, v1, v2, a, b, bucket, note in random.sample(shown, min(args.sample, len(shown))):
        ua = (a.get("repository") or {}).get("url")
        ub = (b.get("repository") or {}).get("url")
        print("\n  %s  %s -> %s   [%s]" % (name, v1, v2, bucket))
        if note:
            print("    %s" % note)
        if args.transition == "repo_owner_changed":
            print("    repo: %s" % ua)
            print("      ->  %s" % ub)
            if args.github_token:
                print("    kind: %s -> %s"
                      % (owner_kind(owner(ua), args.github_token),
                         owner_kind(owner(ub), args.github_token)))
        else:
            print("    before: %s" % pkg_pairs(a))
            print("    after : %s" % pkg_pairs(b))

    if args.out:
        json.dump({"transition": args.transition, "total": len(hits),
                   "buckets": dict(buckets),
                   "events": [{"server": n, "from_version": v1, "to_version": v2,
                               "bucket": bk, "note": nt}
                              for n, v1, v2, _, _, bk, nt in hits]},
                  open(args.out, "w"), indent=2)


def cmd_placeholders(store, args):
    """Scan every current record for unedited template values in the repository
    URL. Any hit demonstrates that the registry verifies namespace ownership but
    does not validate that the supplied repository actually exists or belongs to
    the publisher. That is a standalone finding about publication validation."""
    hits = []
    for r in store.states_at(args.snapshot):
        rec = store.get_blob(r["content_hash"])
        url = (rec.get("repository") or {}).get("url")
        if url and is_placeholder(owner(url)):
            hits.append((r["server_name"], r["version"], url, r["status"]))

    print("placeholder repository owners: %d" % len(hits))
    by_server = {h[0] for h in hits}
    print("distinct servers affected:     %d" % len(by_server))
    print("\nall hits:")
    for name, ver, url, status in sorted(hits)[:args.sample]:
        print("  %-46s %-12s %-9s %s" % (name[:46], ver, status, url))
    if args.out:
        json.dump([{"server": n, "version": v, "url": u, "status": s}
                   for n, v, u, s in hits], open(args.out, "w"), indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--transition")
    ap.add_argument("--bucket", help="show samples from one subclass only")
    ap.add_argument("--placeholders", action="store_true")
    ap.add_argument("--github-token", help="optional; adds User vs Organization")
    ap.add_argument("--sample", type=int, default=15)
    ap.add_argument("--out")
    args = ap.parse_args()

    store = Store(args.data)
    if args.placeholders:
        cmd_placeholders(store, args)
    elif args.transition:
        cmd_transition(store, args)
    else:
        ap.error("need --transition or --placeholders")


if __name__ == "__main__":
    main()