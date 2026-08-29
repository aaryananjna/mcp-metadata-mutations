#!/usr/bin/env python3
"""
Interactive hand-adjudication of a transition set.

Why do this at all. A rule fires on a pattern; it does not know what the pattern
means. For small sets the honest move is to look at every case and label it
against a protocol written down BEFORE looking at the data. Deciding the
categories afterwards means inventing a category to fit whatever is on screen,
which makes the result unfalsifiable.

    python3 adjudicate.py --snapshot 2026-08-22 --transition repo_id_changed
    python3 adjudicate.py --snapshot 2026-08-22 --transition repo_id_changed --summary
    python3 adjudicate.py --snapshot 2026-08-22 --transition repo_id_changed --recheck 10

Resumable: labels are appended to a CSV as you go, and already-labelled cases
are skipped. Ctrl-C whenever.

--recheck re-presents already-labelled cases with the previous label hidden, so
you can measure agreement with your earlier self. A solo researcher cannot
compute inter-rater reliability, but intra-rater agreement is computable and is
the honest substitute. Report it.
"""

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path

from diff import transitions
from store import Store

# Protocols are declared here, in code, ahead of the data. Adding a label
# mid-adjudication invalidates everything labelled before it, so if you need a
# new one, add it and re-do the set.
PROTOCOLS = {
    "repo_id_changed": {
        "question": "The repository ID changed, so the repo at this URL is not "
                    "the same repo it was. What happened?",
        "labels": {
            "1": ("moved_to_new_repo",
                  "URL also changed; publisher moved to a different repository"),
            "2": ("deleted_and_recreated",
                  "Same owner and name, new ID; repo was deleted and remade"),
            "3": ("transferred",
                  "Ownership transferred between accounts, same project"),
            "4": ("different_project",
                  "New repo is a visibly different project, not a continuation"),
            "5": ("id_added_or_removed",
                  "One side has no ID; not a true ID change"),
            "6": ("unclear",
                  "Cannot determine from available evidence"),
        },
    },
    "secret_input_added": {
        "question": "A new input marked isSecret appeared. Did the server's "
                    "trust envelope actually widen?",
        "labels": {
            "1": ("new_credential_required",
                  "Server now demands a credential it did not need before"),
            "2": ("renamed_existing",
                  "Same credential, different field name or location"),
            "3": ("marking_corrected",
                  "Existing input was newly (and correctly) marked isSecret"),
            "4": ("optional_addition",
                  "New secret is optional; existing users unaffected"),
            "5": ("unclear", "Cannot determine"),
        },
    },
    "remote_host_changed": {
        "question": "The remote endpoint host changed. Where did it go?",
        "labels": {
            "1": ("same_org_new_host",
                  "New host is clearly the same operator, e.g. subdomain move"),
            "2": ("platform_migration",
                  "Moved onto or off a hosting platform"),
            "3": ("unrelated_host",
                  "New host has no visible relationship to the publisher"),
            "4": ("localhost_or_placeholder",
                  "One side is localhost, example.com or similar"),
            "5": ("unclear", "Cannot determine"),
        },
    },
}


def repo_of(rec):
    return rec.get("repository") or {}


def collect_cases(store, snapshot, transition):
    rows = store.states_at(snapshot)
    by_server = {}
    for r in rows:
        by_server.setdefault(r["server_name"], []).append(r)

    cases = []
    for name, chain in by_server.items():
        for prev, cur in zip(chain, chain[1:]):
            a = store.get_blob(prev["content_hash"])
            b = store.get_blob(cur["content_hash"])
            if transition in transitions(a, b):
                cases.append({
                    "server": name,
                    "from_version": prev["version"],
                    "to_version": cur["version"],
                    "from_published": prev["published_at"],
                    "to_published": cur["published_at"],
                    "before": a,
                    "after": b,
                    "all_transitions": transitions(a, b),
                })
    cases.sort(key=lambda c: (c["server"], c["from_published"] or ""))
    return cases


def case_id(c):
    return "%s|%s|%s" % (c["server"], c["from_version"], c["to_version"])


def show(c, n, total):
    ra, rb = repo_of(c["before"]), repo_of(c["after"])
    print("\n" + "=" * 76)
    print("[%d/%d]  %s" % (n, total, c["server"]))
    print("        %s  ->  %s" % (c["from_version"], c["to_version"]))
    print("        %s  ->  %s"
          % ((c["from_published"] or "")[:10], (c["to_published"] or "")[:10]))
    print("-" * 76)
    print("  BEFORE  url : %s" % ra.get("url"))
    print("          id  : %s   source: %s" % (ra.get("id"), ra.get("source")))
    print("          desc: %s" % (c["before"].get("description") or "")[:66])
    print("  AFTER   url : %s" % rb.get("url"))
    print("          id  : %s   source: %s" % (rb.get("id"), rb.get("source")))
    print("          desc: %s" % (c["after"].get("description") or "")[:66])
    other = [t for t in c["all_transitions"] if t != ARGS.transition]
    if other:
        print("  also changed: %s" % ", ".join(other))
    print("-" * 76)
    print("  open in a browser to check current state:")
    for u in (ra.get("url"), rb.get("url")):
        if u:
            print("    %s" % u)


def load_labels(path):
    out = {}
    if Path(path).exists():
        with open(path) as f:
            for row in csv.DictReader(f):
                out[row["case_id"]] = row
    return out


def append_label(path, row):
    exists = Path(path).exists()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=["case_id", "server", "from_version",
                                           "to_version", "label", "note"])
        if not exists:
            wr.writeheader()
        wr.writerow(row)


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--transition", required=True, choices=sorted(PROTOCOLS))
    ap.add_argument("--out")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--recheck", type=int, default=0)
    ARGS = ap.parse_args()

    proto = PROTOCOLS[ARGS.transition]
    out = ARGS.out or "reports/adjudication-%s.csv" % ARGS.transition
    done = load_labels(out)

    store = Store(ARGS.data)
    cases = collect_cases(store, ARGS.snapshot, ARGS.transition)

    if ARGS.summary:
        counts = Counter(r["label"] for r in done.values())
        print("transition : %s" % ARGS.transition)
        print("cases      : %d" % len(cases))
        print("adjudicated: %d\n" % len(done))
        for label, n in counts.most_common():
            print("  %-24s %4d  (%5.1f%%)"
                  % (label, n, 100.0 * n / max(1, len(done))))
        json.dump({"transition": ARGS.transition, "total_cases": len(cases),
                   "adjudicated": len(done), "labels": dict(counts)},
                  open(out.replace(".csv", ".json"), "w"), indent=2)
        return

    if ARGS.recheck:
        pool = [c for c in cases if case_id(c) in done]
        random.shuffle(pool)
        pool = pool[:ARGS.recheck]
        agree = 0
        print("RECHECK: %d cases, previous labels hidden.\n" % len(pool))
        for i, c in enumerate(pool, 1):
            show(c, i, len(pool))
            print("\n  %s" % proto["question"])
            for k, (lab, desc) in sorted(proto["labels"].items()):
                print("    %s. %-24s %s" % (k, lab, desc))
            choice = input("\n  label> ").strip()
            if choice not in proto["labels"]:
                print("  skipped")
                continue
            new = proto["labels"][choice][0]
            old = done[case_id(c)]["label"]
            agree += new == old
            print("  previously: %s   now: %s   %s"
                  % (old, new, "AGREE" if new == old else "DIFFER"))
        print("\nintra-rater agreement: %d/%d (%.0f%%)"
              % (agree, len(pool), 100.0 * agree / max(1, len(pool))))
        print("Report this number. It bounds how reproducible your labels are.")
        return

    todo = [c for c in cases if case_id(c) not in done]
    print("transition : %s" % ARGS.transition)
    print("cases      : %d total, %d already labelled, %d to go"
          % (len(cases), len(done), len(todo)))
    print("output     : %s" % out)
    print("\nPROTOCOL (fixed before looking at data):")
    print("  %s" % proto["question"])
    for k, (lab, desc) in sorted(proto["labels"].items()):
        print("    %s. %-24s %s" % (k, lab, desc))
    print("\n  s = skip, q = quit and save\n")

    for i, c in enumerate(todo, 1):
        show(c, i, len(todo))
        print("\n  %s" % proto["question"])
        for k, (lab, desc) in sorted(proto["labels"].items()):
            print("    %s. %-24s %s" % (k, lab, desc))
        choice = input("\n  label> ").strip().lower()
        if choice == "q":
            break
        if choice == "s" or choice not in proto["labels"]:
            print("  skipped")
            continue
        note = input("  note (optional)> ").strip()
        append_label(out, {
            "case_id": case_id(c), "server": c["server"],
            "from_version": c["from_version"], "to_version": c["to_version"],
            "label": proto["labels"][choice][0], "note": note,
        })
        print("  saved: %s" % proto["labels"][choice][0])

    print("\nDone. Run with --summary for the breakdown.")


if __name__ == "__main__":
    main()


    