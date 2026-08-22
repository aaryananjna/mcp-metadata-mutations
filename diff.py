#!/usr/bin/env python3
"""
Two different questions, two different diffs. Do not conflate them.

  chain   : within ONE snapshot, walk each server's version history in
            publishedAt order and emit field-level transitions between
            consecutive versions. This is retrospective. The list endpoint
            returns every version ever published, so on day one this already
            covers the registry's entire lifetime. You do not have to wait
            twelve weeks to have results.

  silent  : compare TWO snapshots and find (name, version) pairs whose
            content_hash changed. The registry says this cannot happen.
            Measuring the rate at which a guarantee fails is the forward-looking
            half of the study, and only the daily collector can produce it.

Every detector here is deterministic and inspectable. No model, no scoring
weights, no learned threshold. Recent ecosystem-scale work found that under
half of existing MCP scanner alerts survive manual validation, so an
undergraduate heuristic stack is not going to do better. What it can do is be
100% reproducible and honestly bounded, which is worth more.

    python3 diff.py chain --snapshot 2026-08-21
    python3 diff.py silent --from 2026-08-21 --to 2026-08-22
"""

import argparse
import json
import sqlite3
from collections import Counter
from urllib.parse import urlparse

from store import Store

# Transition type -> (severity, OWASP ASI, NIST AI RMF function)
# Severity is an ordinal label, not a number. Do not average these.
RUBRIC = {
    "repo_owner_changed":       ("high",   "ASI04", "GOVERN-6.1"),
    "repo_id_changed":          ("high",   "ASI04", "GOVERN-6.1"),
    "repo_removed":             ("high",   "ASI04", "MAP-4.1"),
    "package_registry_switch":  ("high",   "ASI04", "MAP-4.1"),
    "package_identifier_changed": ("high", "ASI04", "MAP-4.1"),
    "remote_host_changed":      ("high",   "ASI04", "MAP-4.1"),
    "secret_input_added":       ("medium", "ASI03", "MAP-2.3"),
    "transport_type_changed":   ("medium", "ASI04", "MAP-4.1"),
    "remote_host_added":        ("medium", "ASI04", "MAP-4.1"),
    "description_changed":      ("low",    "ASI02", "MEASURE-2.7"),
    "website_host_changed":     ("low",    "ASI04", "MAP-4.1"),
    "repo_added":               ("info",   "-",     "-"),
    "remote_host_removed":      ("info",   "-",     "-"),
    "schema_version_changed":   ("info",   "-",     "-"),
}


def host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def repo_owner(url):
    """github.com/ORG/repo -> ORG. Owner change is a stronger signal than a
    bare URL change, which is often just a rename."""
    p = [x for x in urlparse(url or "").path.split("/") if x]
    return p[0].lower() if p else ""


def secret_inputs(server):
    """Names of every input the publisher marked isSecret, across headers,
    env vars and args. A new credential requirement appearing mid-life means
    the trust envelope grew after adoption."""
    out = set()

    def walk(items):
        for it in items or []:
            if isinstance(it, dict) and it.get("isSecret"):
                out.add(it.get("name") or it.get("valueHint") or "?")

    for pkg in server.get("packages") or []:
        walk(pkg.get("environmentVariables"))
        walk(pkg.get("packageArguments"))
        walk(pkg.get("runtimeArguments"))
        t = pkg.get("transport") or {}
        walk(t.get("headers"))
    for rem in server.get("remotes") or []:
        walk(rem.get("headers"))
    return out


def remote_hosts(server):
    return {host(r.get("url", "")) for r in (server.get("remotes") or []) if r.get("url")}


def transport_types(server):
    ts = {r.get("type") for r in (server.get("remotes") or []) if r.get("type")}
    for p in server.get("packages") or []:
        t = (p.get("transport") or {}).get("type")
        if t:
            ts.add(t)
    return ts


def pkg_signature(server):
    return {
        (p.get("registryType"), p.get("identifier"))
        for p in (server.get("packages") or [])
    }


def transitions(a, b):
    """Field-level transitions from server record a to b."""
    out = []

    if a.get("description") != b.get("description"):
        out.append("description_changed")

    ra, rb = a.get("repository") or {}, b.get("repository") or {}
    if ra and not rb:
        out.append("repo_removed")
    elif rb and not ra:
        out.append("repo_added")
    elif ra and rb:
        if ra.get("id") and rb.get("id") and ra["id"] != rb["id"]:
            out.append("repo_id_changed")
        if repo_owner(ra.get("url")) != repo_owner(rb.get("url")):
            out.append("repo_owner_changed")

    sa, sb = pkg_signature(a), pkg_signature(b)
    if sa and sb and sa != sb:
        types_a = {t for t, _ in sa}
        types_b = {t for t, _ in sb}
        if types_a != types_b:
            out.append("package_registry_switch")
        ids_a = {i for _, i in sa}
        ids_b = {i for _, i in sb}
        if ids_a != ids_b:
            out.append("package_identifier_changed")

    ha, hb = remote_hosts(a), remote_hosts(b)
    if ha and hb and ha != hb:
        if hb - ha and ha - hb:
            out.append("remote_host_changed")
        elif hb - ha:
            out.append("remote_host_added")
        elif ha - hb:
            out.append("remote_host_removed")

    if transport_types(a) != transport_types(b):
        out.append("transport_type_changed")

    if secret_inputs(b) - secret_inputs(a):
        out.append("secret_input_added")

    if host(a.get("websiteUrl", "")) and host(a.get("websiteUrl", "")) != host(b.get("websiteUrl", "")):
        out.append("website_host_changed")

    if a.get("$schema") != b.get("$schema"):
        out.append("schema_version_changed")

    return out


def cmd_chain(store, snapshot):
    db = store.db
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """SELECT server_name, version, content_hash, published_at, status
           FROM observations WHERE snapshot_date=?
           ORDER BY server_name, published_at, version""",
        (snapshot,),
    ).fetchall()

    by_server = {}
    for r in rows:
        by_server.setdefault(r["server_name"], []).append(r)

    events, counts = [], Counter()
    multi = 0
    for name, chain in by_server.items():
        if len(chain) < 2:
            continue
        multi += 1
        for prev, cur in zip(chain, chain[1:]):
            a = store.get_blob(prev["content_hash"])
            b = store.get_blob(cur["content_hash"])
            for t in transitions(a, b):
                sev, asi, nist = RUBRIC.get(t, ("info", "-", "-"))
                counts[t] += 1
                events.append({
                    "server": name,
                    "from_version": prev["version"],
                    "to_version": cur["version"],
                    "from_published": prev["published_at"],
                    "to_published": cur["published_at"],
                    "transition": t,
                    "severity": sev,
                    "owasp_asi": asi,
                    "nist_ai_rmf": nist,
                })

    return {
        "snapshot": snapshot,
        "servers_total": len(by_server),
        "servers_with_multiple_versions": multi,
        "version_pairs": sum(max(0, len(c) - 1) for c in by_server.values()),
        "transition_counts": dict(counts.most_common()),
        "events": events,
    }


def cmd_silent(store, frm, to):
    db = store.db
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """SELECT a.server_name, a.version,
                  a.content_hash  AS old_content, b.content_hash  AS new_content,
                  a.envelope_hash AS old_env,     b.envelope_hash AS new_env,
                  a.status AS old_status, b.status AS new_status,
                  a.updated_at AS old_updated, b.updated_at AS new_updated
           FROM observations a
           JOIN observations b
             ON a.server_name=b.server_name AND a.version=b.version
           WHERE a.snapshot_date=? AND b.snapshot_date=?""",
        (frm, to),
    ).fetchall()

    silent, status_flips = [], []
    for r in rows:
        if r["old_content"] != r["new_content"]:
            a = store.get_blob(r["old_content"])
            b = store.get_blob(r["new_content"])
            silent.append({
                "server": r["server_name"],
                "version": r["version"],
                "transitions": transitions(a, b),
                "updated_at_moved": r["old_updated"] != r["new_updated"],
                "old_content_hash": r["old_content"],
                "new_content_hash": r["new_content"],
            })
        elif r["old_env"] != r["new_env"] and r["old_status"] != r["new_status"]:
            status_flips.append({
                "server": r["server_name"],
                "version": r["version"],
                "from": r["old_status"],
                "to": r["new_status"],
            })

    a_keys = {(r["server_name"], r["version"]) for r in rows}
    added = db.execute(
        """SELECT server_name, version FROM observations WHERE snapshot_date=?""",
        (to,),
    ).fetchall()
    new_records = [
        {"server": s, "version": v}
        for s, v in ((r["server_name"], r["version"]) for r in added)
        if (s, v) not in a_keys
    ]

    return {
        "from": frm,
        "to": to,
        "compared_version_records": len(rows),
        "silent_edits": silent,
        "silent_edit_count": len(silent),
        "silent_edits_without_updated_at_bump": sum(
            1 for s in silent if not s["updated_at_moved"]
        ),
        "status_flips": status_flips,
        "new_version_records": len(new_records),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["chain", "silent"])
    ap.add_argument("--data", default="data")
    ap.add_argument("--snapshot")
    ap.add_argument("--from", dest="frm")
    ap.add_argument("--to")
    ap.add_argument("--out")
    ap.add_argument("--summary-only", action="store_true")
    args = ap.parse_args()

    store = Store(args.data)
    if args.mode == "chain":
        res = cmd_chain(store, args.snapshot)
    else:
        res = cmd_silent(store, args.frm, args.to)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(res, f, indent=2)
    if args.summary_only:
        res = {k: v for k, v in res.items() if k not in ("events", "silent_edits")}
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()