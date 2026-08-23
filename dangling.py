#!/usr/bin/env python3
"""
Scan every repository owner referenced in a snapshot and find the ones that no
longer exist on GitHub.

WHAT THIS MEASURES, PRECISELY. A 404 from GET /users/{login} means "no account
with that login is visible to the requesting token." It does NOT mean the name
is unregistered. At least three states collapse into that one status code:

  1. The name is genuinely free and registerable by anyone.
  2. The org exists but is enterprise-managed or otherwise restricted, and
     GitHub returns 404 to non-members rather than confirming it exists.
  3. A transient block: anonymous browsing walls, bot checks, secondary limits.

An earlier version of this script labelled all of these "missing" and reported
them as claimable names. That was wrong, and it was caught by opening two of the
flagged orgs in a browser and finding a sign-in wall rather than a 404 page.

So the defensible claim is the weaker one: these repository URLs are NOT
PUBLICLY RESOLVABLE. A public registry entry pointing at a repository the public
cannot read is a genuine supply-chain transparency gap, and unlike the takeover
claim it follows directly from what was measured.

Deciding which of the three states any individual case is in requires manual
adjudication against a known-negative control. See --control.

    export GITHUB_TOKEN=ghp_...
    python3 dangling.py --snapshot 2026-08-22 --token "$GITHUB_TOKEN"
    python3 dangling.py --snapshot 2026-08-22 --token "$GITHUB_TOKEN" --latest-only

Resumable. Every lookup is cached to disk, so Ctrl-C and restart costs nothing.
Rate limited to stay inside GitHub's 5,000/hour authenticated budget; it reads
the response headers rather than guessing, and sleeps when the window runs low.

Expect a few thousand distinct owners and roughly an hour. Run it and go away.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

from classify import owner
from store import Store

API = "https://api.github.com/users/"


class OwnerResolver:
    def __init__(self, token=None, cache_path="data/github_owner_cache.json"):
        self.token = token
        self.cache_path = Path(cache_path)
        self.cache = {}
        if self.cache_path.exists():
            self.cache = json.loads(self.cache_path.read_text())
        self.dirty = 0
        self.remaining = None

    def _save(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, indent=0, sort_keys=True))
        self.dirty = 0

    def resolve(self, login):
        if login in self.cache:
            return self.cache[login]

        # Respect the budget by reading it, not by assuming it. Unauthenticated
        # is 60/hour, authenticated 5,000, and burning through it gets you 403s
        # for the rest of the window.
        if self.remaining is not None and self.remaining < 20:
            print("  rate limit low, sleeping 60s", file=sys.stderr)
            time.sleep(60)
            self.remaining = None

        req = urllib.request.Request(API + login, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mcp-registry-longitudinal-study"})
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)

        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                self.remaining = int(r.headers.get("X-RateLimit-Remaining", 1000))
                kind = json.loads(r.read()).get("type", "unknown")
        except urllib.error.HTTPError as e:
            self.remaining = int(e.headers.get("X-RateLimit-Remaining", 1000)) \
                if e.headers.get("X-RateLimit-Remaining") else self.remaining
            if e.code == 404:
                # NOT "does not exist". See the module docstring: this is
                # "not visible to this token", which is three states at once.
                kind = "unresolvable"
            elif e.code in (403, 429):
                print("  rate limited, sleeping 120s", file=sys.stderr)
                time.sleep(120)
                return self.resolve(login)
            else:
                return "error_%s" % e.code       # transient, not cached
        except Exception:
            return "unknown"                     # transient, not cached

        self.cache[login] = kind
        self.dirty += 1
        if self.dirty >= 25:
            self._save()
        return kind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--token", help="GitHub token; no scopes needed")
    ap.add_argument("--latest-only", action="store_true",
                    help="only the current version of each server")
    ap.add_argument("--out", default="reports/dangling.json")
    args = ap.parse_args()

    store = Store(args.data)
    rows = store.states_at(args.snapshot)

    # owner login -> list of (server, version, is_latest, status, url)
    refs = defaultdict(list)
    forge_other = 0
    no_repo = 0
    scanned = 0

    for r in rows:
        if args.latest_only and not r["is_latest"]:
            continue
        scanned += 1
        rec = store.get_blob(r["content_hash"])
        url = (rec.get("repository") or {}).get("url")
        if not url:
            no_repo += 1
            continue
        if "github.com" not in url:
            forge_other += 1
            continue
        lg = owner(url)
        if lg:
            refs[lg].append((r["server_name"], r["version"],
                             r["is_latest"], r["status"], url))

    with_gh = scanned - no_repo - forge_other
    print("records in snapshot     : %d" % len(rows))
    print("records scanned         : %d%s"
          % (scanned, "  (latest version of each server)" if args.latest_only else ""))
    print("  no repository field   : %d  (%.1f%%)"
          % (no_repo, 100.0 * no_repo / max(1, scanned)))
    print("  non-GitHub forge      : %d" % forge_other)
    print("  with a GitHub repo    : %d  <-- denominator for the rate below"
          % with_gh)
    print("  distinct GitHub owners: %d" % len(refs))

    resolver = OwnerResolver(args.token)
    cached = sum(1 for lg in refs if lg in resolver.cache)
    print("  already cached        : %d" % cached)
    print("  to look up            : %d\n" % (len(refs) - cached))

    if not args.token:
        print("WARNING: no token. Unauthenticated is 60 lookups/hour, so this "
              "will take days. Pass --token.\n", file=sys.stderr)

    # Known-negative control. If these do not come back unresolvable, the
    # resolver itself is broken and every number below is meaningless.
    controls = ["zzq-does-not-exist-" + s for s in ("aaa", "bbb", "ccc")]
    ctl = {c: resolver.resolve(c) for c in controls}
    bad_ctl = [c for c, k in ctl.items() if k != "unresolvable"]
    print("control probe: %s" % ("PASS" if not bad_ctl else "FAIL %s" % bad_ctl))
    if bad_ctl:
        sys.exit("resolver is not distinguishing states correctly; aborting")

    kinds = {}
    for i, lg in enumerate(sorted(refs), 1):
        kinds[lg] = resolver.resolve(lg)
        if i % 200 == 0:
            print("  %d/%d resolved" % (i, len(refs)), file=sys.stderr)
    resolver._save()

    missing = {lg: refs[lg] for lg, k in kinds.items() if k == "unresolvable"}
    affected_records = sum(len(v) for v in missing.values())
    affected_servers = {s for v in missing.values() for s, _, _, _, _ in v}
    latest_hits = [(s, ver, url) for v in missing.values()
                   for s, ver, isl, st, url in v if isl]
    active_hits = sum(1 for v in missing.values()
                      for _, _, _, st, _ in v if st == "active")

    print("\n=== NOT PUBLICLY RESOLVABLE ===")
    print("NOTE: 404 means 'not visible to this token', which covers free names,")
    print("      restricted/enterprise orgs, AND transient blocks. Do not report")
    print("      these as claimable without adjudicating each one by hand.\n")
    print("unresolvable GitHub owners : %d  (%.2f%% of %d)"
          % (len(missing), 100.0 * len(missing) / max(1, len(refs)), len(refs)))
    print("version records affected   : %d  (%.2f%% of %d with a GitHub repo)"
          % (affected_records, 100.0 * affected_records / max(1, with_gh), with_gh))
    print("  of which status=active   : %d" % active_hits)
    print("distinct servers affected  : %d" % len(affected_servers))
    print("CURRENT versions affected  : %d   <-- the actionable set"
          % len(latest_hits))

    if latest_hits:
        print("\ncurrent versions pointing at an unresolvable owner:")
        for s, ver, url in sorted(latest_hits)[:60]:
            print("  %-52s %-10s %s" % (s[:52], ver, url))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump({
        "snapshot": args.snapshot,
        "latest_only": args.latest_only,
        "records_scanned": scanned,
        "records_with_github_repo": with_gh,
        "records_without_repo_field": no_repo,
        "distinct_owners": len(refs),
        "unresolvable_owners": len(missing),
        "caveat": ("404 = not visible to this token. Covers free names, "
                   "restricted/enterprise orgs, and transient blocks. Requires "
                   "manual adjudication before any claim of registerability."),
        "affected_version_records": affected_records,
        "affected_active_records": active_hits,
        "affected_servers": len(affected_servers),
        "affected_current_versions": len(latest_hits),
        "detail": {lg: [{"server": s, "version": v, "is_latest": bool(il),
                         "status": st, "url": u} for s, v, il, st, u in refs[lg]]
                   for lg in missing},
    }, open(args.out, "w"), indent=2)
    print("\nwrote %s" % args.out)


if __name__ == "__main__":
    main()