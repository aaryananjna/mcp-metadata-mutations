#!/usr/bin/env python3
"""
Daily collector for the official MCP Registry.

    python3 collect.py                                    # full pull, today
    python3 collect.py --date 2026-08-22                  # override label
    python3 collect.py --fixture fixtures/page_real.json  # offline test
    python3 collect.py --since 2026-08-21T00:00:00Z       # incremental log

Why stdlib only: this runs unattended on a schedule for three months. Every
dependency is a chance for a transitive break to silently kill a day of data.
urllib is ugly and it is never going to move out from under you.

Why a FULL pull every day and not `updated_since`:
The registry documents server.json as immutable post-publication and offers
`updated_since` for cheap incremental sync. Trusting that is circular: the
point of this study is to test whether the immutability guarantee holds. An
in-place edit that does not touch `updatedAt` is invisible to incremental sync
by construction. So we pull everything, hash everything, and run the
incremental query SEPARATELY as a cross-check. The difference between the two
answers is a result:

    silent_edits = {changed by content hash} - {reported by updated_since}

That set is expected to be empty. Publishing a well-measured empty set is a
real finding, and a non-empty one is a significant finding.

Cost: ~800 pages at limit=100. Once a day is well inside the "regular but
infrequent (e.g. once per hour)" guidance the registry gives aggregators.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from store import Store

BASE = "https://registry.modelcontextprotocol.io"
LIST_PATH = "/v0.1/servers"
PAGE_LIMIT = 100  # documented maximum
USER_AGENT = ("mcp-registry-longitudinal-study/0.2 "
              "(academic measurement; contact: YOUR_EMAIL_HERE)")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_page(cursor=None, since=None, include_deleted=True, timeout=30,
               max_retries=5):
    """One page, with exponential backoff.

    include_deleted defaults to True. Deleted servers are the most interesting
    population in a rug-pull study and the default listing hides them. The API
    forces include_deleted=True whenever updated_since is supplied, so this
    keeps the two query modes comparable.
    """
    params = {"limit": PAGE_LIMIT}
    if cursor:
        params["cursor"] = cursor
    if since:
        params["updated_since"] = since
    if include_deleted:
        params["include_deleted"] = "true"

    url = BASE + LIST_PATH + "?" + urllib.parse.urlencode(params)
    delay, last_err = 2.0, None

    for _ in range(max_retries):
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = "HTTP %s for %s" % (e.code, url)
            # 4xx other than 429 will not fix themselves. Fail fast and loud.
            if e.code != 429 and 400 <= e.code < 500:
                raise RuntimeError(last_err) from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = "%s: %s" % (type(e).__name__, e)
        time.sleep(delay)
        delay *= 2

    raise RuntimeError("giving up after %d attempts: %s" % (max_retries, last_err))


def iter_records(fixture=None, since=None, sleep=0.5, verbose=True):
    """Yield (record, page_number). Cursor pagination with a loop guard."""
    if fixture:
        with open(fixture) as f:
            page = json.load(f)
        for rec in page.get("servers", []):
            yield rec, 1
        return

    cursor, page_no, seen = None, 0, set()
    while True:
        page = fetch_page(cursor=cursor, since=since)
        page_no += 1
        records = page.get("servers", [])
        for rec in records:
            yield rec, page_no

        nxt = (page.get("metadata") or {}).get("nextCursor")
        if verbose and page_no % 50 == 0:
            print("  page %d ..." % page_no, file=sys.stderr)
        if not nxt:
            break
        # A repeated cursor means the server is looping us. Bail rather than
        # spin forever on a scheduled job nobody is watching.
        if nxt in seen:
            raise RuntimeError("cursor loop detected at %r" % nxt)
        seen.add(nxt)
        cursor = nxt
        time.sleep(sleep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--date", default=None, help="snapshot label, default UTC today")
    ap.add_argument("--fixture", default=None, help="read a saved page instead of HTTP")
    ap.add_argument("--since", default=None, help="RFC3339; runs incremental mode")
    ap.add_argument("--sleep", type=float, default=0.5, help="seconds between pages")
    args = ap.parse_args()

    label = args.date or datetime.now(timezone.utc).date().isoformat()
    store = Store(args.data)

    # Incremental mode is a side log, never part of the state machine. It
    # returns a subset of the registry, so feeding it to the interval logic
    # would look like every unreturned server had vanished.
    if args.since:
        recs = [r for r, _ in iter_records(since=args.since, sleep=args.sleep)]
        store.log_incremental(label, args.since, recs)
        print(json.dumps({"mode": "incremental", "snapshot": label,
                          "since": args.since, "reported": len(recs)}, indent=2))
        return

    started = now_iso()
    store.begin_snapshot(label, started)

    pages = records = new_blobs = dupes = 0
    keys = set()
    try:
        for rec, page_no in iter_records(fixture=args.fixture, sleep=args.sleep):
            pages = max(pages, page_no)
            records += 1
            s = rec.get("server", {}) or {}
            k = (s.get("name"), s.get("version"))
            # (name, version) is the assumed primary key. If the API ever
            # returns it twice in one snapshot that assumption is wrong and
            # every downstream count is wrong. Count it, do not swallow it.
            if k in keys:
                dupes += 1
            keys.add(k)
            if store.observe(rec, started):
                new_blobs += 1
            if records % 2000 == 0:
                store.commit()
        opened, closed = store.end_snapshot(now_iso(), pages, records, new_blobs, ok=True)
    except Exception as e:
        store.end_snapshot(now_iso(), pages, records, new_blobs, ok=False,
                           error="%s: %s" % (type(e).__name__, e))
        print("FAILED: %s" % e, file=sys.stderr)
        raise

    print(json.dumps({
        "snapshot": label,
        "pages": pages,
        "version_records": records,
        "distinct_servers": len({k[0] for k in keys}),
        "new_blobs": new_blobs,
        "states_opened": opened,
        "states_closed": closed,
        "duplicate_keys": dupes,
    }, indent=2))


if __name__ == "__main__":
    main()