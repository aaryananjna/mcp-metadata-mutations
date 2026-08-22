#!/usr/bin/env python3
"""
Daily collector for the official MCP Registry.

    python3 collect.py                      # full pull, today's date
    python3 collect.py --date 2026-08-21    # override snapshot label
    python3 collect.py --fixture fixtures/page_real.json   # offline test
    python3 collect.py --since 2026-08-20T00:00:00Z --tag incremental

Why stdlib only: this runs unattended on a schedule for three months. Every
dependency is a chance for a transitive break to silently kill a day of data.
urllib is ugly and it is never going to move out from under you.

Why a FULL pull every day and not `updated_since`:
The registry documents server.json as immutable post-publication, and offers
`updated_since` for cheap incremental sync. Trusting that is circular: the
whole point of this study is to test whether the immutability guarantee holds.
An in-place edit that does not touch `updatedAt` is invisible to an incremental
sync by construction. So we pull everything, hash everything, and separately
run the incremental query. The DIFFERENCE between the two is a result:

    silent_edits = {changed by content hash} - {reported by updated_since}

That set is expected to be empty. Publishing a well-measured empty set is a
real finding, and if it is ever non-empty it is a significant one.

Cost of a full pull: ~100 pages at limit=100. At one run per day that is well
inside the "regular but infrequent (e.g. once per hour)" guidance the registry
gives to aggregators.
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
USER_AGENT = (
    "mcp-registry-longitudinal-study/0.1 "
    "(academic measurement; contact: anjna.aaryan@gmail.com)"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_page(cursor=None, since=None, include_deleted=True, timeout=30,
               max_retries=5):
    """One page, with exponential backoff.

    include_deleted defaults to True. Deleted servers are the most interesting
    population in a rug-pull study and the default listing hides them. Note the
    API forces include_deleted=True whenever updated_since is supplied, so this
    keeps the two query modes comparable.
    """
    params = {"limit": PAGE_LIMIT}
    if cursor:
        params["cursor"] = cursor
    if since:
        params["updated_since"] = since
    if include_deleted:
        params["include_deleted"] = "true"

    url = f"{BASE}{LIST_PATH}?" + urllib.parse.urlencode(params)
    delay = 2.0
    last_err = None

    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code} for {url}"
            # 4xx other than 429 will not fix themselves; fail fast and loud.
            if e.code != 429 and 400 <= e.code < 500:
                raise RuntimeError(last_err) from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(delay)
        delay *= 2

    raise RuntimeError(f"giving up after {max_retries} attempts: {last_err}")


def iter_records(fixture=None, since=None, sleep=0.5, verbose=True):
    """Yield (record, page_number). Cursor pagination with a loop guard."""
    if fixture:
        with open(fixture) as f:
            page = json.load(f)
        for rec in page.get("servers", []):
            yield rec, 1
        return

    cursor, page_no, seen_cursors = None, 0, set()
    while True:
        page = fetch_page(cursor=cursor, since=since)
        page_no += 1
        records = page.get("servers", [])
        for rec in records:
            yield rec, page_no

        meta = page.get("metadata") or {}
        nxt = meta.get("nextCursor")
        if verbose:
            print(f"  page {page_no}: {len(records)} records, next={nxt!r}",
                  file=sys.stderr)
        if not nxt:
            break
        # A repeated cursor means the server is looping us. Bail rather than
        # spin forever on a scheduled job nobody is watching.
        if nxt in seen_cursors:
            raise RuntimeError(f"cursor loop detected at {nxt!r}")
        seen_cursors.add(nxt)
        cursor = nxt
        time.sleep(sleep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--date", default=None, help="snapshot label, default UTC today")
    ap.add_argument("--fixture", default=None, help="read a saved page instead of HTTP")
    ap.add_argument("--since", default=None, help="RFC3339; runs incremental mode")
    ap.add_argument("--tag", default=None, help="suffix for the snapshot label")
    ap.add_argument("--sleep", type=float, default=0.5, help="seconds between pages")
    args = ap.parse_args()

    label = args.date or datetime.now(timezone.utc).date().isoformat()
    if args.tag:
        label = f"{label}:{args.tag}"

    started = now_iso()
    store = Store(args.data)
    store.start_run(label, started)

    pages = records = new_blobs = 0
    dupe_keys = 0
    seen_keys = set()

    try:
        for rec, page_no in iter_records(fixture=args.fixture, since=args.since,
                                         sleep=args.sleep):
            pages = max(pages, page_no)
            records += 1
            server = rec.get("server", {})
            key = (server.get("name"), server.get("version"))
            if key in seen_keys:
                # (name, version) is the assumed primary key. If the API ever
                # returns it twice in one snapshot, that assumption is wrong and
                # every downstream count is wrong. Count it, do not swallow it.
                dupe_keys += 1
            seen_keys.add(key)
            if store.record_observation(label, started, rec):
                new_blobs += 1
            if records % 1000 == 0:
                store.commit()
        store.commit()
        store.finish_run(label, now_iso(), pages, records, new_blobs, ok=True)
    except Exception as e:  # noqa: BLE001 - we want the reason persisted
        store.commit()
        store.finish_run(label, now_iso(), pages, records, new_blobs,
                         ok=False, error=f"{type(e).__name__}: {e}")
        print(f"FAILED: {e}", file=sys.stderr)
        raise

    distinct_servers = len({k[0] for k in seen_keys})
    print(json.dumps({
        "snapshot": label,
        "pages": pages,
        "version_records": records,
        "distinct_servers": distinct_servers,
        "new_blobs": new_blobs,
        "duplicate_keys": dupe_keys,
    }, indent=2))


if __name__ == "__main__":
    main()