#!/usr/bin/env python3
"""
Re-hash stored blobs and confirm every hash still matches its filename.

This is the whole reason to content-address rather than to just gzip a daily
dump. Storage was never the problem: ~9.6k records at a few hundred bytes each
is single-digit megabytes a day even uncompressed. The reason the hash is the
filename is that it makes the dataset self-verifying. Anyone who downloads it
can confirm, without trusting you, that the record you claim the registry
served on day N is byte-identical to what you stored on day N.

    python3 verify.py --data data              # verify everything
    python3 verify.py --data data --sample 500 # spot check, for CI
"""

import argparse
import random
import sys

from store import Store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--sample", type=int, default=0, help="0 = check all")
    args = ap.parse_args()

    store = Store(args.data)
    hashes = [r[0] for r in store.db.execute("SELECT content_hash FROM blobs")]
    if args.sample and args.sample < len(hashes):
        random.seed(0)  # deterministic spot check
        hashes = random.sample(hashes, args.sample)

    bad = [h for h in hashes if not store.verify_blob(h)]
    print(f"checked {len(hashes)} blobs, {len(bad)} corrupt")
    if bad:
        for h in bad[:20]:
            print(f"  CORRUPT {h}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()