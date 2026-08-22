# Lab notebook

Running log of collection runs, decisions, and observations. Append only, do
not rewrite history. If a number here turns out to be wrong, add a correction
below it rather than editing it. The point of this file is that a reader can
reconstruct what I knew and when I knew it.

---

## 2026-08-22 — first full snapshot

Command:

    python3 collect.py --data data

Result:

    pages             806
    version_records   80578
    distinct_servers  24777
    new_blobs         80578
    duplicate_keys    0

Notes:

- Versions per server: 80578 / 24777 = 3.25 average.
- `duplicate_keys: 0` confirms `(name, version)` is a valid primary key for a
  single snapshot. Every downstream count depends on this, so it is checked on
  every run rather than assumed.
- This count includes deleted servers (`include_deleted=true`). Deleted servers
  are hidden from the default listing but are the most interesting population
  for a rug-pull study, so they are collected deliberately. Any comparison to a
  published server count from another source has to account for this.
- My starting assumption was ~9,600 servers. Off by roughly 2.5x. Recording the
  wrong prior on purpose so the writeup can say where the number came from.

Environment issue: macOS Python could not verify TLS certificates on the first
attempt (`CERTIFICATE_VERIFY_FAILED`). Not a registry issue. Fixed by
installing the certifi bundle. The failed run is recorded in the `runs` table
with `ok=0` and was superseded by the successful run above.

---

## Open questions

- [ ] What is the count with `version=latest` only, versus all versions?
- [ ] Status breakdown: how many active / deprecated / deleted?
- [ ] What fraction of servers are package-backed vs remote-only? Remote servers
      have a mutable runtime surface the registry cannot see, so this bounds
      what the study can and cannot claim.
- [ ] How far back does the earliest `publishedAt` go? That is the true window
      of the retrospective analysis.

---

## Decisions and why

- **Full pull daily, not `updated_since`.** The study is testing whether the
  registry's immutability guarantee holds. An in-place edit that does not touch
  `updatedAt` is invisible to incremental sync by construction, so trusting it
  would be circular. The incremental query is run separately as a cross-check,
  and the gap between the two answers is itself a result.
- **Two hashes per record.** `content_hash` covers the part claimed immutable;
  `envelope_hash` covers status and timestamps. One combined hash would merge
  "silent in-place edit" with "status flipped to deprecated," which are
  completely different events.
- **Deterministic rules, no classifier.** Prior work found under half of
  existing MCP scanner alerts survive manual validation. A heuristic stack is
  not going to beat that. Reproducibility and honest bounds are worth more than
  apparent sophistication.