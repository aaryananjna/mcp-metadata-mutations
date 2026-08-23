# Lab notebook

Running log of collection runs, decisions, and observations. Append only. If a
number here turns out to be wrong, add a correction below it rather than editing
it. The point of this file is that a reader can reconstruct what I knew and when.

---

## 2026-08-22 — first full snapshot

    pages             807
    version_records   80,636
    distinct_servers  24,791
    states_opened     80,636
    states_closed     0
    duplicate_keys    0

Consistency checks that passed:

- `duplicate_keys = 0` confirms `(name, version)` is a valid primary key within
  a snapshot. Every downstream count depends on this, so it is asserted on every
  run rather than assumed.
- `is_latest = 1` count equals `distinct_servers` exactly. Every server has
  exactly one latest version, no more and no fewer.
- Status counts sum exactly to the record total, so no record has a null status.

Population:

    status active             78,522
    status deleted             1,246
    status deprecated            810
    servers with >1 version    9,812  (39.6% of 24,791)
    consecutive version pairs 55,801
    mean versions per server    3.25
    earliest publishedAt      2025-09-08  (registry preview launch)

The retrospective window is therefore 2025-09-08 to 2026-08-22, about 11.5
months, available on day one. The list endpoint returns every version ever
published, not just the latest, so the full version history did not require
waiting for calendar time to pass.

My starting assumption was ~9,600 servers. Off by roughly 2.5x. Recording the
wrong prior on purpose so the writeup can say where the number came from. Part
of the gap is that this collector passes `include_deleted=true`, so it sees
records the default public listing hides.

An earlier run the same day returned 80,578 records and 24,777 servers. The
delta of 58 records and 14 servers over a few hours is a free organic growth
datapoint.

---

## 2026-08-22 — detector audits

### package_identifier_changed: over-reported by 24x

    raw firings                    7,069
    artifact_version_in_name       4,401  (62.3%)
    artifact_version_in_url        2,285  (32.3%)
    real_rename                      196  ( 2.8%)
    url_changed_beyond_version       103  ( 1.5%)
    package_count_changed             84  ( 1.2%)
    defensible                       299  ( 4.2% of raw)

Root cause: the `identifier` field carries the version inside the string for OCI
images (`ghcr.io/org/name:v1.2.3`) and MCPB download URLs. Every routine release
therefore changes the identifier and trips a naive equality check. My first
hypothesis was that MCPB URLs dominated; the audit showed OCI tags were about
twice as common. Directionally right, specifics wrong.

The 84 `package_count_changed` cases are unresolved and excluded from the
defensible count pending manual review. Adding an OCI image alongside an
existing npm package is benign; dropping one is not.

### repo_owner_changed: over-reported by ~3.6x

    raw firings                      192
    converged_to_namespace            72  (37.5%)
    both_match_namespace              49  (25.5%)
    diverged_from_namespace           39  (20.3%)  SIGNAL
    unrelated                         14  ( 7.3%)  SIGNAL
    case_or_punctuation_only           7  ( 3.6%)
    forge_changed                      5  ( 2.6%)
    placeholder_replaced               3  ( 1.6%)
    substring_related                  2  ( 1.0%)
    homoglyph_confusable               1  ( 0.5%)
    defensible                        53  (27.6% of raw)

`converged_to_namespace` at 72 is arguably more interesting than the
divergences: those are servers whose repository URL pointed at an account the
publisher did not control, and which was later corrected. They spent real
calendar time in a live registry pointing at the wrong place.

`diverged_from_namespace` is still heterogeneous. Manual review of 25 samples
suggests roughly three quarters are solo developers graduating to a company org
(`ned-del` -> `fairseal-io`, `fahassan00` -> `bounceprotect`), which is benign,
and roughly one quarter go the other way, org to individual account:

    giveradar        -> matt-timmermans
    topvisor         -> Artemeey
    gvnrdev          -> mightbesaad
    plantrip         -> klabianco
    provision-stack  -> TravisLinkey
    muovi-ar         -> mmiani

That direction narrows who is accountable for the code after adoption, which is
the concerning one. Splitting it needs the GitHub API (User vs Organization),
since it cannot be computed from registry data alone.

One case flagged for manual follow-up: `dev.sexai/sexai-mcp` moved from
`sexaidev/sexai-mcp` to `sxaidev/sxai-mcp`, a single character deleted from both
the org and the repository name, under a namespace still spelled `sexai`.

### The pattern worth naming

Both detectors that fired more than a hundred times lost roughly three quarters
of their firings to subclassification. **A detector count is a hypothesis, not a
finding.** Nothing gets reported without an audit of the underlying strings.
This is also why raw counts stay in the writeup alongside corrected ones: the
correction ratio is itself a result about how noisy naive scanning of this
ecosystem is.

---

## 2026-08-22 — DISCLOSURE: unvalidated repository URLs

Found via `audit.py --placeholders`: 5 version records across 4 servers carry
unedited template values in `repository.url`, all with status `active`.

    com.nursinghomedatabase/mcp                 1.0.0   github.com/YOUR_GITHUB_USERNAME/...
    io.github.SpearmanMODE/nexus-alpha-geometry 0.1.0   github.com/YOUR_GITHUB_USERNAME/...
    io.github.SpearmanMODE/nexus-alpha-geometry 0.1.1   github.com/YOUR_GITHUB_USERNAME/...
    io.github.poojaBjAcharya/cdgcsearchmetadata 1.0.0   github.com/example/remote-fs
    so.pharaoh/pharaoh                          1.0.0   github.com/YOUR_ORG/pharaoh-mcp

Checked against the GitHub API on 2026-08-22:

    YOUR_GITHUB_USERNAME   404, does not exist, registerable
    YOUR_ORG               404, does not exist, registerable
    example                exists, User account created 2009-02-25

Implication: the registry verifies namespace ownership at publication but does
not appear to validate that the supplied `repository.url` resolves or that the
publisher controls the referenced account. A third party could register either
unclaimed name and become the apparent source-of-truth repository for those
entries.

I did not register or interact with any of these accounts.

Severity, honestly: low. This may well be a known and accepted design choice
rather than a defect. Reporting anyway because it costs little and the response
is itself worth recording.

    reported to    github.com/modelcontextprotocol/registry, private advisory
    date reported  TODO
    embargo        30 days on specific server names; aggregate stats unembargoed
    response       TODO

---

## Decisions and why

- **Full pull daily, not `updated_since`.** The study tests whether the
  registry's immutability guarantee holds. An in-place edit that does not touch
  `updatedAt` is invisible to incremental sync by construction, so trusting it
  would be circular. The incremental query runs separately as a cross-check and
  the gap between the two answers is itself a result.

- **Two hashes per record.** `content_hash` covers the part claimed immutable;
  `envelope_hash` also covers status and timestamps. One combined hash would
  merge "silent in-place edit" with "status flipped to deprecated," which are
  completely different events.

- **Canonical JSON before hashing.** Sorted keys, tight separators. Hashing raw
  response bytes would produce a fleet-wide false positive the first time
  upstream reorders a field.

- **Interval-encoded storage (v2).** v1 stored one row per snapshot per record,
  growing ~80k rows a day into a 62MB binary that git re-stored in full on every
  commit, heading for multiple gigabytes over 12 weeks. v2 stores one row per
  distinct state with first_seen and last_seen, so the table grows with actual
  change rather than with calendar time.

- **The sqlite index is gitignored.** It is derived data, rebuildable from the
  committed delta manifests via `python3 store.py data`. What gets committed is
  the content-addressed blob store and the per-day manifests. Never put the only
  copy of anything in a database.

- **Content addressing is for evidence, not storage.** Storage was never the
  constraint. The hash being the filename means anyone can verify that the
  record I claim the registry served on day N is byte-identical to what I
  stored, without trusting me.

- **Deterministic rules, no classifier.** Prior work found under half of
  existing MCP scanner alerts survive manual validation. A heuristic stack will
  not beat that. Reproducibility and honest bounds are worth more than apparent
  sophistication. `test_classify.py` pins the classifier against 15 hand-labeled
  real samples so a future change cannot silently break it.

- **One writer.** The GitHub Action owns collection; I only analyze locally.
  Running the collector in both places produces competing manifests for the same
  date and a merge conflict every day. Local loop is now:
  `git pull` -> `python3 store.py data` -> analyze.

- **Passive collection only.** Registry API reads, plus public GitHub API
  lookups for account type. No connections to `remotes[]` endpoints, no package
  execution, no probing of anyone's infrastructure. This bounds what the study
  can claim: the registry is the identity and pointer layer, so this measures
  ASI04-style supply chain pointer mutation, not ASI02 tool description
  poisoning. Tool descriptions do not appear in registry records at all, and the
  `description` field is capped at 100 characters, so the registry is
  structurally not where description poisoning happens.

---

## Open questions

- [ ] Split `diverged_from_namespace` by direction using GitHub User vs
      Organization. Org -> personal is the signal.
- [ ] Hand-audit all 47 `repo_id_changed`. The schema names this field as the
      repository-resurrection detector, so this is the sharpest small set.
- [ ] Subclassify `secret_input_added` (516) and `remote_host_changed` (530).
- [ ] Resolve the 84 `package_count_changed` cases.
- [ ] Near-miss naming analysis across all server and owner names, seeded by the
      `sexai` -> `sxai` case.
- [ ] What fraction of servers are remote-only vs package-backed? Remote servers
      have a mutable runtime surface the registry cannot see, which bounds what
      this study can claim.
- [ ] Comparison population: PulseMCP runs a sub-registry mirroring the same
      spec but states it does not guarantee immutability. Same instrument, two
      populations, one of which admits to mutating.

      ## 2026-08-22 (evening) — correction: dangling owner scan


- -  - - - -  - - - -  - - - - - -  - - - - - - -  - - - - - - - - - - -
Reported 238 "unregistered" GitHub owners. That label was wrong. A 404 from
GET /users/{login} means "not visible to this token", which covers free names,
restricted/enterprise orgs, and transient blocks. Caught by opening two flagged
orgs (bap-microsoft, sherweb-development) in a browser and finding a sign-in
wall rather than a 404 page.

Metric relabelled to "not publicly resolvable": ~2% of currently-installable
servers (382 of 19,242 with a GitHub repo) reference a repository the public
cannot read. That is a weaker claim and a defensible one.

Disclosure held. Nothing reported. A finding that cannot survive questioning
should not be sent to a vendor.