# mcp-metadata-mutations

Our MCP data collection checks if there are changes in the data after it has
been published, using the Model Context Protocol registry:
https://registry.modelcontextprotocol.io

There is an automatic data collection machine set up which collects data every
day on any changes detected, and my notes include more of my thoughts on it.

Current numbers: [`reports/RESULTS.md`](reports/RESULTS.md) (regenerated from
the data by `report.py`, never edited by hand)
Working notes and corrections: [`NOTES.md`](NOTES.md)

## Why

We want to answer questions about the rug pull threat model. So what is a rug
pull? A rug pull is a server that publishes metadata, then gets adopted, and
then changes. To measure that, you have to look at the same record repeatedly
to find changes. As of early 2026, no publicly disclosed, named victim of an
MCP rug pull had been identified, and the academic work that formalized the
attack did so without a large-scale empirical component. That gap is why I
built this: to measure whether and how records actually mutate after
publication, at ecosystem scale.

## What this actually measures (and what it doesn't)

The registry record only contains name, title, description (100 chars),
version, package coordinates, remote URL endpoints, and repo link. It does NOT
contain tool names, tool descriptions, or input schemas. Those are in the live
`tools/list` response from a running server.

1. The registry is the identity and pointer layer. So this study measures
   supply chain pointer mutation (OWASP ASI04), not tool description poisoning
   (ASI02). Don't expect a 100 character description field to be where
   injection happens.
2. This study also does not connect to third party servers to get tool-level
   data, and does not execute any published package.

## Method

A GitHub Action pulls every page of `/v0.1/servers` and hashes each record to
detect change, then commits the result. The study is testing whether the
registry's guarantee that records cannot change after publication actually
holds. A separate cross-check asks the API what it thinks changed, using
`updated_since`, and compares that against what the hashes detected. The
difference between those two answers is itself a measurement: an edit the
registry did not report is more interesting than one it did.

There are two hashes per record, the content_hash and the envelope_hash. The
content hash covers the server object (the immutable part), and the envelope
hash also covers status and timestamps. Keeping them separate matters because a
silent in-place edit and a status flip to deprecated are completely different
events, and one combined hash would smear them together.

## First full snapshot, 2026-08-22

    pages             807
    version_records   80,636
    distinct_servers  24,791
    states_opened     80,636
    states_closed     0
    duplicate_keys    0

Since duplicate_keys is 0, it confirms that (name, version) is a valid primary
key within a snapshot. The `is_latest = 1` count equals `distinct_servers`
exactly, which means every server has exactly one latest version and no more.

Population:

    status active             78,522
    status deleted             1,246
    status deprecated            810
    servers with >1 version    9,812  (39.6% of 24,791)
    consecutive version pairs 55,801
    mean versions per server    3.25
    earliest publishedAt      2025-09-08  (registry preview launch)

The retrospective window is therefore 2025-09-08 to 2026-08-22, about 11.5
months, available on day one. This is because the list endpoint returns every
version ever published, not just the latest, so the full version history is
computable from a single snapshot without waiting.

My starting assumption was ~9,600 servers, which was off by roughly 2.5x. Part
of the gap is that this collector passes `include_deleted=true`, so it sees
records the default public listing hides.

An earlier run the same day returned 80,578 records and 24,777 servers.

## Detector audits

### package_identifier_changed: over-reported by 24x

    raw firings                    7,069
    artifact_version_in_name       4,401  (62.3%)
    artifact_version_in_url        2,285  (32.3%)
    real_rename                      196  ( 2.8%)
    url_changed_beyond_version       103  ( 1.5%)
    package_count_changed             84  ( 1.2%)
    defensible                       299  ( 4.2% of raw)

Root cause: the `identifier` field carries the version inside the string for
OCI images and MCPB download URLs. Every routine release therefore changes the
identifier and trips an equality check. My first thought was that MCPB URLs
dominated, but the audit showed OCI tags were about twice as common.

The 84 `package_count_changed` cases are unresolved and excluded from the
defensible count.

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

`converged_to_namespace` at 72 is more interesting than the divergences, since
those are servers whose repository URL pointed at an account the publisher did
not control, and which was later corrected.

Resolving GitHub account types narrowed it further. Of the 39 divergences, 26
were a solo developer moving to a company org, which is benign. Only 2 went the
other way, from an organization to an individual account, which is the
direction that narrows who is accountable for the code after adoption.

One case flagged for manual follow-up: `dev.sexai/sexai-mcp` moved from
`sexaidev/sexai-mcp` to `sxaidev/sxai-mcp`, a single character deleted from
both the org and the repository name, under a namespace still spelled `sexai`.

### repo_id_changed: hand-audited, all 47 cases

    total cases               47
    moved_to_new_repo         30  (63.8%)
    deleted_and_recreated     17  (36.2%)

The registry schema names `repository.id` as the way to detect repository
resurrection: the ID survives renames and transfers, so if it changes, the repo
at that URL is not the same repo. I adjudicated every case by hand against a
protocol fixed in code before I looked at the data.

17 cases are same owner, same repository name, different ID, meaning the
repository was deleted and recreated. That is 0.30 per 1,000 version pairs.

Zero cases landed in `transferred`, which is a consistency check that passed:
GitHub preserves the repository ID across a transfer, so that label should be
unreachable for this transition. My protocol also included an
`id_added_or_removed` label that turned out to be impossible, since the
detector only fires when both sides have an ID. Writing an unreachable category
into a protocol is a flaw worth recording.

## Repository reference integrity

I also checked whether the repositories these records point at are actually
reachable. This produced my biggest correction of the project.

The scan resolved every GitHub owner referenced by a current server version:

    current versions scanned        24,797
    no repository field              5,532  (22.3%)
    with a GitHub repository        19,242
    distinct GitHub owners          10,794
    owners not publicly resolvable     238  (2.20%)
    current versions affected          382  (1.99%)

My first version of this labelled those 238 as "unregistered" and concluded the
names were claimable by anyone, which would have meant a third party could take
over the apparent source repository for a published server. Before reporting
that, I opened a few of the flagged orgs in a browser and got a sign-in wall
instead of a 404 page. Comparing against a control name that definitely does
not exist showed the two behave differently.

So a 404 from the GitHub users API does not mean "unregistered". It means "not
visible to this token", which covers at least three states: names that really
are free, restricted or enterprise-managed orgs, and transient blocks. Both of
the first two are confirmed present in my data.

The defensible claim is the weaker one: about 2% of currently installable
servers point at a source repository the public cannot read. That is a supply
chain transparency gap, not a takeover risk, and it follows directly from what
I measured.

Separately, 5 version records across 4 servers have unedited template values in
the repository URL, like `github.com/YOUR_GITHUB_USERNAME/...`, all with status
active. Those are unambiguous, and the registry accepted them, which suggests
it verifies namespace ownership at publication but not that the repository URL
resolves or belongs to the publisher.

I did not register or interact with any of these accounts. Nothing has been
reported to a vendor, because a finding that cannot survive questioning should
not be sent to anyone.

## The pattern

Every detector that fired more than a hundred times lost most of its firings to
subclassification, and one measurement turned out to mean something weaker than
I first claimed. A detector count is a hypothesis. The underlying strings are
the evidence. I report raw counts alongside corrected ones, because the
correction ratio says something real about how noisy naive scanning of this
ecosystem is.

## Limitations

- No tool-level data. The registry does not carry it and I do not connect to
  servers to get it.
- Servers exposed only through `remotes[]` can change their entire runtime
  behaviour with no registry footprint, so that mutation is invisible here.
- The forward-looking half of the study, detecting in-place edits, needs
  calendar time before the numbers mean anything.
- Repository resolvability conflates several states, as described above.
- Official registry only.
- Detectors are hand-written and conservative, so they will miss mutation types
  I did not think to encode. Recall is unknown.
- Counts include deleted records, which the default public listing hides.

## Decisions and why

- **Full pull daily, not `updated_since`.** The study tests whether the
  registry's immutability guarantee holds, and an in-place edit that does not
  touch `updatedAt` is invisible to incremental sync by construction. Trusting
  it would be circular.

- **Two hashes per record.** `content_hash` covers the part claimed immutable;
  `envelope_hash` also covers status and timestamps.

- **Interval-encoded storage (v2).** v1 stored one row per snapshot per record,
  growing ~80k rows a day into a 62MB binary that git re-stored in full on
  every commit, heading for multiple gigabytes over 12 weeks. v2 stores one row
  per distinct state with first_seen and last_seen, so the table grows with
  actual change rather than with calendar time.

- **Content addressing is for evidence, not storage.** Storage was never the
  constraint. The hash being the filename means anyone can verify that the
  record I claim the registry served on day N is byte-identical to what I
  stored.

- **Deterministic rules, no classifier.** `test_classify.py` pins the
  classifier against 15 hand-labelled real samples so a future change cannot
  silently break it.

- **One writer.** The GitHub Action owns collection; I only analyze locally.
  Local loop is: `git pull` -> `python3 store.py data` -> analyze.

- **Passive collection only.** Registry API reads, plus public GitHub API
  lookups for account type. No connections to `remotes[]` endpoints, no package
  execution, no probing of anyone's infrastructure. This bounds what the study
  can claim: the registry is the identity and pointer layer, so this measures
  ASI04-style supply chain pointer mutation, not ASI02 tool description
  poisoning.

## Reproducing

    python3 store.py data                                  # rebuild index
    python3 verify.py --data data                          # check integrity
    python3 report.py --data data --snapshot YYYY-MM-DD    # regenerate results

Collection runs unattended in GitHub Actions. Running it locally as well
produces competing manifests for the same date; the Action is the only writer.

## Licence

Code MIT. Dataset CC BY 4.0. The dataset is publicly published registry
metadata, collected and redistributed unmodified.