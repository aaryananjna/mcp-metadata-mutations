Our MCP data collections checks if there are changes in the data after it has been published, using the Model contet protol registry: https://registry.modelcontextprotocol.io


There is an automatic data collection machine set up whihc collects data everyday on any changes detected, and my notes inludes more of my thoughts on it.


## Why

We want to answer questions about the rug pull threat model. So what is rug pull? rug pull is a server that publihes metadata, then gets adopted and then also changees. So to measure that, one whould have to measure the record repeatedly to find changes. As of 2026 yet, no publicly discloded named victim of the MCP rug pull have been known, but that is why I made this, to find out if there ARE victims.


## What this actually measures(and what it doesn't)
The registry record only contains nae, title, description(100 chars), vesion, package coordinates, remote URL endpoints, and repo link. It does NOT contain. tool names, tool descriptions and input schemas. Those are in live `tools/list` response from a runnning server.  

1. The registry is  the identity and pointer layer.
    So this study measures the supply chain pointer mutation(OWASP ASI04), and not tool description poisoning(ASI02). So don't espect a 100 character despcrtion field facing injections. 
2. This study also does not requier connecting to third party servers to get tool-level data.

## Method

So a Github action set up pulls every page in the `/v0.1/servers` and hashes each record(to dectect change) and commits the result. So the study is testing if the resgitstry guarantee of not being able to chnge holds. On the other hand, a cross check is run to check if there is a gap between the updated and non-updates version versions. 

There two hashes per rrcord, the content_hash and the envelope hash. The content hash covers the server object(immutable part), and the enveloe hash covers status and timestamps. 

So now looking at our Lba notes



## 2026-08-22 — first full snapshot

    pages             807
    version_records   80,636
    distinct_servers  24,791
    states_opened     80,636
    states_closed     0
    duplicate_keys    0


Since duplicate heys is 0, it comfirms the (name, version) is a primary key in the snapshot. 

`is_latest = 1` count equals `distinct_servers` exactly. E

Population:

    status active             78,522
    status deleted             1,246
    status deprecated            810
    servers with >1 version    9,812  (39.6% of 24,791)
    consecutive version pairs 55,801
    mean versions per server    3.25
    earliest publishedAt      2025-09-08  (registry preview launch)


The retrospective window is therefore 2025-09-08 to 2026-08-22, about 11.5 months, available on day one.

My starting assumption was ~9,600 servers, which was kind of by roughly 2.5x.  Part of the gap is that this collector passes `include_deleted=true`, so it sees records the default public listing hides.

An earlier run the same day returned 80,578 records and 24,777 servers. 

## 2026-08-22 — detector audits

### package_identifier_changed: over-reported by 24x

    raw firings                    7,069
    artifact_version_in_name       4,401  (62.3%)
    artifact_version_in_url        2,285  (32.3%)
    real_rename                      196  ( 2.8%)
    url_changed_beyond_version       103  ( 1.5%)
    package_count_changed             84  ( 1.2%)
    defensible                       299  ( 4.2% of raw)


Root cause: the `identifier` field carries the version inside the string for OCI images and MCPB download URLs. Every routine release therefore changes the identifier and trips an equality check. My first
thought  was that MCPB URLs dominated but the audit showed OCI tags were about twice as common. 

The 84 `package_count_changed` cases are unresolved and excluded from the review. 

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

`converged_to_namespace` at 72 is more interesting than the
divergences since those are servers whose repository URL pointed at an account the publisher did not control, and which was later corrected.


One case flagged for manual follow-up: `dev.sexai/sexai-mcp` moved from `sexaidev/sexai-mcp` to `sxaidev/sxai-mcp`, a single character deleted from both
the org and the repository name, under a namespace still spelled `sexai`.


### A pattern 

Both detectors that fired more than a hundred times lost roughly three quarters of their firings to subclassification. 

## Decisions and why

- **Full pull daily, not `updated_since`.** The study tests whether the registry's immutability guarantee holds. 

- **Two hashes per record.** `content_hash` covers the part claimed immutable;
  `envelope_hash` also covers status and timestamps.


- **Interval-encoded storage (v2).** v1 stored one row per snapshot per record,
  growing ~80k rows a day into a 62MB binary that git re-stored in full on every commit, heading for multiple gigabytes over 12 weeks. v2 stores one row per
  distinct state with first_seen and last_seen, so the table grows with actual change rather than with calendar time.


- **Content addressing is for evidence, not storage.** Storage was never the constraint. The hash being the filename means anyone can verify that the
  record I claim the registry served on day N is byte-identical to what I
  stored. 

- **Deterministic rules, no classifier.** `test_classify.py` pins the classifier against 15 hand-labeled
  real samples so a future change cannot break it.

- **One writer.** The GitHub Action owns collection; I only analyze locally.
 Local loop is now:
  `git pull` -> `python3 store.py data` -> analyze.

- **Passive collection only.** Registry API reads, plus public GitHub API
  lookups for account type. No connections to `remotes[]` endpoints, no package
  execution, no probing of anyone's infrastructure. This bounds what the study
  can claim: the registry is the identity and pointer layer, so this measures
  ASI04-style supply chain pointer mutation, not ASI02 tool description
  poisoning. 
---

