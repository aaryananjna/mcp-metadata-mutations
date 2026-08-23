# mcp-metadata-mutations

A longitudinal measurement study of how server metadata changes after
publication in the public [Model Context Protocol registry](https://registry.modelcontextprotocol.io).

Daily content-addressed snapshots, deterministic change detection, and an
audited account of what the detectors get wrong.

**Current results: [`reports/RESULTS.md`](reports/RESULTS.md)** (regenerated
from the data, never edited by hand)
**Working notes and corrections: [`NOTES.md`](NOTES.md)**

---

## Why

Published security work on the MCP ecosystem is almost entirely made up of
snapshots: crawl the registries once, run static or runtime checks, report how
many servers look risky today. That answers "what is the state of the
ecosystem," and it answers it repeatedly.

It does not answer the question the rug-pull threat model actually poses. A
rug pull is a server that publishes benign metadata, gets adopted, and then
changes. Measuring that requires observing the same records repeatedly over
time. The attack class has been formalised in the literature, but without a
large-scale empirical component, and as of early 2026 no publicly disclosed,
named victim of an MCP rug pull in production had been identified.

This repository is the instrument for measuring it.

## What this actually measures, and what it does not

The registry record (`server.json`) contains a name, title, a description
capped at 100 characters, a version, package coordinates, remote endpoint URLs,
and a repository link. **It contains no tool names, no tool descriptions, and
no input schemas.** Those exist only in a live `tools/list` response from a
running server.

Two consequences, and they are the load-bearing scoping decisions here:

1. The registry is the **identity and pointer layer**. This study measures
   supply chain pointer mutation (OWASP ASI04), not tool description poisoning
   (ASI02). A 100-character description field is structurally not where
   instruction injection happens.
2. Getting tool-level data would require connecting to third-party servers or
   executing published packages. This study does neither. See Ethics.

## Method

**Collection.** A daily GitHub Action pulls every page of `/v0.1/servers` with
`include_deleted=true`, hashes each record, and commits the result. Full pull
every day rather than `updated_since`, because the study is testing whether the
registry's immutability guarantee holds and an in-place edit that does not
touch `updatedAt` is invisible to incremental sync by construction. The
incremental query runs separately as a cross-check, and the gap between the two
answers is itself a measurement.

**Two hashes per record.** `content_hash` covers the `server` object, the part
documented as immutable. `envelope_hash` also covers status and timestamps. One
combined hash would merge "silent in-place edit" with "status flipped to
deprecated," which are unrelated events. Records are canonicalised (sorted
keys, tight separators) before hashing, so an upstream field reordering does
not register as a fleet-wide change.

**Storage.** Content-addressed blobs on disk plus per-day delta manifests. The
SQLite index is derived and gitignored; `python3 store.py data` rebuilds it.
Content addressing is here for evidence, not for space: the hash being the
filename means a third party can verify that the record claimed for a given day
is byte-identical to what was stored, without trusting this repository.

**Two analyses.** *Retrospective*: the list endpoint returns every version ever
published, so version-to-version transitions across the registry's full history
are computable from a single snapshot. *Prospective*: comparing snapshots
across days detects in-place edits to records the registry documents as
immutable. Only the second requires waiting.

**Detection is deterministic.** Named rules over structured fields. No model,
no learned threshold, no invented severity weights. Recent ecosystem-scale work
found under half of existing MCP scanner alerts survive manual validation; a
heuristic stack is not going to beat that, so this optimises for
reproducibility and honest bounds instead. `test_classify.py` pins the
classifier against hand-labelled real samples.

## The methodological result

Every detector that fired more than a hundred times was subclassified and
audited against the underlying strings. Each lost most of its firings:

| Detector | Raw | Defensible | Retained | What the artifacts were |
|---|---|---|---|---|
| `package_identifier_changed` | 7,069 | 299 | 4.2% | Version strings inside OCI tags and MCPB download URLs |
| `repo_owner_changed` | 192 | 53 | 27.6% | Case-only renames, same-entity respellings, forge migrations |

A third measurement was corrected outright. An earlier version of the
repository-resolvability scan labelled GitHub API 404s as "unregistered" and
concluded the names were claimable. Manual control testing showed that a 404
means "not visible to this token," which covers free names, restricted or
enterprise-managed orgs, and transient blocks. Both states were confirmed
present in the data. The metric was relabelled to "not publicly resolvable,"
which is weaker and follows from what was measured.

**A detector count is a hypothesis. The underlying strings are the evidence.**
Raw counts are reported alongside corrected ones throughout, because the
correction ratio is itself a result about how noisy naive scanning of this
ecosystem is.

## Limitations

- **No tool-level data.** The registry does not carry it and this study does
  not connect to servers to obtain it. Claims are bounded to registry metadata.
- **Remote-only servers are partly opaque.** A server exposed through
  `remotes[]` can change everything about its runtime behaviour with zero
  registry footprint. That mutation is invisible here by construction.
- **The prospective half needs calendar time.** Silent-edit rates over a short
  window are not meaningful. The retrospective half does not have this problem.
- **Repository resolvability conflates several states.** See above. Individual
  cases require manual adjudication and have not all received it.
- **Single registry.** The official registry only. 
- **Detectors are conservative and hand-written.** They will miss mutation
  types nobody thought to encode. Recall is unknown and unmeasured.
- **Population counts include deleted records**, which the default public
  listing hides. Comparisons to other published server counts must account for
  this.

## Ethics and disclosure

Collection is passive. Reads of the public registry API, plus public GitHub API
lookups for account metadata. **No connections to third-party `remotes[]`
endpoints, no execution of published packages, no probing of anyone's
infrastructure, no authentication to anything that is not public.**

No account, organisation, or namespace identified by this study has been
registered, claimed, or interacted with.

Anything that appears genuinely malicious goes to the maintainer and the
registry through private disclosure before publication, with a 30 day window on
specifics. Aggregate statistics are published without embargo.

Findings are not reported to vendors until they survive questioning. A
measurement that cannot be defended should not be sent to anyone, and one such
finding was withheld on exactly that basis.

## Repository layout

```
collect.py         daily collector, stdlib only
store.py           content-addressed store; run directly to rebuild the index
diff.py            version-chain and snapshot-to-snapshot diffs
classify.py        subclassifiers for over-firing detectors
audit.py           pull the raw before/after strings behind any detector
dangling.py        repository reference resolvability scan
report.py          regenerate reports/RESULTS.md from the data
verify.py          re-hash stored blobs; the dataset is self-verifying
test_classify.py   classifier pinned against hand-labelled real samples
data/objects/      content-addressed blobs (the evidence)
data/snapshots/    per-day delta manifests (the time series)
reports/           generated output
NOTES.md           lab notebook, including corrections
```

## Reproducing

```bash
python3 store.py data                                  # rebuild index
python3 verify.py --data data                          # check integrity
python3 report.py --data data --snapshot YYYY-MM-DD    # regenerate results
```

Collection itself runs unattended in GitHub Actions. Running it locally as well
produces competing manifests for the same date; the Action is the only writer.

## Licence

Code MIT. Dataset CC BY 4.0. The dataset consists of publicly published
registry metadata, collected and redistributed unmodified.