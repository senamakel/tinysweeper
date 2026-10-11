# TinySweeper 0.1.1 review quality audit

## Live baseline (2026-10-10)

Three independent live recordings used the deployed `c4709cf5` binary, the
three existing labeled cases, and the operator's `flash`/`deep` model ladders.
Each case had a $1 ceiling. Repository evidence came from the committed
fixtures; embeddings and memory were disabled in these local evaluations.
This measures the diff/tree review pipeline, not production retrieval quality.

| Run | Boundary labels matched | Clean-case false positives | Duplicates | Total cost |
| --- | --- | --- | --- | --- |
| 1 | 2/2 | 4 | 1 | $0.055942 |
| 2 | 1/2 | 3 | 1 | $0.043615 |
| 3 | 0/2 | 4 | 1 | $0.044114 |

The scorer includes summary notes. Every matched boundary finding in these
runs was below the inline posting threshold. Run 2 matched a test-coverage
observation to the first boundary label; that is weaker evidence than the
concrete cursor finding in run 1. These numbers therefore do not establish
reliable actionable recall. All runs avoided the corpus's forbidden
kernel/privilege hallucinations and code-anchored description findings.

The full scorecards, including matching reasons and model identities, are in
[`evals/reports/2026-10-10-baseline.json`](../evals/reports/2026-10-10-baseline.json).

## Additional comparison

A fourth recording selected the deeper `max-reasoning` ladder. It matched
neither boundary label, produced three false positives and one duplicate on
the clean case, and spent $0.019616 across the three cases. Some routes rejected
the provider-specific reasoning object with HTTP 400, leaving coverage
incomplete. This run does not justify changing the production model route.
Its full scorecard is in
[`evals/reports/2026-10-10-depth-comparison.json`](../evals/reports/2026-10-10-depth-comparison.json).

Strict offline replays of all three baseline cassettes against PR #195 made
no network calls and preserved all scores, including the three duplicate
counts. Those duplicates were summary notes, whereas #195 groups inline
findings. Its regression tests demonstrate safer grouping, but this corpus
shows no deduplication improvement from that change.

PR #203 extends concern grouping to below-gate summary notes. Strict replays
of the same three recordings reduce each clean-case duplicate count from one
to zero. Recall, false positives, and forbidden hits stay unchanged. Original
observations remain in the proposal for audit; only the strongest matching
note is displayed. This is a measured display improvement, not a claim of
better model precision. Full scorecards are in
[`evals/reports/2026-10-10-summary-dedupe.json`](../evals/reports/2026-10-10-summary-dedupe.json).

## Production evidence and fixes

Production initially could not reach the memory engine, requested an embedding
ladder the box did not serve, and then rejected bearer-authenticated model calls
to a non-loopback HTTP endpoint after the Embed migration. Configuration now
uses the served `vectors-oai3` route, the published Cortex host-gateway port,
and a certificate-validated private nginx TLS listener. The listener binds
only the Docker gateway address. The deployment workflow checks mounted
configuration with the incoming image before replacing the running service;
a shell regression executes the actual remote deployment script.

Fresh reviews then revealed two further issues: embedding requests omitted the
configured dimensions, and budget settlement did not receive the gateway's
buyer charge even though the displayed bill did. The latter exhausted the
ledger conservatively and left reviews incomplete. The dimension regression is fixed and deployed at `648a9ff0`: a diagnostic
request returned the configured 1,024-wide vector. The SDK settlement and
scoped admission fixes are tested together in the release candidate.

An additional regression reproduced budget admission failing before any
spend: two concurrent calls each reserved $0.60 against a $1 limit, although
their eventual charges were much smaller. Correct settlement and serialized
admission within each scoped ledger are both needed; raising the ceiling
would conceal the problem. A scoped queue trades some latency for affordable
complete reviews while keeping cancellation and independent scopes separate.

Fresh-head approval also needs verification. The deployed binary suppresses a
second approval when its previous verdict was approval, even after the PR head
changes. Merge checks correctly reject that stale approval. PR #205 pins
suppression to a known matching commit, preserves incomplete-review
withdrawals, and avoids an additional GitHub API request. Its regressions
cover moved heads, unknown heads, and preserving decisive review metadata.

Memory's health endpoint was reachable after the configuration repair, but
answer requests still timed out. Reachability alone does not prove useful
memory retrieval. After the dimension repair, indexing progressed but another input exceeded
the provider's 8,192-token limit. PR #206 bounds inputs at 8,000 UTF-8 bytes
and batches by a conservative byte bound. Regression tests preserve dense
source, multibyte text, whitespace prefixes, gaps, and trailing newlines.
A live diagnostic with deterministic dense ASCII text reproduced rejection
at 12,000 bytes and success at 8,000 bytes (6,070 measured tokens, 1,024
dimensions, 20 microdollars charged).

At 21:46 UTC, Cortex still logged repeated provider timeouts and marked its
answer role unhealthy after five failures, despite a healthy container check.
During 22:10–22:26 UTC, extraction completed 113 jobs, but TinySweeper still
logged recall and answer timeouts, with no successful recalled-memory event.
The mounted answer model was already `flash`. The evidence does not establish
the upstream cause. Memory failures produce partial/unavailable context; they
do not directly account for missing file coverage in model verdicts.

## Candidate validation

The combined candidate at `eb5fcc8e` includes PRs #201–#213 and the immutable
OpenHuman billing/physical-timeout/capacity integration `e91a4742`. Its monetary queue, reasoning wire format, hard limit,
cancellation, and independent scopes pass all 19 gateway parity tests, including physical timeout and conservative
unknown-charge fallback cases. The
combined library suite passes 2,327 tests and 11 CLI tests with four existing live
tests ignored.
Clippy with warnings denied and the all-feature/all-target check also pass.
OpenHuman #7354 remains open; its tested billing changes are pinned without
claiming upstream merge or fully green upstream CI. A known floating-point
rounding edge can conservatively add one microdollar to a provider USD charge.

Three fresh recordings completed at source `dd225938`, including PRs
#201–#205 before the security scope follow-up. Retrieval was disabled as in
the baseline. Eight of nine final proposals were complete; the clean case in
run 1 failed description schema validation (`missing field rule`). Its scorer
reports zero spend on failure, but the 46 recorded calls actually total
$0.015204. The baseline had nine complete proposals.

| Run | Boundary labels matched | Clean-case scorer false positives | Clean duplicates | Recorded cost |
| --- | --- | --- | --- | --- |
| 1 | 2/2 | failed case | unknown | $0.055296 including failed-case recordings |
| 2 | 1/2 | 4 | 0 | $0.054780 |
| 3 | 1/2 | 4 | 0 | $0.056561 |

Successful cases took 315–789 seconds, versus much shorter baseline cases.
These results do not establish better precision, recall, or latency. Some
scorer false positives describe actual body omissions or optional contract
limitations, so the labels need careful interpretation. The new recordings
also exposed generic tests/style notes in the security lane; PR #202 now
filters explicitly out-of-scope model proposals with a structured decision,
while preserving scanner facts and failing open on uncertain metadata. That
follow-up requires its own fresh live validation. The full audited scorecards
and completeness data are in
[`evals/reports/2026-10-10-candidate-comparison.json`](../evals/reports/2026-10-10-candidate-comparison.json).

A separate read-only candidate review of PR #204's exact `8598a26b` head
completed all five lanes with no findings or unanswered units, costing
$0.024905. Its unmodified proposal was published by the existing deterministic
`app::apply` path on the server after the model calls returned. GitHub recorded
a real App approval clearing the earlier incorrect objection. With all 17
checks passing, independent CodeRabbit approval, and no unresolved threads,
#204 merged normally at `128b3eff`.

Two subsequent live recordings used the security scope follow-up and read-only
git archives at the original reviewed TinySweeper commits, recording genuine
lookups rather than fabricating context. Both proposals were complete. On the
kernel/summary case, the falsifier rejected the invalid temporary-borrow claim
and explicitly removed a generic truncation contract issue from the security
lane; the legitimate optional truncation finding remained in critique. Both
security lanes had no summary notes, and forbidden hits stayed zero. The
scorer still reported four clean-case false positives, including body omissions
and contract preferences that its labels do not cover. This is evidence for
specific noise fixes, not a general precision or latency improvement. Full
scorecards and actual rejection decisions are in
[`evals/reports/2026-10-10-security-scope-live.json`](../evals/reports/2026-10-10-security-scope-live.json).

## Interpretation

Availability repairs and deterministic deduplication regressions are valuable,
but they are separate from model recall and precision. A release should report
which fixes are verified and retain these live baseline results. A small
three-case corpus cannot establish general review quality, and low spend is
not evidence of a complete review.

The native budget-capacity wait fix merged through TinyInference #75 and
TinyAgents #377 after fresh approvals and green CI. OpenHuman #7360 publishes
the tested SDK integration `e91a4742`, including two actual wire regressions
for fallback after a temporary wait and cancellation without dispatch. That
SDK PR remains behind the documented #7354/#7358 dependency gates; the
TinySweeper #210 validates parallel admission with real HTTP barriers:
two affordable calls dispatch concurrently, while a third waits for settlement.

A complete fresh review of #202 incorrectly claimed that `crate::falsify`
was missing after reading only `src/falsify.rs`. That exact path is absent,
but `src/falsify/mod.rs` exists. The lookup response was accurate; the model
overgeneralized it. The proposal was retained as evidence and was not
published. PR #211 adds bounded, sanitized directory-list evidence instead of guessing
module filenames. Its canonical cassettes were recorded from actual calls;
24 historical lookup outcomes were repaired by querying the exact original
Git tree. Original model answers were preserved. Strict replay has zero
misses and zero loose matches, but boundary recall remains 0/2 and one
critique unit remains unanswered. The untouched baseline is incomparable
because the genuine evidence and prompt fingerprints changed.


## Final route comparison

With identical source `031fdc3b` and immutable PR heads, routing every review
tier through `deep` completed #202 in 183 seconds ($0.043477) and #207 in
191 seconds ($0.043528), with no unanswered units. Keeping scan on `flash`
took 462 and 491 seconds respectively and left one unit unanswered in each.
The deep #207 proposal was clean and published normally, clearing the earlier
changes request. The deep #202 review falsely claimed a singleton out-of-scope
assessment occurred in the fail-open test; the actual array contains only
duplicate/conflicting assessments and intentionally incomplete metadata. That
proposal was retained without publishing its incorrect objection.

Fresh historical-tree recordings of the final source with scan still on
`flash` produced another false critical temporary-String lifetime claim on
#45, and a medium unsupported-reasoning-effort observation on #68. Both left
the tests lane unanswered. These results support the routing reliability
change and demonstrate why broad accuracy claims would be premature.


The full same-source, same-head route comparison covers five PRs:

| PR | Flash scan seconds / unanswered | Deep scan seconds / unanswered |
| --- | --- | --- |
| #202 | 462 / 1 | 183 / 0 |
| #203 | 387 / 2 | 208 / 0 |
| #206 | 549 / 2 | 230 / 0 |
| #207 | 491 / 1 | 191 / 0 |
| #208 | 570 / 2 | 138 / 0 |

Together these deep attempts cost $0.168760 versus $0.140736 for flash scan.
The deep #206 description lane still falsely claimed merged tree chunks
escaped the input bound; an independent exact-source probe combined eight
3,024-byte definitions and returned four 6,048-byte chunks that reconstruct
the complete source. The existing aggregate guard already enforces the cap.
The follow-up enables the description lane's existing bounded read-only
lookup flow, while keeping its findings in the review summary. The falsifier
also receives anchored source lines rather than just a path and claim text.
Both changes have actual failing-then-passing regressions; their fresh live
validation must be reported separately from these earlier comparisons.


## Provider outage and structured refusals

Surplus fell below the gateway's $0.50 minimum balance during the final
follow-up trials. Those exhausted-provider proposals had unanswered units and
were retained without approval. The existing OpenRouter account restored the
same `openai/gpt-5.6-luna` model under a verified $1.80 per million output-token
ceiling, preferring the OpenAI endpoint. The production gateway was validated
before replacement and an actual authenticated probe returned HTTP 200 with
$0.0000086 reported usage. Its previous container remains available for rollback. The existing per-machine
private environment and normal renderer retain the fallback on later installs.
The flash route also returned HTTP 200 from `z-ai/glm-5.3-flash` through
OpenRouter, with $0.00000876 reported usage.
Embedding fallback was added only after three same-text comparisons against
stored production vectors established the same `text-embedding-3-large` space.
Cosine similarities were 0.999999, 1.0, and 0.999712 across public YAML and two
UTF-8 Rust sources; all vectors have 1,024 dimensions. The index signature stays
`ladder:vectors-oai3:1024`, and no reindex was performed. Total probe cost was
$0.00014885. The final private TLS endpoint returned HTTP 200 with the expected
model, 1,024 dimensions, and $0.00000117 usage. This proves endpoint recovery,
not useful retrieval. Workspace commit `f230807` passed the native configuration
guard and deployed through the normal fleet helpers on both reachable hosts.
The earlier rejected configuration was corrected without bypassing that guard.
Embedding prices were verified from the provider catalog; the native embedding
configuration does not support an enforced price ceiling.

Fresh reviews of #202, #206 and #212 using source `eb5fcc8e` and that fallback
had zero posted findings but respectively three, two and one unanswered units.
An additional diagnostic #212 run confirmed `InvalidJson` after one physical
attempt. These are incomplete reviews, not clean approvals. TinySweeper was not
requesting any of Embed's existing bounded structured repair attempts; the
follow-up adds one repair under the same budget and timeout boundaries.

The gateway configuration synced to the reachable Mac mini and robot1.
Dragonfly refused SSH, so its synchronization remains unverified.


The independently verified final three-case strict replay has zero cassette
misses, zero loose matches, zero unusable replies and no unanswered units.
Current tapes represent $0.284131 of actual calls; retaining the archived first
attempt brings total known recording spend to $0.406248. Boundary recall is
still 0/2, and two findings are unscored because labels are not exhaustive.
The repeated boundary case produced no security finding and did not invoke
the falsifier, so its absent earlier false finding is not evidence that the
new falsifier removed it. The unchanged baseline remains incomparable.


## Bounded JSON repair trials

Source `0c4e627a`, binary SHA-256
`91f0f405b8094397a65698e08e965331a1314f441d592f3f27e477fb787d00ba`,
adds one JSON-mode repair and preserves aggregate charges across attempts.
The combined suite passed 2,325 feature tests and 11 CLI tests, default
Clippy, formatting, and all-feature/all-target checking.

| PR | Seconds | Known cost | Unanswered | Posted-eligible findings |
| --- | ---: | ---: | ---: | ---: |
| #202 | 213.113 | $0.142210 | 0 | 0 |
| #206 | 180.603 | $0.101520 | 1 | 0 |
| #212 | 36.095 | $0.005106 | 0 | 0 |
| #213 | 193.031 | $0.162734 | 0 | 0 |
| #214 | 196.711 | $0.073208 | 0 | 1 false |

Complete clean proposals for #202, #212 and #213 were published through
normal apply after model calls returned; those PRs merged normally. #214
merged with an independent exact-head CodeRabbit approval. Its model Tests
claim that provider charges were lost was disproven by the upstream gateway
normalizer and the actual two-attempt wire regression; that proposal was
withheld. #206 remained incomplete and was also withheld.

A diagnostic #206 attempt took 140.803 seconds, cost $0.079958, and left
two unanswered units plus a false oversized-line test claim. Transparent
response capture showed multiple replies containing two concatenated JSON
objects, despite `finish_reason: stop`; strict parsing correctly rejected
them. The single-line splitter and its fresh regression test directly
disprove the reported defect. These outcomes remain in the audit, including
failed attempts. They do not establish a general precision improvement.


## Lookup response contract and checkout evidence

Source `68252333` aligns the lookup-enabled schema with its multi-turn prompt:
one JSON object, provisional summary, and empty findings while asking for
evidence. A regression failed on the contradictory original schema and passes
after the fix. The CLI now also accepts a clean checkout pinned to the live
head, so operator trials can search the same evidence as server reviews.
Parser and Git-integrity regressions cover wrong heads, tracked modifications,
and untracked files; submodule ignore settings cannot hide dirty state.

The 93 fresh canonical responses replay strictly with no cassette misses or
loose matches and no unanswered units. They cost $0.082564 total: $0.037610
for OpenCompany, $0.027266 for #45, and $0.017688 for #68. The boundary case
matched E1 with an exclusive-bound finding and `next()` replacement, while
still missing E2. Its explanation contains a confused sentence about pins at
the boundary. The exhaustive clean #45 case produced two false findings,
including a self-contradictory Python-attribute claim; #68 had no findings.
All output is retained, with labels and baseline unchanged. This isolated
match does not establish stable recall or a general precision improvement.

The forge-only #206 review completed in 282.544 seconds for $0.189602 with
no unanswered units, but asserted a conditional HIGH without inspecting its
consumer. It was withheld. That outcome prompted a separate trial using a
clean matching checkout; it must not be substituted for the earlier result.


### Additional checkout-backed trials and security regression

The matching-checkout #206 trial took 370.731 seconds and cost $0.154275,
with two unanswered units and no posted findings. It was withheld. The
matching-checkout #215 trial completed in 314.862 seconds for $0.145780,
with two findings identifying the same valid ignored-file evidence issue.
The separate production review also found that issue. A clean Git status
alone permits ignored files, so a general directory reader could expose an
ordinary ignored private file to the model.

Source `0a549f36` limits checkout reads to Git's reviewable-path allowlist
and validates the head through the hardened Git runner. Two regressions
failed before the fix: an ignored ordinary file was readable, and a Git
fsmonitor hook ran during validation. Both pass after the fix. Existing
wrong-head, tracked-modification and untracked-file tests remain in place.
The subsequent stale-checkout warning is covered by the review engine's
existing revision comparison: a mismatching supplied tree is dropped in
favor of the forge reader pinned to the freshly fetched PR head.

A new actual-wire test shows that Embed's native OpenAI transport already
makes every strict-schema property required, including nested lookup
fields. It passed against the existing adapter, so no redundant schema
normalizer was added and this is coverage rather than a reproduced bug.
The strict-schema #206 trial finished in 139.600 seconds for $0.082698,
with no posted findings but twelve unanswered units. It was withheld.
The small successful provider probe therefore did not establish full-review
reliability, and changing the operator setting alone is not a proven fix.


The strict-schema #215 trial took 221.056 seconds for $0.124005, with seven
unanswered units and three posted findings. It was withheld. Two findings
asserted unsupported requirements for the human-readable recording report;
the mutable-checkout warning concerns caller-controlled changes after the
preflight rather than the already guarded fresh-head comparison.
A captured strict-schema #206 diagnostic took 167.193 seconds for $0.079244,
with nine unanswered units and no posted findings. It was also withheld.
Actual request metadata contains `json_schema` with `strict: true`; HTTP 200
responses from OpenRouter's OpenAI provider nevertheless contain concatenated
JSON objects. Some objects are duplicates and others differ. The gateway
client relays the upstream response bytes unchanged. No parser relaxation or
schema-mode deployment follows from these results.

After the checkout security fix, the combined candidate passed 2,327 library
tests and 13 CLI tests, feature Clippy with warnings denied, all-feature/all-target
checking, formatting and the OpenHuman pin assertion. These are local candidate
checks; they do not stand in for release publication or deployment receipts.

Wire hashes and all three strict-mode trial receipts are retained in
[`strict-schema-trials.json`](../evals/reports/2026-10-11-strict-schema-trials.json).
