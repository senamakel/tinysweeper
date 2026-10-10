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

The combined candidate now includes PRs #201–#209 and the immutable OpenHuman
billing/physical-timeout integration `84a31e90`. Its monetary queue, reasoning wire format, hard limit,
cancellation, and independent scopes pass all 16 gateway parity tests. The
combined library suite including #209 passes 2,316 tests with four existing live
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
