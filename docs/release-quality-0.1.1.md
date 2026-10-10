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
ledger conservatively and left reviews incomplete. These require regression
coverage at their respective client/SDK boundaries.

Memory's health endpoint was reachable after the configuration repair, but
answer requests still timed out. Reachability alone does not prove useful
memory retrieval. The index also remained cold until dimension-correct
embedding requests could be deployed.

## Interpretation

Availability repairs and deterministic deduplication regressions are valuable,
but they are separate from model recall and precision. A release should report
which fixes are verified and retain these live baseline results. A small
three-case corpus cannot establish general review quality, and low spend is
not evidence of a complete review.
