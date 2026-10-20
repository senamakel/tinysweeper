# Corpus recording and 48-hour observation

This runbook covers two separate measurements: whether the labelled historical
misses are found by the real review path, and whether the deployed review queue
continues to meet its operating limits after a rollout. A successful replay
does not establish production health, and production metrics do not establish
corpus recall.

## Record the historical cases

The five `recall` cases in `evals/cases/` are frozen to externally reviewed
heads. `evals/README.md` lists their short IDs and evidence. The expected
findings are evaluator-only; never copy case TOML, expected labels, fix
explanations, or score output into model input. The recording command loads the
historical fixture and reaches the ordinary read-only review path. Use the
matching archived source checkout for any additional source lookups.

Before recording, verify the operator-owned local provider credential is
available without printing or copying its value. Use a recording-only config
that pins one known provider and model, disables model and provider fallback,
disables agentic reviewers, disables reasoning, and sets a bounded output
ceiling. Confirm its price schedule and the model's current context/output
limits from provider documentation. The CLI's `--max-cost-usd` only limits
admission between cases; it is not a provider invoice cap. Each case also has
a `budget.max_cost_usd` label. The runner binds the smallest of the operator
per-review budget, the case budget, and the run budget divided across all
selected cases to the shared review budget root. An unreported-usage refusal
stops later cases because its charge is unknown.

The checked-in candidate is [`evals/recording.deepinfra.toml`](../../../evals/recording.deepinfra.toml).
It uses DeepSeek V3.2 at the pinned DeepInfra endpoint, disables model and
provider fallback and reasoning, sets `max_tokens = 4096`, and gives the
gateway a conservative per-million-token price bound. Revalidate public
endpoint availability, context/output limits, and rates immediately before
recording; the config and price table do not prove the provider's live limits
have not changed.

For any paid recording, calculate the worst-case dispatch cost from the
configured input ceiling and the largest output allowed by retries, then
multiply by the maximum physical dispatch count. Include every selected case
and known prior attempts in the shared total. Proceed only when that bound is
at most $0.50 per case and $2.50 for this work. Do not treat a gateway balance,
an API key's account limit, a corpus label, or the CLI admission threshold as
authorization to exceed those limits. If usage is unknown or the bound cannot
be established, stop paid work and preserve the case as unrecorded.

Record the five cases individually so failures and spend are attributable:

```sh
cargo run --locked --features harness --bin tinysweeper -- eval run \
  --record --case tm-0102-memory-pending-debug-state \
  --config evals/recording.deepinfra.toml --max-cost-usd 0.50 \
  --max-physical-calls-per-case 8
```

Repeat with each of the four `oh-...` cases listed in `evals/README.md`, using
its exact historical source checkout with `--tree` when lookups are needed.
Never pass one checkout for a different repository or head. Capture each
command's source identity, config digest, exit status, raw output hash, model
and provider answered, reported usage, and known cost. Keep credential values
and request/response payloads private. Stop immediately after any provider
error that lacks usage information. The recorder persists a call-budget audit
at `evals/cassettes/<case-id>/recording-attempts.json`; it reserves capacity
before dispatch and records actual committed physical calls after success or
failure. A crash leaves the full reservation charged. Do not remove the audit
or lock file to obtain a fresh allowance; investigate and preserve its history.

After all five recordings exist, run the offline proof and scorecard with no
model configured:

```sh
cargo test --locked -j1 eval
cargo run --locked --bin tinysweeper -- eval score
cargo run --locked --bin tinysweeper -- eval report
```

For each case report expected labels, matched labels, misses, false positives
only when the case is exhaustive, cassette strict hits/misses, review errors,
known provider cost, and whether the result is a valid measurement. Failed
reviews, strict replay misses, and missing cassettes are not hits. Recall is
`matched expected labels / all expected labels`; show per-case values as well
as the aggregate so a strong case cannot hide a complete miss elsewhere.
Include the exact corpus and config digests. Do not publish an aggregate recall
until all five cases have real strict-hit recordings and completed reviews.

## Observe the rollout for 48 hours

Start the observation window at the recorded deployment timestamp. Use the
server's existing queue/status telemetry and the deployment's normal metrics
source; do not infer production values from local tests or corpus runs. Record
the source query or dashboard, deployment identifier, window start/end in UTC,
sample count, numerator and denominator for each percentage, and the raw
export's digest. Keep user payloads and secrets out of the report.

Record these metrics at the start and at 24 and 48 hours:

| Metric | Measurement | Target |
| --- | --- | --- |
| Push-to-start latency | p50 seconds from accepted push to review start | under 5 minutes |
| Deadline hits | deadline-hit reviews / reviews with a terminal status | under 5% |
| Budget refusals | count of review starts refused for budget | approximately zero; report the exact count |
| Success with unanswered files | successful lanes that left requested files unanswered | zero |

For each sample, state missing telemetry explicitly. A missing denominator is
`not measured`, never zero. Investigate every deadline hit, refusal, and
successful lane with unanswered files against its trace and queue record;
report counts and causes without copying private request content. Compare the
48-hour window with the immediately preceding 48-hour window under the same
definitions and query. If definitions or deployment versions differ, mark the
comparison non-comparable and retain both raw values.

The final report must contain the actual before and after values, time windows,
sample counts, data source, deployment identifier, and the query/export hash.
If the 48-hour window has not elapsed, the report must say `pending` and must
not claim the rollout acceptance criteria are complete. Keep publication and
rollout decisions with the parent issue owner; this page is an operating
procedure, not deployment authorization.
