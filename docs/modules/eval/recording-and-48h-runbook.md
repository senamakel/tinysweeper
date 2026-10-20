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

The first `tm-0102-memory-pending-debug-state` capture used
[`evals/recording.deepinfra.toml`](../../../evals/recording.deepinfra.toml),
DeepSeek V3.2 at pinned DeepInfra. It exhausted its eight-call initial limit:
the proposal marked the review partial, left ten files unanswered, and did not
complete a file. Treat its missed label as a cap-interrupted partial baseline,
not a completed recall measurement. Its cassette and proposal are preserved;
rerunning Record mode makes new provider calls and can replace cassette data.

The bounded continuation candidate is
[`evals/recording.gptoss-novita.toml`](../../../evals/recording.gptoss-novita.toml).
It pins GPT-OSS 120B to the Novita endpoint, disables all fallback and agentic
review, uses JSON structured output, sets a 12000-token starting limit, and
requests low reasoning effort. Revalidate the exact endpoint, native output
limit, and rates immediately before any call; this candidate does not
authorize a call by itself.

For any paid recording, calculate the worst-case dispatch cost from the
configured input ceiling and the largest output allowed by retries, then
multiply by the maximum physical dispatch count. Include every selected case
and known prior attempts in the shared total. Proceed only when that bound is
at most $0.50 per case and $2.50 for this work. Do not treat a gateway balance,
an API key's account limit, a corpus label, or the CLI admission threshold as
authorization to exceed those limits. If usage is unknown or the bound cannot
be established, stop paid work and preserve the case as unrecorded.

The first case has already reserved and used eight physical attempts. Its
persistent ledger permits at most 40 total attempts for this provider, so a
continuation can reserve only the remaining 32. The other four cases may each
reserve at most 32. Never delete or reset these ledgers. Using the verified
GPT-OSS Novita endpoint bounds, one worst-case dispatch (131072 input and
32768 native output tokens) is at most $0.014746 after micro-dollar rounding.
The five-case upper bound, including the first case's known $0.011331, is
$2.370691. Recheck the live endpoint and recalculate these bounds immediately
before use; stop if any usage is unknown or the bound changes.

Record the five cases individually so failures and spend are attributable.
The first case may be continued only after the parent reconciles the existing
ledger and explicitly authorizes another call:

```sh
cargo run --locked --features harness --bin tinysweeper -- eval run \
  --record --case tm-0102-memory-pending-debug-state \
  --config evals/recording.gptoss-novita.toml --max-cost-usd 0.48 \
  --max-physical-calls-per-case 40 \
  --out evals/runs/issue235/gptoss-novita/tm-0102-memory-pending-debug-state
```

Use `--max-physical-calls-per-case 32` for each of the other four cases, with
an output directory under `evals/runs/issue235/gptoss-novita/` named for that
case. Keep the initial V3.2 proposal and run output in its original directory.

Repeat with each of the four `oh-...` cases listed in `evals/README.md`, using
only the matching historical source material when lookups are needed. Never
pass one checkout for a different repository or head. Capture each
command's source identity, config digest, exit status, raw output hash, model
and provider answered, reported usage, and known cost. Keep credential values
and request/response payloads private. Stop immediately after any provider
error that lacks usage information. The recorder persists a call-budget audit
at `evals/recording-attempts/<case-id>/recording-attempts.json`; it reserves capacity
before dispatch and records actual committed physical calls after success or
failure. A process crash leaves the full reservation charged; atomic replacement
does not promise durability across power loss. Do not remove the audit or lock
file to obtain a fresh allowance; investigate and preserve its history.

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
