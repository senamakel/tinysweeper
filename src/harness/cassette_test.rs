//! Cassette recording, replay, and the two ways it is allowed to miss.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::harness::mock::MockModel;
use crate::ports::model::Message;

#[derive(Clone, Default)]
struct ReviewBudgetProbe {
    remaining: Option<Arc<std::sync::atomic::AtomicUsize>>,
    completed: Arc<std::sync::atomic::AtomicUsize>,
}

struct PhysicalEventCounter(std::sync::atomic::AtomicUsize);

impl crate::ports::model::ModelCallObserver for PhysicalEventCounter {
    fn completed(
        &self,
        _usage: Usage,
        succeeded: bool,
        refused: bool,
        _latency: std::time::Duration,
    ) {
        assert!(succeeded);
        assert!(!refused);
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl Model for ReviewBudgetProbe {
    async fn complete(&self, _request: ModelRequest) -> Result<ModelResponse> {
        use std::sync::atomic::Ordering;

        if let Some(remaining) = &self.remaining
            && remaining
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_sub(1)
                })
                .is_err()
        {
            return Err(Error::Budget {
                spent: 1.0,
                limit: 1.0,
                usage: None,
            });
        }
        self.completed.fetch_add(1, Ordering::Relaxed);
        let usage = Usage {
            input_tokens: 2,
            output_tokens: 1,
            calls_attempted: 1,
            calls_succeeded: 1,
            cost_usd: 1.0,
            ..Usage::default()
        };
        if let Some(observer) = crate::ports::model::current_model_call_observer() {
            observer.completed(usage, true, false, std::time::Duration::ZERO);
        }
        Ok(ModelResponse {
            value: answer(),
            model: "review-budget-probe".into(),
            usage,
        })
    }

    async fn review(
        &self,
        _request: ModelRequest,
        _tree: &dyn crate::ports::tree::TreeReader,
        _policy: &crate::config::types::LookupPolicy,
    ) -> Result<ModelResponse> {
        Ok(ModelResponse {
            value: answer(),
            model: "review-budget-probe-logical-review".into(),
            usage: Usage::default(),
        })
    }

    fn complete_reports_physical_calls(&self) -> bool {
        true
    }

    fn review_reports_physical_calls(&self) -> bool {
        false
    }

    fn scoped_budget(&self, _budget_usd: f64) -> Option<Arc<dyn Model>> {
        Some(Arc::new(self.clone()))
    }

    fn with_review_budget(&self, limit_usd: f64) -> Option<Arc<dyn Model>> {
        let calls = limit_usd.floor().max(0.0) as usize;
        Some(Arc::new(Self {
            remaining: Some(Arc::new(std::sync::atomic::AtomicUsize::new(calls))),
            completed: self.completed.clone(),
        }))
    }
}

#[tokio::test]
async fn recording_cassette_preserves_review_root_and_recording_state_across_scopes() {
    use std::sync::atomic::Ordering;

    for bind_after_scope in [false, true] {
        let dir = tempfile::tempdir().expect("temporary cassette directory");
        let inner = Arc::new(ReviewBudgetProbe::default());
        let completed = inner.completed.clone();
        let cassette = Arc::new(Cassette::record(inner, dir.path()));
        let model: Arc<dyn Model> = cassette.clone();
        let root = if bind_after_scope {
            model
                .scoped_budget(8.0)
                .expect("recording cassette forwards lane scopes")
                .with_review_budget(1.0)
                .expect("recording cassette forwards review binding")
        } else {
            model
                .with_review_budget(1.0)
                .expect("recording cassette forwards review binding")
        };
        let lane = root
            .scoped_budget(8.0)
            .expect("recording cassette retains the review root on lane rescope");
        assert!(root.complete_reports_physical_calls());
        assert!(root.review_reports_physical_calls());
        let physical_events =
            Arc::new(PhysicalEventCounter(std::sync::atomic::AtomicUsize::new(0)));

        let first = crate::ports::model::with_model_call_observer(
            physical_events.clone(),
            root.complete(request("probe", "first paid response")),
        )
        .await
        .expect("the first response fits the review root");
        assert_eq!(first.value, answer());
        let second = crate::ports::model::with_model_call_observer(
            physical_events.clone(),
            lane.complete(request("probe", "second paid response")),
        )
        .await;
        assert!(matches!(second, Err(Error::Budget { .. })));
        assert_eq!(completed.load(Ordering::Relaxed), 1);
        assert_eq!(physical_events.0.load(Ordering::Relaxed), 1);
        assert_eq!(cassette.served(), 1);
        assert_eq!(cassette.spend().usage.input_tokens, 2);
        assert_eq!(cassette.spend().usage.output_tokens, 1);
        assert_eq!(cassette.cost_usd(), 1.0);
        assert_eq!(
            cassette
                .flush()
                .expect("the original recorder sees the take"),
            1
        );
        assert_eq!(
            load(dir.path())
                .expect("the recorded take remains readable")
                .len(),
            1
        );

        let replay = Cassette::replay(dir.path(), Mode::Strict).expect("strict replay loads");
        assert!(!replay.complete_reports_physical_calls());
        assert!(!replay.review_reports_physical_calls());
        crate::ports::model::with_model_call_observer(
            physical_events.clone(),
            replay.complete(request("probe", "first paid response")),
        )
        .await
        .expect("replay serves the recorded response without another live call");
        assert_eq!(completed.load(Ordering::Relaxed), 1);
        assert_eq!(physical_events.0.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn recording_cassette_preserves_dispatch_control_across_budget_binding_orders() {
    use crate::harness::mock::execution_test_support::{DispatchProbe, execution_control};
    use crate::ports::model_execution::ModelExecutionRefusal;

    for scope_first in [false, true] {
        for control_first in [false, true] {
            let dir = tempfile::tempdir().expect("temporary cassette directory");
            let mock = MockModel::new()
                .then(json!({"summary":"first"}))
                .then(json!({"summary":"must remain queued"}))
                .with_usage(Usage {
                    input_tokens: 2,
                    output_tokens: 1,
                    calls_attempted: 1,
                    calls_succeeded: 1,
                    cost_usd: 1.0,
                    ..Usage::default()
                });
            let cassette = Arc::new(Cassette::record(
                Arc::new(DispatchProbe::new(mock.clone())),
                dir.path(),
            ));
            let model: Arc<dyn Model> = cassette.clone();
            let (execution, control) = execution_control(1);
            let scoped = if scope_first {
                model
                    .scoped_budget(8.0)
                    .expect("recording cassette creates a lane scope")
            } else {
                model
            };
            let root = if control_first {
                let controlled = scoped
                    .with_execution_control(control)
                    .unwrap_or_else(|| scoped.clone());
                controlled
                    .with_review_budget(10.0)
                    .expect("recording cassette binds the shared review budget")
            } else {
                let budgeted = scoped
                    .with_review_budget(10.0)
                    .expect("recording cassette binds the shared review budget");
                budgeted.with_execution_control(control).unwrap_or(budgeted)
            };
            let lane = root
                .scoped_budget(8.0)
                .expect("rescoping retains the recording state and both controls");

            assert!(
                root.complete(request("probe", "first paid response"))
                    .await
                    .is_ok()
            );
            assert!(matches!(
                lane.complete(request("probe", "refused second response"))
                    .await,
                Err(Error::ModelExecutionRefused {
                    refusal: ModelExecutionRefusal::CallLimit,
                    ..
                })
            ));
            assert_eq!(
                mock.calls(),
                1,
                "the refused call does not reach the inner model"
            );
            assert_eq!(execution.snapshot().committed_calls, 1);
            assert_eq!(cassette.served(), 1);
            assert_eq!(cassette.spend().usage.input_tokens, 2);
            assert_eq!(cassette.cost_usd(), 1.0);
            assert_eq!(
                cassette
                    .flush()
                    .expect("the shared recorder retains its first take"),
                1
            );
            assert_eq!(load(dir.path()).expect("recorded take loads").len(), 1);
            assert!(root.complete_reports_physical_calls());
            assert!(root.review_reports_physical_calls());
        }
    }
}

#[tokio::test]
async fn replay_cassette_serves_answers_without_committing_a_live_dispatch_permit() {
    use crate::harness::mock::execution_test_support::execution_control;

    let dir = tempfile::tempdir().expect("temporary cassette directory");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("probe", "recorded response"))
        .await
        .expect("recording writes one take");
    recorder.flush().expect("write the take to disk");

    let replay = Cassette::replay(dir.path(), Mode::Strict).expect("load recorded take");
    let (execution, control) = execution_control(1);
    assert!(replay.with_execution_control(control).is_none());
    let response = replay
        .complete(request("probe", "recorded response"))
        .await
        .expect("offline replay does not need a live dispatch capability");
    assert_eq!(response.value, answer());
    assert_eq!(execution.snapshot().committed_calls, 0);
    assert!(!replay.complete_reports_physical_calls());
}

#[tokio::test]
async fn recording_cassette_review_reports_the_physical_path_it_uses() {
    let dir = tempfile::tempdir().expect("temporary cassette directory");
    let inner = Arc::new(ReviewBudgetProbe::default());
    let completed = inner.completed.clone();
    let cassette = Arc::new(Cassette::record(inner.clone(), dir.path()));
    let physical_events = Arc::new(PhysicalEventCounter(std::sync::atomic::AtomicUsize::new(0)));
    let tree = crate::ports::tree::MockTree::from_files([("src/lib.rs", "pub fn answer() {}")]);
    let policy = crate::config::types::LookupPolicy::default();

    // The probe's own review is logical-only. Cassette has no review override,
    // so the trait default routes it through Cassette::complete and the inner
    // model's physical completion path.
    let logical = crate::ports::model::with_model_call_observer(
        physical_events.clone(),
        inner.review(request("probe", "logical review"), &tree, &policy),
    )
    .await
    .expect("the inner logical review succeeds");
    assert_eq!(logical.usage.calls_attempted, 0);
    assert_eq!(completed.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(
        physical_events.0.load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let recorded = crate::ports::model::with_model_call_observer(
        physical_events.clone(),
        cassette.review(request("probe", "recorded review"), &tree, &policy),
    )
    .await
    .expect("recording review uses the inner physical completion");
    assert_eq!(recorded.value, answer());
    assert_eq!(completed.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        physical_events.0.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the effective completion path emits one physical event"
    );
    assert_eq!(cassette.served(), 1);
    assert_eq!(
        cassette
            .flush()
            .expect("the review was recorded in the cassette"),
        1
    );
    assert!(cassette.complete_reports_physical_calls());
    assert_eq!(
        cassette.review_reports_physical_calls(),
        cassette.complete_reports_physical_calls(),
        "review defaults to the cassette's complete implementation"
    );
}

fn request(model: &str, prompt: &str) -> ModelRequest {
    ModelRequest {
        model: model.to_string(),
        messages: vec![Message::system("instructions"), Message::user(prompt)],
        schema: json!({"type": "object"}),
        schema_name: "tinysweeper_critique".into(),
        max_tokens: 8000,
    }
}

fn answer() -> serde_json::Value {
    json!({"summary": "Nothing to report.", "findings": []})
}

#[test]
fn the_key_covers_everything_that_can_change_an_answer() {
    let base = request("z-ai/glm-5.2", "the diff");

    assert_eq!(key(&base), key(&request("z-ai/glm-5.2", "the diff")));

    let other_model = request("deepseek/deepseek-v4-pro", "the diff");
    assert_ne!(
        key(&base),
        key(&other_model),
        "the model decides the answer"
    );

    let other_prompt = request("z-ai/glm-5.2", "a different diff");
    assert_ne!(key(&base), key(&other_prompt), "so does the prompt");

    let mut other_schema = base.clone();
    other_schema.schema_name = "tinysweeper_falsify".into();
    assert_ne!(key(&base), key(&other_schema), "and the schema");

    // The same name with a different body is a different output contract: a
    // provider that answers against `properties: {summary: string}` does not
    // answer like one against `properties: {findings: []}`.
    let mut other_schema = base.clone();
    other_schema.schema = json!({"type": "object", "properties": {"findings": {"type": "array"}}});
    assert_ne!(key(&base), key(&other_schema), "and the schema body");

    let mut other_ceiling = base.clone();
    other_ceiling.max_tokens = 4000;
    assert_ne!(
        key(&base),
        key(&other_ceiling),
        "a model that runs out of tokens answers differently"
    );
}

#[test]
fn the_key_is_the_schema_not_its_key_order() {
    // `serde_json`'s map order is a feature flag, not a property of the value.
    // The `serve` build enables `preserve_order` (via `bson`), so the same
    // contract stringifies with its keys in a different order than the offline
    // build. The key must hash the contract, not this build's serialization
    // quirk. Both schemas below are the same schema, keys written in different
    // order at two depths; without canonical sorting they hash differently
    // exactly in the `serve` CI job.
    let first = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "summary": {"type": "string"},
            "findings": {"type": "array"}
        },
        "required": ["summary"]
    });
    let second = json!({
        "properties": {
            "findings": {"type": "array"},
            "summary": {"type": "string"}
        },
        "required": ["summary"],
        "additionalProperties": false,
        "type": "object"
    });

    let with_schema = |schema| {
        let mut r = request("z-ai/glm-5.2", "the diff");
        r.schema = schema;
        r
    };
    assert_eq!(
        key(&with_schema(first)),
        key(&with_schema(second)),
        "the key must hash the schema, not the build's key serialization order"
    );
}

#[test]
fn the_key_distinguishes_who_said_what() {
    // The same text as a system instruction and as user evidence is not the
    // same prompt: one is policy and the other is attacker-controlled.
    let mut swapped = request("z-ai/glm-5.2", "text");
    swapped.messages = vec![Message::user("instructions"), Message::system("text")];
    assert_ne!(key(&request("z-ai/glm-5.2", "text")), key(&swapped));
}

#[tokio::test]
async fn a_recording_replays_the_same_answer_the_same_cost_and_the_same_model() {
    let dir = tempfile::tempdir().expect("tempdir");

    let live = Arc::new(
        MockModel::always(answer())
            .answering_as("deepseek/deepseek-v4-pro")
            .with_usage(Usage {
                input_tokens: 1_200,
                output_tokens: 300,
                reasoning_tokens: 0,
                calls_attempted: 0,
                calls_succeeded: 0,
                calls_refused: 0,
                calls_errored: 0,
                cached_tokens: 900,
                embed_tokens: 0,
                cost_usd: 0.000_15,
            }),
    );
    let recorder = Cassette::record(live, dir.path());
    let recorded = recorder
        .complete(request("z-ai/glm-5.2", "the diff"))
        .await
        .expect("records");
    assert_eq!(recorder.flush().expect("flushes"), 1);

    let player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    let replayed = player
        .complete(request("z-ai/glm-5.2", "the diff"))
        .await
        .expect("replays");

    assert_eq!(replayed.value, recorded.value);
    // The fallback is part of the recording: the run being reproduced is the
    // one where a cheaper model answered, not the one that was configured.
    assert_eq!(replayed.model, "deepseek/deepseek-v4-pro");
    // Replayed verbatim rather than re-derived through the price table, so a
    // re-score reports the dollars the live run actually paid.
    assert_eq!(replayed.usage.cost_usd, 0.000_15);
    assert_eq!(replayed.usage.cached_tokens, 900);
}

#[tokio::test]
async fn a_changed_prompt_is_a_loud_miss_rather_than_a_stale_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "the diff"))
        .await
        .expect("records");
    recorder.flush().expect("flushes");

    let player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    let err = player
        .complete(request("z-ai/glm-5.2", "the diff, reworded"))
        .await
        .expect_err("must not serve the old answer");

    let message = err.to_string();
    // The message has to say what to do, because "the corpus is stale" is the
    // single most common thing this will report.
    assert!(message.contains("prompt changed"), "{message}");
    assert!(message.contains("re-record"), "{message}");
    assert!(message.contains("tinysweeper_critique"), "{message}");
}

#[tokio::test]
async fn a_loose_replay_survives_a_cosmetic_edit_and_counts_that_it_did() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "the diff"))
        .await
        .expect("records");
    recorder.flush().expect("flushes");

    let player = Cassette::replay(dir.path(), Mode::Loose).expect("loads");
    let replayed = player
        .complete(request("z-ai/glm-5.2", "the  diff"))
        .await
        .expect("falls back to call order");

    assert_eq!(replayed.value, answer());
    // Counted, and reported, so a loose run is never mistaken for a strict one.
    assert_eq!(player.loose_hits(), 1);
}

#[tokio::test]
async fn an_exhausted_loose_cassette_says_how_far_it_got() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "one"))
        .await
        .expect("records");
    recorder.flush().expect("flushes");

    let player = Cassette::replay(dir.path(), Mode::Loose).expect("loads");
    player
        .complete(request("z-ai/glm-5.2", "two"))
        .await
        .expect("first falls back");
    let err = player
        .complete(request("z-ai/glm-5.2", "three"))
        .await
        .expect_err("nothing left");

    assert!(err.to_string().contains("exhausted"), "{err}");
}

#[tokio::test]
async fn cost_usd_sums_every_answer_served_recorded_or_replayed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let live = Arc::new(MockModel::always(answer()).with_usage(Usage {
        input_tokens: 100,
        output_tokens: 20,
        reasoning_tokens: 0,
        calls_attempted: 0,
        calls_succeeded: 0,
        calls_refused: 0,
        calls_errored: 0,
        cached_tokens: 0,
        embed_tokens: 0,
        cost_usd: 0.01,
    }));
    let recorder = Cassette::record(live, dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "one"))
        .await
        .expect("records");
    recorder
        .complete(request("z-ai/glm-5.2", "two"))
        .await
        .expect("records");
    assert_eq!(recorder.cost_usd(), 0.02);
    recorder.flush().expect("flushes");

    // Replay reports the same figure, because usage is replayed verbatim.
    let player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    player
        .complete(request("z-ai/glm-5.2", "one"))
        .await
        .expect("replays");
    player
        .complete(request("z-ai/glm-5.2", "two"))
        .await
        .expect("replays");
    assert_eq!(player.cost_usd(), 0.02);

    // A strict miss served no answer and must cost nothing — a failed case is
    // charged only for what it actually used.
    let miss_dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), miss_dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "known"))
        .await
        .expect("records");
    recorder.flush().expect("flushes");
    let strict = Cassette::replay(miss_dir.path(), Mode::Strict).expect("loads");
    strict
        .complete(request("z-ai/glm-5.2", "different"))
        .await
        .expect_err("must not serve the old answer");
    assert_eq!(strict.cost_usd(), 0.0);
}

#[tokio::test]
async fn calls_replay_in_the_order_they_were_made() {
    let dir = tempfile::tempdir().expect("tempdir");
    let live = MockModel::new()
        .then(json!({"n": 1}))
        .then(json!({"n": 2}))
        .then(json!({"n": 3}));
    let recorder = Cassette::record(Arc::new(live), dir.path());
    for prompt in ["one", "two", "three"] {
        recorder
            .complete(request("z-ai/glm-5.2", prompt))
            .await
            .expect("records");
    }
    assert_eq!(recorder.flush().expect("flushes"), 3);

    // Filename order is call order, which is what the loose fallback rides on.
    let player = Cassette::replay(dir.path(), Mode::Loose).expect("loads");
    for expected in 1..=3 {
        let got = player
            .complete(request("z-ai/glm-5.2", "unrecognised"))
            .await
            .expect("falls back in order");
        assert_eq!(got.value, json!({"n": expected}));
    }
}

#[tokio::test]
async fn two_identical_prompts_in_one_run_both_survive_the_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "same"))
        .await
        .expect("records");
    recorder
        .complete(request("z-ai/glm-5.2", "same"))
        .await
        .expect("records");

    // Same key both times. Keying the filename on the hash alone would have
    // written one file and lost a call, which shows up later as a cassette
    // that runs out early.
    assert_eq!(recorder.flush().expect("flushes"), 2);
    let files = std::fs::read_dir(dir.path()).expect("readable").count();
    assert_eq!(files, 2);
}

#[tokio::test]
async fn a_prompt_is_not_written_to_disk_unless_it_is_asked_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(Arc::new(MockModel::always(answer())), dir.path());
    recorder
        .complete(request("z-ai/glm-5.2", "a private repository's diff"))
        .await
        .expect("records");
    recorder.flush().expect("flushes");

    let written = std::fs::read_dir(dir.path())
        .expect("readable")
        .filter_map(|e| e.ok())
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<String>();

    // A cassette committed from a private repository must not carry its diff.
    assert!(
        !written.contains("a private repository's diff"),
        "the prompt was written without being asked for: {written}"
    );

    let dir2 = tempfile::tempdir().expect("tempdir");
    let opted_in =
        Cassette::record(Arc::new(MockModel::always(answer())), dir2.path()).with_prompts(true);
    opted_in
        .complete(request("z-ai/glm-5.2", "a public repository's diff"))
        .await
        .expect("records");
    opted_in.flush().expect("flushes");
    let written2 = std::fs::read_dir(dir2.path())
        .expect("readable")
        .filter_map(|e| e.ok())
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<String>();
    assert!(written2.contains("a public repository's diff"));
}

#[test]
fn replaying_a_directory_that_holds_no_cassette_says_how_to_make_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = Cassette::replay(dir.path().join("absent"), Mode::Strict).expect_err("no cassette");
    assert!(err.to_string().contains("eval run --record"), "{err}");
}

struct RefusingModel(Option<crate::ports::model::Usage>);

#[async_trait::async_trait]
impl Model for RefusingModel {
    async fn complete(&self, _request: ModelRequest) -> Result<ModelResponse> {
        let error = crate::error::Error::Model("refused".into());
        Err(match self.0 {
            Some(usage) => error.with_usage(usage),
            None => error,
        })
    }
}

#[tokio::test]
async fn reported_refusal_usage_is_counted_without_inventing_an_answer_model() {
    let dir = tempfile::tempdir().unwrap();
    let recorder = Cassette::record(
        Arc::new(RefusingModel(Some(crate::ports::model::Usage {
            input_tokens: 100,
            output_tokens: 10,
            cost_usd: 0.01,
            ..Default::default()
        }))),
        dir.path(),
    );
    assert!(
        recorder
            .complete(request("requested-model", "review"))
            .await
            .is_err()
    );
    assert_eq!(recorder.cost_usd(), 0.01);
    assert_eq!(recorder.spend().usage.input_tokens, 100);
    assert!(recorder.spend().models.is_empty());
    assert!(!recorder.has_unreported_usage());
    assert_eq!(
        recorder.flush().unwrap(),
        0,
        "A refusal is not an invented response cassette"
    );
}

#[tokio::test]
async fn unreported_refusal_charge_remains_explicitly_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let recorder = Cassette::record(Arc::new(RefusingModel(None)), dir.path());
    assert!(
        recorder
            .complete(request("requested-model", "review"))
            .await
            .is_err()
    );
    assert_eq!(recorder.cost_usd(), 0.0);
    assert!(recorder.has_unreported_usage());
    assert!(recorder.spend().models.is_empty());
}
