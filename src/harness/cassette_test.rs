//! Cassette recording, replay, and the two ways it is allowed to miss.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::harness::mock::MockModel;
use crate::ports::model::{Message, ModelResponse};
use crate::ports::tree::{Found, Lookup, TreeQuery, TreeReader};

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

struct ReviewOnlyModel {
    reviews: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Model for ReviewOnlyModel {
    async fn complete(&self, _request: ModelRequest) -> Result<ModelResponse> {
        Err(crate::error::Error::Model(
            "the test requires Model::review".into(),
        ))
    }

    async fn review(
        &self,
        _request: ModelRequest,
        tree: &dyn TreeReader,
        _policy: &crate::config::types::LookupPolicy,
    ) -> Result<ModelResponse> {
        self.reviews
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = tree
            .lookup(&Lookup::Read {
                path: "src/lib.rs".into(),
                start: Some(1),
                end: Some(2),
            })
            .await?;
        let _ = tree
            .explore(&TreeQuery::Symbol {
                symbol: "load_state".into(),
                limit: 3,
            })
            .await?;
        Ok(ModelResponse {
            value: answer(),
            model: "test/review-only".into(),
            usage: Usage {
                input_tokens: 17,
                output_tokens: 5,
                cost_usd: 0.002,
                ..Default::default()
            },
        })
    }
}

struct ReviewTree;

#[async_trait::async_trait]
impl TreeReader for ReviewTree {
    async fn lookup(&self, lookup: &Lookup) -> Result<Found> {
        Ok(match lookup {
            Lookup::Read { path, .. } if path == "src/lib.rs" => Found::Text {
                text: "1: pub fn load_state() {}\n2: // source".into(),
                start: 1,
                end: 2,
                total: 2,
            },
            _ => Found::NotFound,
        })
    }

    async fn explore(&self, query: &TreeQuery) -> Result<Found> {
        Ok(match query {
            TreeQuery::Symbol { symbol, .. } if symbol == "load_state" => Found::Hits {
                hits: vec![crate::ports::tree::Hit {
                    path: "src/lib.rs".into(),
                    line: 1,
                    text: "pub fn load_state() {}".into(),
                }],
                truncated: false,
                skipped: vec![],
            },
            _ => Found::NotFound,
        })
    }

    fn describe(&self) -> String {
        "test tree".into()
    }

    fn revision(&self) -> Option<String> {
        Some("a".repeat(40))
    }
}

#[tokio::test]
async fn recording_review_forwards_actual_review_and_tree_queries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let live = Arc::new(ReviewOnlyModel {
        reviews: std::sync::atomic::AtomicUsize::new(0),
    });
    let recorder = Cassette::record(live.clone(), dir.path());
    let policy = crate::config::types::LookupPolicy::default();

    let response = recorder
        .review(request("test/review-only", "inspect this change"), &ReviewTree, &policy)
        .await
        .expect("records through review");

    assert_eq!(response.model, "test/review-only");
    assert_eq!(live.reviews.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(recorder.flush().expect("flushes"), 1);
    let take: Take = serde_json::from_str(
        &std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .expect("cassette directory")
                .next()
                .expect("one take")
                .expect("take entry")
                .path(),
        )
        .expect("take file"),
    )
    .expect("take json");
    let context = take.review_context.expect("review query context");
    let revision = "a".repeat(40);
    assert_eq!(context.revision.as_deref(), Some(revision.as_str()));
    assert_eq!(context.queries.len(), 2);
    assert!(matches!(
        context.queries[0].query,
        RecordedTreeQuery::Lookup(Lookup::Read { .. })
    ));
    assert!(matches!(
        context.queries[1].query,
        RecordedTreeQuery::Symbol { .. }
    ));
    assert_eq!(take.usage.cost_usd, 0.002);
}

#[tokio::test]
async fn review_replay_reissues_queries_and_reconstructs_identical_evidence_offline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let live = Arc::new(ReviewOnlyModel {
        reviews: std::sync::atomic::AtomicUsize::new(0),
    });
    let source = ReviewTree;
    let recording_tree = crate::ports::tree::RecordingTree::new(&source);
    let recorder = Arc::new(Cassette::record(live.clone(), dir.path()));
    let mut models = crate::config::types::Models::default();
    models.agentic_reviewers = true;
    let live_cap = crate::flows::caps::ModelCapability::new(recorder.clone(), models.clone());
    let call = crate::flows::panel::Call {
        id: "reviewer".into(),
        model: "test/review-only".into(),
        system: "inspect".into(),
        prompt: "change evidence".into(),
        schema_name: "tinysweeper_critique".into(),
    };
    let schema = json!({"type": "object"});
    let policy = crate::config::types::LookupPolicy::default();
    let (live_response, live_evidence) = live_cap
        .review(&call, &schema, &recording_tree, &policy)
        .await
        .expect("live review");
    recorder.flush().expect("flushes actual review response");
    assert_eq!(live.reviews.load(std::sync::atomic::Ordering::SeqCst), 1);

    let recorded_lookups = recording_tree.recorded();
    assert_eq!(recorded_lookups.len(), 2);
    let replay_tree = crate::ports::tree::MockTree::from_recorded(recorded_lookups);
    let replay = Arc::new(Cassette::replay(dir.path(), Mode::Strict).expect("loads"));
    let replay_cap = crate::flows::caps::ModelCapability::new(replay.clone(), models);
    let (replayed_response, replayed_evidence) = replay_cap
        .review(&call, &schema, &replay_tree, &policy)
        .await
        .expect("offline replay reissues source reads");

    assert_eq!(replayed_response.value, live_response.value);
    assert_eq!(replayed_response.usage, live_response.usage);
    assert_eq!(replayed_evidence, live_evidence);
    assert_eq!(replay.served(), 1);
    assert_eq!(replay.strict_misses(), 0);

    let falsification_request = |evidence: &str| {
        let mut request = request("test/review-only", "falsify the finding");
        request.messages.push(Message::user(evidence));
        request
    };
    assert_eq!(
        key(&falsification_request(&live_evidence)),
        key(&falsification_request(&replayed_evidence)),
        "source evidence must keep the downstream falsification prompt stable"
    );
}

#[tokio::test]
async fn review_context_policy_revision_and_method_are_part_of_strict_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = Cassette::record(
        Arc::new(ReviewOnlyModel {
            reviews: std::sync::atomic::AtomicUsize::new(0),
        }),
        dir.path(),
    );
    let review_request = request("test/review-only", "inspect this change");
    let policy = crate::config::types::LookupPolicy::default();
    recorder.review(review_request.clone(), &ReviewTree, &policy).await.expect("records");
    recorder.flush().expect("flushes");

    let player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    let mut changed_policy = policy.clone();
    changed_policy.rounds += 1;
    assert!(player.review(review_request.clone(), &ReviewTree, &changed_policy).await.is_err());
    assert_eq!(player.strict_misses(), 1);

    struct DifferentRevision;
    #[async_trait::async_trait]
    impl TreeReader for DifferentRevision {
        async fn lookup(&self, _: &Lookup) -> Result<Found> { Ok(Found::NotFound) }
        fn describe(&self) -> String { "same reader".into() }
        fn revision(&self) -> Option<String> { Some("b".repeat(40)) }
    }
    let revision_player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    assert!(revision_player
        .review(review_request.clone(), &DifferentRevision, &policy)
        .await
        .is_err());
    assert_eq!(revision_player.strict_misses(), 1);

    let method_player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    assert!(method_player.complete(review_request).await.is_err());
    assert_eq!(method_player.strict_misses(), 1);

    struct SameRevisionDifferentSource;
    #[async_trait::async_trait]
    impl TreeReader for SameRevisionDifferentSource {
        async fn lookup(&self, _: &Lookup) -> Result<Found> { Ok(Found::NotFound) }
        async fn explore(&self, _: &TreeQuery) -> Result<Found> { Ok(Found::NotFound) }
        fn describe(&self) -> String { "/different/absolute/archive".into() }
        fn revision(&self) -> Option<String> { Some("a".repeat(40)) }
    }
    let source_player = Cassette::replay(dir.path(), Mode::Strict).expect("loads");
    assert!(source_player
        .review(request("test/review-only", "inspect this change"), &SameRevisionDifferentSource, &policy)
        .await
        .is_err());
    assert_eq!(source_player.strict_misses(), 1);
    assert_eq!(source_player.cost_usd(), 0.0);
}

struct ScopedQuotaModel {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    scopes: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl Model for ScopedQuotaModel {
    async fn complete(&self, _request: ModelRequest) -> Result<ModelResponse> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if call > 0 {
            return Err(crate::error::Error::Model("scope exhausted".into()).with_usage(
                Usage {
                    input_tokens: 50,
                    output_tokens: 7,
                    cost_usd: 0.005,
                    ..Default::default()
                },
            ));
        }
        Ok(ModelResponse {
            value: answer(),
            model: "test/scoped".into(),
            usage: Usage {
                input_tokens: 100,
                output_tokens: 12,
                cost_usd: 0.01,
                ..Default::default()
            },
        })
    }

    fn scoped_budget(&self, budget_usd: f64) -> Option<Arc<dyn Model>> {
        assert!(budget_usd > 0.0);
        self.scopes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(Arc::new(Self {
            calls: self.calls.clone(),
            scopes: self.scopes.clone(),
        }))
    }
}

#[tokio::test]
async fn scoped_review_and_direct_calls_share_the_root_cassette_and_refusal_spend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let model = Arc::new(ScopedQuotaModel {
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        scopes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
    let recorder = Arc::new(Cassette::record(model.clone(), dir.path()));
    let mut models = crate::config::types::Models::default();
    models.agentic_reviewers = true;
    models.budget_usd_per_pr = 100.0;
    let capability = crate::flows::caps::ModelCapability::new(recorder.clone(), models);
    let policy = crate::config::types::LookupPolicy {
        enabled: false,
        ..Default::default()
    };
    let call = crate::flows::panel::Call {
        id: "reviewer".into(),
        model: "test/scoped".into(),
        system: "inspect".into(),
        prompt: "change evidence".into(),
        schema_name: "tinysweeper_critique".into(),
    };
    capability
        .review(&call, &json!({}), &ReviewTree, &policy)
        .await
        .expect("first call goes through scoped review");
    let err = capability
        .model()
        .complete(request("test/scoped", "direct follow-up"))
        .await
        .expect_err("the same finite model scope refuses the second call");

    assert!(err.to_string().contains("scope exhausted"));
    assert!(model.scopes.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    assert_eq!(model.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(recorder.served(), 1);
    assert_eq!(recorder.spend().usage.input_tokens, 150);
    assert_eq!(recorder.cost_usd(), 0.015);
    assert_eq!(recorder.flush().expect("root cassette sees scoped response"), 1);
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
