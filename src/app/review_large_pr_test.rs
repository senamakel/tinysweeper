//! End-to-end acceptance fixtures for bounded large pull-request reviews.

use crate::app::review::{Proposal, review};
use crate::config::types::{Config, CouncilAgent};
use crate::error::{Error, Result};
use crate::forge::mock::{MockForge, MockState, Write};
use crate::forge::types::{
    ChangedFile, FileStatus, PullRequest, RepoId, ReviewThread, ThreadComment,
};
use crate::harness::mock::MockModel;
use crate::ports::model::{Model, ModelRequest, ModelResponse, Usage};
use crate::ports::model_execution::ModelExecutionControl;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct LargeReviewModel {
    control: Option<Arc<dyn ModelExecutionControl>>,
    attempts: Arc<Mutex<Vec<ModelRequest>>>,
    calls: Arc<Mutex<Vec<ModelRequest>>>,
    finding: bool,
}

#[async_trait::async_trait]
impl Model for LargeReviewModel {
    async fn complete(&self, request: ModelRequest) -> Result<ModelResponse> {
        self.attempts
            .lock()
            .expect("attempt list lock")
            .push(request.clone());
        let control = self
            .control
            .as_ref()
            .ok_or(Error::ReviewExecutionUnavailable)?;
        let permit = control
            .acquire()
            .await
            .map_err(|refusal| Error::ModelExecutionRefused {
                refusal,
                usage: None,
                accounting_complete: true,
            })?;
        permit
            .mark_dispatched()
            .map_err(|refusal| Error::ModelExecutionRefused {
                refusal,
                usage: None,
                accounting_complete: true,
            })?;
        self.calls
            .lock()
            .expect("successful call list lock")
            .push(request.clone());

        let prompt = request
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<String>();
        let value = match request.schema_name.as_str() {
            "tinysweeper_critique" if self.finding && prompt.contains("src/z_api.rs") => {
                json!({
                    "summary": "The public API result should be documented.",
                    "findings": [{
                        "path": "src/z_api.rs",
                        "existing_code": "pub fn z_api() -> bool { true }",
                        "rule": "api-documentation",
                        "title": "Document the public API result",
                        "body": "The public result contract is not described.",
                        "severity": "medium",
                        "confidence": 0.95
                    }]
                })
            }
            "tinysweeper_critique" | "tinysweeper_security" => json!({
                "summary": "No additional issue was found.",
                "findings": []
            }),
            "tinysweeper_falsify" => json!({ "incorrect": [] }),
            "review_summary" => json!({
                "executive_summary": "The change updates the reviewed repository.",
                "changes": "The reviewed changes update source and interface files.",
                "features": [],
                "tests": [],
                "positive_observations": {}
            }),
            "tinysweeper_thread_resolution" => json!({
                "resolve": false,
                "reason": "The reply does not establish that the finding is fixed."
            }),
            "tinysweeper_wireframe" => json!({ "screens": [] }),
            schema => return Err(Error::Model(format!("unexpected schema {schema}"))),
        };
        drop(permit);
        Ok(ModelResponse {
            value,
            model: request.model,
            usage: Usage {
                input_tokens: 2,
                output_tokens: 1,
                cost_usd: 0.0001,
                ..Usage::default()
            },
        })
    }

    fn with_execution_control(
        &self,
        control: Arc<dyn ModelExecutionControl>,
    ) -> Option<Arc<dyn Model>> {
        let mut bound = self.clone();
        bound.control = Some(control);
        Some(Arc::new(bound))
    }
}

fn config() -> Config {
    let mut config: Config = crate::config::DEFAULTS
        .parse::<toml::Table>()
        .expect("default config parses")
        .try_into()
        .expect("default config converts");
    config.review.lanes = vec!["critique".into()];
    config.summary.enabled = true;
    config.knowledge.extract = false;
    config.retrieval.enabled = false;
    config
}

fn changed_file(path: &str) -> ChangedFile {
    ChangedFile {
        path: path.into(),
        status: FileStatus::Modified,
        additions: 1,
        deletions: 1,
        patch: Some(format!(
            "@@ -0,0 +1,1 @@\n+fn {}() {{}}\n",
            path.rsplit('/').next().unwrap().trim_end_matches(".rs")
        )),
        ..ChangedFile::default()
    }
}

fn large_fixture_files() -> Vec<ChangedFile> {
    let mut files = vec![
        ChangedFile {
            path: "src/x_api.rs".into(),
            status: FileStatus::Modified,
            additions: 1,
            deletions: 1,
            patch: Some("@@ -0,0 +1,1 @@\n+pub fn x_api() -> bool { true }\n".into()),
            ..ChangedFile::default()
        },
        ChangedFile {
            path: "src/y_api.rs".into(),
            status: FileStatus::Modified,
            additions: 1,
            deletions: 1,
            patch: Some("@@ -0,0 +1,1 @@\n+pub fn y_api() -> bool { true }\n".into()),
            ..ChangedFile::default()
        },
        ChangedFile {
            path: "src/z_api.rs".into(),
            status: FileStatus::Modified,
            additions: 1,
            deletions: 1,
            patch: Some("@@ -0,0 +1,1 @@\n+pub fn z_api() -> bool { true }\n".into()),
            ..ChangedFile::default()
        },
        ChangedFile {
            path: "app/src/Button.tsx".into(),
            status: FileStatus::Modified,
            additions: 1,
            deletions: 1,
            patch: Some("@@ -0,0 +1,1 @@\n+function Button() { return <button />; }\n".into()),
            ..ChangedFile::default()
        },
    ];
    files.extend((0..56).map(|index| ChangedFile {
        path: format!("src/plain_{index:02}.rs"),
        status: FileStatus::Modified,
        additions: 1,
        deletions: 1,
        patch: Some(format!("@@ -0,0 +1,1 @@\n+fn plain_{index}() {{}}\n")),
        ..ChangedFile::default()
    }));
    files
}

fn large_config() -> Config {
    let mut config = config();
    config.review.lanes = vec!["critique".into(), "security".into()];
    config.review.strictness = 3;
    config.review.passes = 3;
    config.council.enabled = true;
    config.council.agents = vec![CouncilAgent {
        id: "extra-reviewer".into(),
        ..CouncilAgent::default()
    }];
    config.review.large_pr.files = 30;
    config.review.large_pr.max_groups = 6;
    config.review.large_pr.max_calls = 8;
    config.grouping.enabled = false;
    config.review.approve_when_clean = true;
    config.automerge.enabled = true;
    config.threads.resolve_fixed = true;
    config.threads.ask_model = true;
    config.summary.enabled = true;
    config.wireframe.enabled = true;
    config
}

fn large_forge() -> MockForge {
    let mut state = MockState::default();
    state.pull_requests.insert(
        7,
        PullRequest {
            number: 7,
            title: "feat: bounded large review".into(),
            body: "Review the changed API and interface files.".into(),
            head_sha: "abc123".into(),
            ..PullRequest::default()
        },
    );
    state.files.insert(7, large_fixture_files());
    state.review_threads.insert(
        7,
        vec![ReviewThread {
            id: "PRRT_prior_bot_finding".into(),
            is_resolved: false,
            is_outdated: false,
            comments: vec![
                ThreadComment {
                    author: "tinysweeper[bot]".into(),
                    body: "**Existing invariant**".into(),
                    bot: true,
                    maintainer: false,
                },
                ThreadComment {
                    author: "maintainer".into(),
                    body: "This behavior is intentional.".into(),
                    bot: false,
                    maintainer: true,
                },
            ],
            ..ReviewThread::default()
        }],
    );
    MockForge::with_state(state)
}

async fn run_large_fixture(finding: bool) -> (Proposal, MockForge, Arc<LargeReviewModel>, Config) {
    let forge = large_forge();
    let config = large_config();
    let model = Arc::new(LargeReviewModel {
        control: None,
        attempts: Arc::new(Mutex::new(Vec::new())),
        calls: Arc::new(Mutex::new(Vec::new())),
        finding,
    });
    let proposal = review(
        &forge,
        model.clone() as Arc<dyn Model>,
        &config,
        &RepoId::parse("tinyhumansai/tinysweeper").expect("repo id"),
        7,
    )
    .await
    .expect("the bounded large review returns a proposal");
    (proposal, forge, model, config)
}

fn selected_lane_paths(requests: &[ModelRequest]) -> std::collections::BTreeSet<(String, String)> {
    let mut selected = std::collections::BTreeSet::new();
    for request in requests {
        if !matches!(
            request.schema_name.as_str(),
            "tinysweeper_critique" | "tinysweeper_security"
        ) {
            continue;
        }
        let prompt = request
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<String>();
        let path = ["src/x_api.rs", "src/y_api.rs", "src/z_api.rs"]
            .into_iter()
            .find(|path| prompt.contains(&format!("The file is `{path}`.")))
            .expect("lane request names one selected API unit");
        selected.insert((request.schema_name.clone(), path.to_string()));
    }
    selected
}

#[tokio::test]
async fn sixty_file_empty_large_review_uses_six_global_groups_and_the_shared_call_ceiling() {
    let (proposal, forge, model, config) = run_large_fixture(false).await;
    let calls = model.calls.lock().expect("successful calls lock").clone();
    let expected: std::collections::BTreeSet<_> = [
        (
            "tinysweeper_critique".to_string(),
            "src/x_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/x_api.rs".to_string(),
        ),
        (
            "tinysweeper_critique".to_string(),
            "src/y_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/y_api.rs".to_string(),
        ),
        (
            "tinysweeper_critique".to_string(),
            "src/z_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/z_api.rs".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(selected_lane_paths(&calls), expected);
    assert_eq!(selected_lane_paths(&calls).len(), 6);
    assert!(calls.len() <= config.review.large_pr.max_calls);
    assert_eq!(proposal.usage().calls_attempted, 8);
    assert!(
        calls
            .iter()
            .any(|request| request.schema_name == "review_summary")
    );
    assert!(
        calls
            .iter()
            .any(|request| request.schema_name == "tinysweeper_thread_resolution")
    );
    assert!(config.threads.resolve_fixed && config.threads.ask_model);
    assert!(config.wireframe.enabled);
    assert!(
        model
            .attempts
            .lock()
            .expect("attempt list lock")
            .iter()
            .all(|request| request.schema_name != "tinysweeper_wireframe")
    );
    assert!(
        proposal.wireframe.is_none(),
        "the shared ceiling refuses later optional work"
    );
    assert!(proposal.partial_review.is_some());
    assert!(!proposal.complete());

    let changed_paths: std::collections::BTreeSet<_> = large_fixture_files()
        .into_iter()
        .map(|file| file.path)
        .collect();
    assert_eq!(changed_paths.len(), 60);
    let reviewed_paths: std::collections::BTreeSet<_> = proposal
        .lanes
        .iter()
        .flat_map(|lane| lane.coverage.iter())
        .flat_map(|coverage| coverage.reviewed.iter().cloned())
        .collect();
    let expected_reviewed: std::collections::BTreeSet<_> = [
        "src/x_api.rs".to_string(),
        "src/y_api.rs".to_string(),
        "src/z_api.rs".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(reviewed_paths, expected_reviewed);
    let expected_unreviewed = changed_paths
        .difference(&expected_reviewed)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        proposal
            .unreviewed
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_unreviewed,
        "coverage is per path across both lanes, so the six selected groups cover three files"
    );

    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("partial proposal is published");
    let writes = forge.writes();
    assert!(!writes.iter().any(|write| matches!(
        write,
        Write::Review {
            event: crate::forge::types::ReviewEvent::Approve,
            ..
        } | Write::Merged { .. }
    )));
}

#[tokio::test]
async fn sixty_file_large_review_places_and_falsifies_a_selected_finding_without_approval() {
    let (proposal, forge, model, config) = run_large_fixture(true).await;
    let calls = model.calls.lock().expect("successful calls lock").clone();
    let expected: std::collections::BTreeSet<_> = [
        (
            "tinysweeper_critique".to_string(),
            "src/x_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/x_api.rs".to_string(),
        ),
        (
            "tinysweeper_critique".to_string(),
            "src/y_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/y_api.rs".to_string(),
        ),
        (
            "tinysweeper_critique".to_string(),
            "src/z_api.rs".to_string(),
        ),
        (
            "tinysweeper_security".to_string(),
            "src/z_api.rs".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(selected_lane_paths(&calls), expected);
    assert!(
        calls
            .iter()
            .any(|request| request.schema_name == "tinysweeper_falsify")
    );
    assert!(
        calls
            .iter()
            .any(|request| request.schema_name == "review_summary")
    );
    assert!(calls.len() <= config.review.large_pr.max_calls);
    assert_eq!(proposal.usage().calls_attempted, 8);
    assert!(
        proposal
            .lanes
            .iter()
            .flat_map(|lane| lane.findings.iter())
            .any(|finding| finding.title == "Document the public API result")
    );
    assert!(!proposal.complete());

    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("finding and partial coverage are published");
    let writes = forge.writes();
    assert!(!writes.iter().any(|write| matches!(
        write,
        Write::Review {
            event: crate::forge::types::ReviewEvent::Approve,
            ..
        } | Write::Merged { .. }
    )));
    assert!(writes.iter().any(|write| matches!(write, Write::Check(_))));
    assert!(writes.iter().any(|write| matches!(write, Write::Comment { body, .. } if body.contains("Document the public API result"))));
}

#[cfg(feature = "harness")]
async fn wait_for_gateway_requests(
    gateway: &crate::harness::fake_gateway::FakeGateway,
    expected: usize,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while gateway.requests().len() < expected {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the Gateway receives every admitted physical request");
}

#[cfg(feature = "harness")]
fn gateway_empty_lane_reply(model: &str) -> crate::harness::fake_gateway::Reply {
    crate::harness::fake_gateway::Reply::completion(
        model,
        r#"{"summary":"No issue found.","findings":[]}"#,
        "stop",
        json!({"prompt_tokens":2,"completion_tokens":1,"cost":0.0001}),
    )
}

#[cfg(feature = "harness")]
#[tokio::test]
async fn sixty_file_gateway_repairs_share_the_physical_call_ceiling() {
    use crate::harness::embed::GatewayModel;
    use crate::harness::fake_gateway::{FakeGateway, Reply};

    let mut config = large_config();
    config.models.fallback.clear();
    config.models.provider.last_resort_unpinned = false;
    config.models.budget_usd_per_pr = 10.0;
    let primary = config.models.deep.clone();
    let mut replies = (0..6)
        .map(|_| {
            Reply::completion(
                &primary,
                "{ malformed JSON",
                "stop",
                json!({"prompt_tokens":2,"completion_tokens":1,"cost":0.0001}),
            )
        })
        .collect::<Vec<_>>();
    replies.extend((0..2).map(|_| gateway_empty_lane_reply(&primary)));
    let (gateway, release) = FakeGateway::start_paused(replies).await;
    config.models.base_url = gateway.base_url.clone();
    let forge = large_forge();
    let repo = RepoId::parse("tinyhumansai/tinysweeper").expect("repo id");
    let model: Arc<dyn Model> =
        Arc::new(GatewayModel::with_key(&config.models, "fixture-key".into()));
    let run_config = config.clone();
    let task = tokio::spawn(async move {
        let result = review(&forge, model, &run_config, &repo, 7).await;
        result.map(|proposal| (proposal, forge))
    });

    wait_for_gateway_requests(&gateway, 6).await;
    let initial = gateway.requests();
    assert!(
        initial[..6]
            .iter()
            .all(|request| request["model"] == primary)
    );
    release.add_permits(6);
    wait_for_gateway_requests(&gateway, 8).await;
    release.add_permits(2);

    let proposal = tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .expect("the call-limited review finishes after its two repairs")
        .expect("review task joins")
        .expect("partial review is returned");
    let (proposal, forge) = proposal;
    let requests = gateway.requests();
    assert_eq!(
        requests.len(),
        8,
        "repairs consume the shared physical limit"
    );
    assert!(requests.iter().all(|request| request["model"] == primary));
    assert_eq!(proposal.usage().calls_attempted, 8);
    assert!(!proposal.complete());
    assert_eq!(
        proposal
            .partial_review
            .as_ref()
            .and_then(|partial| partial.stop_reason),
        Some(crate::app::review::PartialReviewReason::CallLimit)
    );
    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("the partial repair-limited proposal is published");
    let writes = forge.writes();
    let check = writes
        .iter()
        .find_map(|write| match write {
            Write::Check(check) | Write::CheckUpdate { check, .. } => Some(check),
            _ => None,
        })
        .expect("the check publishes retained coverage");
    assert_eq!(
        check.conclusion,
        Some(crate::forge::types::CheckConclusion::Neutral)
    );
    assert!(check.summary.contains("not reviewed (call budget)"));
    let hub = writes.iter().find_map(|write| match write {
        Write::Comment { body, .. } | Write::CommentUpdate { body, .. } => Some(body),
        _ => None,
    });
    assert!(hub.is_some_and(|body| body.contains("not reviewed (call budget)")));
    assert!(!writes.iter().any(|write| matches!(
        write,
        Write::Review {
            event: crate::forge::types::ReviewEvent::Approve,
            ..
        } | Write::Merged { .. }
    )));
}

#[cfg(feature = "harness")]
#[tokio::test]
async fn sixty_file_gateway_fallbacks_share_the_physical_call_ceiling() {
    use crate::harness::embed::GatewayModel;
    use crate::harness::fake_gateway::{FakeGateway, Reply};

    let mut config = large_config();
    let primary = config.models.deep.clone();
    let fallback = "z-ai/glm-5.2".to_string();
    config.models.fallback = vec![fallback.clone()];
    config.models.provider.last_resort_unpinned = false;
    config.models.budget_usd_per_pr = 10.0;
    let mut replies = (0..6)
        .map(|_| Reply::error(404, "No endpoints found"))
        .collect::<Vec<_>>();
    replies.extend((0..2).map(|_| gateway_empty_lane_reply(&fallback)));
    let (gateway, release) = FakeGateway::start_paused(replies).await;
    config.models.base_url = gateway.base_url.clone();
    let forge = large_forge();
    let repo = RepoId::parse("tinyhumansai/tinysweeper").expect("repo id");
    let model: Arc<dyn Model> =
        Arc::new(GatewayModel::with_key(&config.models, "fixture-key".into()));
    let run_config = config.clone();
    let task = tokio::spawn(async move {
        let result = review(&forge, model, &run_config, &repo, 7).await;
        result.map(|proposal| (proposal, forge))
    });

    wait_for_gateway_requests(&gateway, 6).await;
    let initial = gateway.requests();
    assert!(
        initial[..6]
            .iter()
            .all(|request| request["model"] == primary)
    );
    release.add_permits(6);
    wait_for_gateway_requests(&gateway, 8).await;
    release.add_permits(2);

    let proposal = tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .expect("the call-limited review finishes after two fallback dispatches")
        .expect("review task joins")
        .expect("partial review is returned");
    let (proposal, forge) = proposal;
    let requests = gateway.requests();
    assert_eq!(
        requests.len(),
        8,
        "fallbacks consume the shared physical limit"
    );
    assert!(
        requests[..6]
            .iter()
            .all(|request| request["model"] == primary)
    );
    assert!(
        requests[6..]
            .iter()
            .all(|request| request["model"] == fallback)
    );
    assert_eq!(proposal.usage().calls_attempted, 8);
    assert!(!proposal.complete());
    assert_eq!(
        proposal
            .partial_review
            .as_ref()
            .and_then(|partial| partial.stop_reason),
        Some(crate::app::review::PartialReviewReason::CallLimit)
    );
    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("the partial fallback-limited proposal is published");
    let writes = forge.writes();
    let check = writes
        .iter()
        .find_map(|write| match write {
            Write::Check(check) | Write::CheckUpdate { check, .. } => Some(check),
            _ => None,
        })
        .expect("the check publishes retained coverage");
    assert_eq!(
        check.conclusion,
        Some(crate::forge::types::CheckConclusion::Neutral)
    );
    assert!(check.summary.contains("not reviewed (call budget)"));
    let hub = writes.iter().find_map(|write| match write {
        Write::Comment { body, .. } | Write::CommentUpdate { body, .. } => Some(body),
        _ => None,
    });
    assert!(hub.is_some_and(|body| body.contains("not reviewed (call budget)")));
    assert!(!writes.iter().any(|write| matches!(
        write,
        Write::Review {
            event: crate::forge::types::ReviewEvent::Approve,
            ..
        } | Write::Merged { .. }
    )));
}

#[tokio::test]
async fn a_partial_large_review_is_published_without_approval_and_keeps_host_gaps() {
    let mut state = MockState::default();
    state.pull_requests.insert(
        7,
        PullRequest {
            number: 7,
            title: "feat: partial review".into(),
            body: "Review two changed files.".into(),
            head_sha: "abc123".into(),
            ..PullRequest::default()
        },
    );
    state
        .files
        .insert(7, vec![changed_file("src/a.rs"), changed_file("src/b.rs")]);
    let forge = MockForge::with_state(state);
    let model: Arc<dyn Model> = Arc::new(MockModel::always(json!({
        "summary": "No finding.",
        "findings": [],
        "executive_summary": "The pull request changes two source files.",
        "changes": "",
        "features": [],
        "tests": [],
        "positive_observations": {}
    })));
    let mut config = config();
    config.grouping.enabled = false;
    config.review.large_pr.files = 1;
    config.review.large_pr.max_groups = 1;
    config.review.large_pr.max_calls = 8;
    config.review.approve_when_clean = true;

    let repo = RepoId::parse("tinyhumansai/tinysweeper").expect("repo id");
    let proposal = review(&forge, model, &config, &repo, 7)
        .await
        .expect("the selected group can be reviewed");
    let encoded = serde_json::to_value(&proposal).expect("proposal serializes");

    assert_eq!(
        encoded["partial_review"]["mode"], "large",
        "the published proposal records host-side partial-review metadata"
    );
    assert_eq!(encoded["partial_review"]["estimate"]["files"], 2);
    assert_eq!(
        encoded["partial_review"]["selected_groups"][0]["paths"],
        json!(["src/a.rs"])
    );
    assert!(
        encoded["partial_review"]["omitted"]
            .as_array()
            .unwrap()
            .iter()
            .any(|omission| omission["path"] == "src/b.rs" && omission["reason"] == "not_selected")
    );
    assert!(proposal.unreviewed.iter().any(|path| path == "src/b.rs"));
    assert!(
        !proposal.complete(),
        "an omitted changed path blocks approval"
    );
    let mut legacy = encoded.clone();
    legacy
        .as_object_mut()
        .expect("proposal is an object")
        .remove("partial_review");
    let decoded: Proposal = serde_json::from_value(legacy).expect("legacy proposal decodes");
    assert!(decoded.partial_review.is_none());

    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("the partial proposal is published");
    let writes = forge.writes();
    assert!(
        !writes.iter().any(|write| matches!(
            write,
            Write::Review {
                event: crate::forge::types::ReviewEvent::Approve,
                ..
            }
        )),
        "publishing partial coverage must never approve"
    );
    assert!(
        writes.iter().any(|write| matches!(write, Write::Check(_))),
        "the partial check remains publishable"
    );
    let hub = writes.iter().find_map(|write| match write {
        Write::Comment { body, .. } | Write::CommentUpdate { body, .. } => Some(body),
        _ => None,
    });
    let hub = hub.expect("partial review hub is published");
    assert!(hub.contains("not reviewed (large PR)"), "{hub}");
    assert!(hub.contains("src/b.rs"), "{hub}");
    assert!(
        hub.contains("not selected by the large-review budget"),
        "{hub}"
    );
}
