use crate::app::review::review;
use crate::config::types::Config;
use crate::forge::mock::{MockForge, MockState, Write};
use crate::forge::types::{ChangedFile, FileStatus, PullRequest, RepoId};
use crate::harness::mock::MockModel;
use crate::ports::model::Model;
use serde_json::json;
use std::sync::Arc;

fn config() -> Config {
    let mut config: Config = crate::config::DEFAULTS
        .parse::<toml::Table>()
        .expect("default config parses")
        .try_into()
        .expect("default config converts");
    config.review.lanes = vec!["critique".into()];
    config.summary.enabled = false;
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
        "findings": []
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
    assert!(proposal.unreviewed.iter().any(|path| path == "src/b.rs"));
    assert!(
        !proposal.complete(),
        "an omitted changed path blocks approval"
    );

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
}
