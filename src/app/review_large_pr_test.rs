use super::*;

#[tokio::test]
async fn a_partial_large_review_is_published_without_approval_and_keeps_host_gaps() {
    use crate::ports::forge::ForgeRead;

    let files = vec![
        changed_file("src/a.rs", "@@ -0,0 +1,1 @@\\n+fn a() {}\\n"),
        changed_file("src/b.rs", "@@ -0,0 +1,1 @@\\n+fn b() {}\\n"),
    ];
    let forge = forge_with(files, vec![]);
    let model = MockModel::always(json!({ "summary": "No finding.", "findings": [] }));
    let mut config = critique_config();
    config.grouping.enabled = false;
    config.review.large_pr.files = 1;
    config.review.large_pr.max_groups = 1;
    config.review.large_pr.max_calls = 8;
    config.review.lanes = vec!["critique".into()];
    config.approve_when_clean = true;

    let proposal = review(&forge, Arc::new(model), &config, &repo(), 7)
        .await
        .expect("the selected group can be reviewed");
    let encoded = serde_json::to_value(&proposal).expect("proposal serializes");

    assert_eq!(
        encoded["partial_review"]["mode"],
        "large",
        "the published proposal records host-side partial-review metadata"
    );
    assert!(proposal.unreviewed.iter().any(|path| path == "src/b.rs"));
    assert!(!proposal.complete(), "an omitted changed path blocks approval");

    crate::app::apply::apply(&forge, &forge, &config, &proposal, None)
        .await
        .expect("the partial proposal is published");
    let writes = forge.writes();
    assert!(
        !writes.iter().any(|write| matches!(
            write,
            crate::forge::Write::Review { event: crate::forge::types::ReviewEvent::Approve, .. }
        )),
        "publishing partial coverage must never approve"
    );
    assert!(
        writes.iter().any(|write| matches!(write, crate::forge::Write::Check(_))),
        "the partial check remains publishable"
    );
}

