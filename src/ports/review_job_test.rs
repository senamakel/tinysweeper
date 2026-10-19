//! Offline contract tests for admission, recovery ownership, and terminal dedupe.

use super::super::review_job_mock::MockReviewJobStore;
use super::{
    Admission, MAX_RUNNING_REVIEWS, MAX_TERMINAL_REVIEW_RESERVATIONS, MAX_UNFINISHED_REVIEWS,
    REVIEW_OWNER_TTL_MS, REVIEW_TOMBSTONE_TTL_MS, ReviewJobId, ReviewJobMode, ReviewJobStore,
    ReviewRequest, ReviewSchedulerState, ReviewTombstone, TerminalOutcome,
};

fn request(id: &str, accepted_at_ms: i64) -> ReviewRequest {
    ReviewRequest {
        id: ReviewJobId(id.to_owned()),
        repo: "owner/repo".into(),
        number: 7,
        author: "contributor".into(),
        installation: 1,
        head_sha: Some("sha".into()),
        delivery: Some(id.to_owned()),
        event: "pull_request".into(),
        mode: ReviewJobMode::Incremental,
        accepted_at_ms,
    }
}

#[tokio::test]
async fn accepted_jobs_recover_after_wakeup_loss_and_completed_jobs_stay_done() {
    let store = MockReviewJobStore::default();
    assert_eq!(
        store
            .admit_batch(vec![request("delivery-a", 10)])
            .await
            .unwrap(),
        Admission::Admitted
    );
    // A fresh worker has no channel state; it claims directly from the durable
    // scheduler record, the same path used by startup recovery and polling.
    let recovered = store
        .claim_next("process-a", 11)
        .await
        .unwrap()
        .expect("accepted work survives a lost wakeup");
    assert!(
        store
            .finish(&recovered, TerminalOutcome::Published, 12, 12)
            .await
            .unwrap()
    );
    assert!(store.claim_next("process-b", 13).await.unwrap().is_none());
    assert_eq!(
        store
            .admit_batch(vec![request("delivery-a", 14)])
            .await
            .unwrap(),
        Admission::Duplicate
    );
}

#[tokio::test]
async fn whole_manual_batch_is_rejected_without_partial_admission() {
    let store = MockReviewJobStore::default();
    let full = (0..MAX_UNFINISHED_REVIEWS)
        .map(|index| request(&format!("job-{index}"), 1))
        .collect::<Vec<_>>();
    assert_eq!(store.admit_batch(full).await.unwrap(), Admission::Admitted);
    assert_eq!(
        store
            .admit_batch(vec![request("manual-a", 2), request("manual-b", 2)])
            .await
            .unwrap(),
        Admission::Full
    );
    assert_eq!(store.unfinished(), MAX_UNFINISHED_REVIEWS);
}

#[tokio::test]
async fn expired_owner_is_recovered_but_live_owner_and_stale_generation_are_fenced() {
    let store = MockReviewJobStore::default();
    store
        .admit_batch(vec![request("delivery-a", 1)])
        .await
        .unwrap();
    let first = store.claim_next("process-a", 2).await.unwrap().unwrap();
    assert!(store.claim_next("process-b", 3).await.unwrap().is_none());
    let second = store
        .claim_next("process-b", 2 + REVIEW_OWNER_TTL_MS)
        .await
        .unwrap()
        .unwrap();
    assert!(second.generation > first.generation);
    assert!(
        !store
            .finish(&first, TerminalOutcome::Published, 40_000, 40_000)
            .await
            .unwrap()
    );
    assert!(
        store
            .defer(&second, 40_001, 50_000)
            .await
            .expect("the current generation may defer")
    );
    assert_eq!(store.unfinished(), 1);
}

#[tokio::test]
async fn live_lease_contention_defers_without_converting_it_to_a_success() {
    let store = MockReviewJobStore::default();
    store
        .admit_batch(vec![request("delivery-a", 1)])
        .await
        .unwrap();
    let claimed = store.claim_next("process-a", 2).await.unwrap().unwrap();
    assert!(store.defer(&claimed, 3, 10_000).await.unwrap());
    assert!(
        store
            .claim_next("process-b", 9_999)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .claim_next("process-b", 10_000)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn running_claims_are_bounded_across_process_owners() {
    let store = MockReviewJobStore::default();
    let jobs = (0..=MAX_RUNNING_REVIEWS)
        .map(|index| request(&format!("delivery-{index}"), 1))
        .collect();
    assert_eq!(store.admit_batch(jobs).await.unwrap(), Admission::Admitted);
    for index in 0..MAX_RUNNING_REVIEWS {
        assert!(
            store
                .claim_next(&format!("process-{index}"), 2)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        store
            .claim_next("process-overflow", 3)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn only_a_live_generation_can_renew_or_finish() {
    let store = MockReviewJobStore::default();
    store
        .admit_batch(vec![request("delivery-a", 1)])
        .await
        .unwrap();
    let first = store.claim_next("process-a", 2).await.unwrap().unwrap();
    assert!(store.renew(&first, 10_000).await.unwrap());
    assert!(store.owns(&first, 10_001).await.unwrap());
    assert!(
        !store
            .owns(&first, 10_000 + REVIEW_OWNER_TTL_MS)
            .await
            .unwrap()
    );
    assert!(
        !store
            .renew(&first, 10_000 + REVIEW_OWNER_TTL_MS)
            .await
            .unwrap()
    );
    let recovered = store
        .claim_next("process-b", 10_000 + REVIEW_OWNER_TTL_MS)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !store
            .finish(
                &first,
                TerminalOutcome::Published,
                10_000 + REVIEW_OWNER_TTL_MS,
                50_000,
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .owns(&recovered, 10_001 + REVIEW_OWNER_TTL_MS)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn terminal_deadlines_remain_deduped_for_seven_days() {
    let store = MockReviewJobStore::default();
    store
        .admit_batch(vec![request("delivery-a", 1)])
        .await
        .unwrap();
    let claimed = store.claim_next("process-a", 2).await.unwrap().unwrap();
    store
        .finish(&claimed, TerminalOutcome::Exhausted, 3, 3)
        .await
        .unwrap();
    assert_eq!(
        store
            .admit_batch(vec![request("delivery-a", 4)])
            .await
            .unwrap(),
        Admission::Duplicate
    );
    assert_eq!(
        store
            .admit_batch(vec![request("delivery-a", 3 + REVIEW_TOMBSTONE_TTL_MS + 1)])
            .await
            .unwrap(),
        Admission::Admitted
    );
}

#[tokio::test]
async fn failed_batch_persistence_admits_no_jobs() {
    let store = MockReviewJobStore::default();
    store.fail_next_admission();
    assert!(
        store
            .admit_batch(vec![request("manual-a", 1), request("manual-b", 1)])
            .await
            .is_err()
    );
    assert_eq!(store.unfinished(), 0);
    assert_eq!(
        store
            .admit_batch(vec![request("manual-a", 2), request("manual-b", 2)])
            .await
            .unwrap(),
        Admission::Admitted
    );
}

#[tokio::test]
async fn tombstone_reservations_backpressure_without_evicting_live_dedupe_ids() {
    let store = MockReviewJobStore::default();
    let state = ReviewSchedulerState {
        terminal: (0..MAX_TERMINAL_REVIEW_RESERVATIONS)
            .map(|index| ReviewTombstone {
                id: ReviewJobId(format!("done-{index:05}-{}", "x".repeat(260))),
                outcome: TerminalOutcome::Exhausted,
                expires_at_ms: REVIEW_TOMBSTONE_TTL_MS * 2,
            })
            .collect(),
        ..ReviewSchedulerState::default()
    };
    store.replace_state_for_test(state);
    assert_eq!(
        store
            .admit_batch(vec![request("new-work", 10)])
            .await
            .unwrap(),
        Admission::Full
    );
    assert_eq!(store.unfinished(), 0);
    let state = store.snapshot_for_test();
    assert_eq!(state.terminal.len(), MAX_TERMINAL_REVIEW_RESERVATIONS);
    assert!(state.unfinished.is_empty());
}
