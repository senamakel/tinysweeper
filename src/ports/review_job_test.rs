//! Offline contract tests for admission, recovery ownership, and terminal dedupe.

use std::sync::Mutex;

use super::{
    Admission, OwnedReview, ReviewJobId, ReviewJobMode, ReviewJobStore, ReviewRequest,
    TerminalOutcome, MAX_RUNNING_REVIEWS, MAX_UNFINISHED_REVIEWS, REVIEW_OWNER_TTL_MS,
    REVIEW_TOMBSTONE_TTL_MS,
};
use crate::error::{Error, Result};

const MAX_TERMINAL: usize = 1_000;

#[derive(Clone)]
struct Entry {
    request: ReviewRequest,
    owner: Option<String>,
    generation: u64,
    owner_until_ms: i64,
    not_before_ms: i64,
    terminal: Option<(TerminalOutcome, i64)>,
}

#[derive(Default)]
pub(crate) struct MockReviewJobStore {
    entries: Mutex<Vec<Entry>>,
    fail_admission: Mutex<bool>,
}

impl MockReviewJobStore {
    pub(crate) fn fail_next_admission(&self) {
        *self.fail_admission.lock().expect("admission failure") = true;
    }

    pub(crate) fn unfinished(&self) -> usize {
        self.entries
            .lock()
            .expect("entries")
            .iter()
            .filter(|entry| entry.terminal.is_none())
            .count()
    }
}

#[async_trait::async_trait]
impl ReviewJobStore for MockReviewJobStore {
    async fn admit_batch(&self, requests: Vec<ReviewRequest>) -> Result<Admission> {
        if std::mem::take(&mut *self.fail_admission.lock().expect("admission failure")) {
            return Err(Error::Forge("simulated scheduler write failure".into()));
        }
        if requests.is_empty() {
            return Ok(Admission::Duplicate);
        }
        let mut entries = self.entries.lock().expect("entries");
        entries.retain(|entry| {
            entry
                .terminal
                .is_none_or(|(_, until)| until > requests[0].accepted_at_ms)
        });
        let mut ids = std::collections::HashSet::new();
        if requests.iter().any(|request| !ids.insert(request.id.clone())) {
            return Err(Error::Forge("duplicate ID in review batch".into()));
        }
        let already = requests
            .iter()
            .filter(|request| entries.iter().any(|entry| entry.request.id == request.id))
            .count();
        if already == requests.len() {
            return Ok(Admission::Duplicate);
        }
        if already != 0
            || entries.iter().filter(|entry| entry.terminal.is_none()).count()
                + requests.len()
                > MAX_UNFINISHED_REVIEWS
            || entries.iter().filter(|entry| entry.terminal.is_some()).count() + requests.len()
                > MAX_TERMINAL
        {
            return Ok(Admission::Full);
        }
        entries.extend(requests.into_iter().map(|request| Entry {
            request,
            owner: None,
            generation: 0,
            owner_until_ms: 0,
            not_before_ms: 0,
            terminal: None,
        }));
        Ok(Admission::Admitted)
    }

    async fn claim_next(&self, owner: &str, now_ms: i64) -> Result<Option<OwnedReview>> {
        let mut entries = self.entries.lock().expect("entries");
        let running = entries
            .iter()
            .filter(|entry| entry.terminal.is_none() && entry.owner.is_some())
            .filter(|entry| entry.owner_until_ms > now_ms)
            .count();
        if running >= MAX_RUNNING_REVIEWS {
            return Ok(None);
        }
        let Some(entry) = entries.iter_mut().find(|entry| {
            entry.terminal.is_none()
                && entry.not_before_ms <= now_ms
                && entry.owner_until_ms <= now_ms
        }) else {
            return Ok(None);
        };
        entry.generation += 1;
        entry.owner = Some(owner.to_owned());
        entry.owner_until_ms = now_ms + REVIEW_OWNER_TTL_MS;
        Ok(Some(OwnedReview {
            request: entry.request.clone(),
            owner: owner.to_owned(),
            generation: entry.generation,
        }))
    }

    async fn renew(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool> {
        let mut entries = self.entries.lock().expect("entries");
        let Some(entry) = entries.iter_mut().find(|entry| owns(entry, owned)) else {
            return Ok(false);
        };
        entry.owner_until_ms = now_ms + REVIEW_OWNER_TTL_MS;
        Ok(true)
    }

    async fn owns(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool> {
        let entries = self.entries.lock().expect("entries");
        Ok(entries
            .iter()
            .find(|entry| owns(entry, owned))
            .is_some_and(|entry| entry.owner_until_ms > now_ms))
    }

    async fn defer(&self, owned: &OwnedReview, not_before_ms: i64) -> Result<bool> {
        let mut entries = self.entries.lock().expect("entries");
        let Some(entry) = entries.iter_mut().find(|entry| owns(entry, owned)) else {
            return Ok(false);
        };
        entry.owner = None;
        entry.owner_until_ms = 0;
        entry.not_before_ms = not_before_ms;
        Ok(true)
    }

    async fn finish(
        &self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        completed_at_ms: i64,
    ) -> Result<bool> {
        let mut entries = self.entries.lock().expect("entries");
        let Some(entry) = entries.iter_mut().find(|entry| owns(entry, owned)) else {
            return Ok(false);
        };
        entry.owner = None;
        entry.owner_until_ms = 0;
        entry.terminal = Some((outcome, completed_at_ms + TOMBSTONE_TTL_MS));
        Ok(true)
    }
}

fn owns(entry: &Entry, owned: &OwnedReview) -> bool {
    entry.terminal.is_none()
        && entry.request.id == owned.request.id
        && entry.owner.as_deref() == Some(&owned.owner)
        && entry.generation == owned.generation
}

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
        store.admit_batch(vec![request("delivery-a", 10)]).await.unwrap(),
        Admission::Admitted
    );
    // A fresh worker has no channel state; it claims directly from the durable
    // scheduler record, the same path used by startup recovery and polling.
    let recovered = store
        .claim_next("process-a", 11)
        .await
        .unwrap()
        .expect("accepted work survives a lost wakeup");
    assert!(store
        .finish(&recovered, TerminalOutcome::Published, 12)
        .await
        .unwrap());
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
    let mut full = (0..MAX_UNFINISHED)
        .map(|index| request(&format!("job-{index}"), 1))
        .collect::<Vec<_>>();
    assert_eq!(
        store.admit_batch(std::mem::take(&mut full)).await.unwrap(),
        Admission::Admitted
    );
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
    store.admit_batch(vec![request("delivery-a", 1)]).await.unwrap();
    let first = store
        .claim_next("process-a", 2)
        .await
        .unwrap()
        .unwrap();
    assert!(store.claim_next("process-b", 3).await.unwrap().is_none());
    let second = store
        .claim_next("process-b", 2 + REVIEW_OWNER_TTL_MS)
        .await
        .unwrap()
        .unwrap();
    assert!(second.generation > first.generation);
    assert!(!store
        .finish(&first, TerminalOutcome::Published, 40_000)
        .await
        .unwrap());
    assert!(store
        .defer(&second, 50_000)
        .await
        .expect("the current generation may defer"));
    assert_eq!(store.unfinished(), 1);
}

#[tokio::test]
async fn live_lease_contention_defers_without_converting_it_to_a_success() {
    let store = MockReviewJobStore::default();
    store.admit_batch(vec![request("delivery-a", 1)]).await.unwrap();
    let claimed = store.claim_next("process-a", 2).await.unwrap().unwrap();
    assert!(store.defer(&claimed, 10_000).await.unwrap());
    assert!(store
        .claim_next("process-b", 9_999)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .claim_next("process-b", 10_000)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn terminal_deadlines_remain_deduped_for_seven_days() {
    let store = MockReviewJobStore::default();
    store.admit_batch(vec![request("delivery-a", 1)]).await.unwrap();
    let claimed = store.claim_next("process-a", 2).await.unwrap().unwrap();
    store
        .finish(&claimed, TerminalOutcome::Exhausted, 3)
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
            .admit_batch(vec![request(
                "delivery-a",
                3 + REVIEW_TOMBSTONE_TTL_MS + 1
            )])
            .await
            .unwrap(),
        Admission::Admitted
    );
}

#[tokio::test]
async fn failed_batch_persistence_admits_no_jobs() {
    let store = MockReviewJobStore::default();
    store.fail_next_admission();
    assert!(store
        .admit_batch(vec![request("manual-a", 1), request("manual-b", 1)])
        .await
        .is_err());
    assert_eq!(store.unfinished(), 0);
    assert_eq!(
        store.admit_batch(vec![request("manual-a", 2), request("manual-b", 2)]).await.unwrap(),
        Admission::Admitted
    );
}
