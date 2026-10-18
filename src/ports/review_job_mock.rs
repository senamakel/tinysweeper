//! Always-compiled offline implementation of the durable review-job port.
//!
//! The mock uses the same scheduler state transitions as production while
//! replacing MongoDB persistence with an in-memory mutex. It never performs
//! network I/O and is available to downstream crates as well as unit tests.

use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::ports::review_job::{
    Admission, MAX_RUNNING_REVIEWS, MAX_TERMINAL_REVIEW_RESERVATIONS, MAX_UNFINISHED_REVIEWS,
    OwnedReview, PaidStart, ReviewJobStore, ReviewRequest, ReviewSchedulerState, TerminalOutcome,
};

/// In-memory implementation of [`ReviewJobStore`] for offline use and tests.
#[derive(Default)]
pub struct MockReviewJobStore {
    state: Mutex<ReviewSchedulerState>,
    fail_admission: Mutex<bool>,
}

impl MockReviewJobStore {
    /// Make the next whole-batch admission fail with a simulated store error.
    pub fn fail_next_admission(&self) {
        *self.fail_admission.lock().expect("admission failure") = true;
    }

    /// Return the number of pending or currently owned requests.
    pub fn unfinished(&self) -> usize {
        self.state.lock().expect("state").unfinished.len()
    }
}

#[async_trait::async_trait]
impl ReviewJobStore for MockReviewJobStore {
    async fn has_capacity_for(&self, count: usize) -> Result<bool> {
        let state = self.state.lock().expect("state");
        Ok(count > 0
            && state.unfinished.len() + count <= MAX_UNFINISHED_REVIEWS
            && state.terminal.len() + state.unfinished.len() + count
                <= MAX_TERMINAL_REVIEW_RESERVATIONS)
    }

    async fn admit_batch(&self, requests: Vec<ReviewRequest>) -> Result<Admission> {
        if std::mem::take(&mut *self.fail_admission.lock().expect("admission failure")) {
            return Err(Error::Forge("simulated scheduler write failure".into()));
        }
        let now_ms = requests
            .iter()
            .map(|request| request.accepted_at_ms)
            .max()
            .unwrap_or_default();
        Ok(self
            .state
            .lock()
            .expect("state")
            .admit_batch(requests, now_ms))
    }

    async fn claim_next(&self, owner: &str, now_ms: i64) -> Result<Option<OwnedReview>> {
        Ok(self.state.lock().expect("state").claim_next(owner, now_ms))
    }

    async fn begin_paid(&self, owned: &OwnedReview, now_ms: i64) -> Result<PaidStart> {
        Ok(self.state.lock().expect("state").begin_paid(owned, now_ms))
    }

    async fn renew(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool> {
        Ok(self.state.lock().expect("state").renew(owned, now_ms))
    }

    async fn owns(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool> {
        Ok(self.state.lock().expect("state").owns(owned, now_ms))
    }

    async fn defer(&self, owned: &OwnedReview, now_ms: i64, not_before_ms: i64) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .expect("state")
            .defer(owned, now_ms, not_before_ms))
    }

    async fn finish(
        &self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        now_ms: i64,
        completed_at_ms: i64,
    ) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .expect("state")
            .finish(owned, outcome, now_ms, completed_at_ms))
    }
}
