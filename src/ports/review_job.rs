//! Durable metadata for accepted server review work.
//!
//! This port stores only the review request fields needed to resume a queued
//! worker after process shutdown. It never stores webhook bodies, comments,
//! pull-request text, or credentials.

use crate::error::Result;

/// Stable identity for one accepted review.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReviewJobId(pub String);

/// Whether a recovered review should reuse incremental state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewJobMode {
    /// Reuse prior evidence and finding fingerprints.
    Incremental,
    /// Run a full review that ignores prior state.
    Full,
}

/// One review request accepted by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewJob {
    /// Stable ID: the webhook delivery for webhook jobs, a generated ID for
    /// each job in a manual batch.
    pub id: ReviewJobId,
    /// Repository in owner/name form.
    pub repo: String,
    /// Pull request number.
    pub number: u64,
    /// Contributor login used by trust policy.
    pub author: String,
    /// GitHub App installation ID.
    pub installation: u64,
    /// Revision carried by the request, when known.
    pub head_sha: Option<String>,
    /// Webhook delivery ID, absent for manual jobs.
    pub delivery: Option<String>,
    /// Webhook event type or manual-review.
    pub event: String,
    /// Review mode.
    pub mode: ReviewJobMode,
    /// Unix time in milliseconds when the server accepted the work.
    pub accepted_at_ms: i64,
}

/// Persistence seam for the bounded server review queue.
#[allow(async_fn_in_trait)]
pub trait ReviewJobStore: Send + Sync {
    /// Persist one webhook review before acknowledging its delivery.
    ///
    /// Returns false when this delivery already has a durable queue record.
    async fn enqueue(&self, job: ReviewJob) -> Result<bool>;

    /// Persist a manual expansion as one atomic batch before accepting it.
    async fn enqueue_manual_batch(&self, batch_id: &str, jobs: Vec<ReviewJob>) -> Result<()>;

    /// Load at most limit unfinished records in acceptance order.
    async fn recover(&self, limit: usize) -> Result<Vec<ReviewJob>>;

    /// Mark a record as running. A failed update does not remove the record.
    async fn mark_running(&self, id: &ReviewJobId) -> Result<()>;

    /// Leave a busy or shutdown-deferred job available to retry.
    async fn mark_pending(&self, id: &ReviewJobId) -> Result<()>;

    /// Mark a terminal review complete so restart recovery does not replay it.
    async fn complete(&self, id: &ReviewJobId) -> Result<()>;

    /// Release only the lease owned by this durable job after a process restart.
    async fn release_stale_lease(&self, id: &ReviewJobId) -> Result<()>;
}

#[cfg(test)]
#[path = "review_job_test.rs"]
mod tests;
