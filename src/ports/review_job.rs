//! Durable admission and ownership for server review work.
//!
//! The server uses this port as the source of truth for accepted work. Wakeup
//! channels are hints only: a process can stop after persisting a request and
//! before sending its hint, so workers also poll this bounded journal.

use crate::error::Result;

/// Maximum accepted requests waiting or running across all server processes.
pub const MAX_UNFINISHED_REVIEWS: usize = 260;
/// Maximum reviews that may be running across all server processes.
pub const MAX_RUNNING_REVIEWS: usize = 4;
/// How long a job owner remains valid without a heartbeat.
pub const REVIEW_OWNER_TTL_MS: i64 = 45_000;
/// How long terminal delivery IDs remain deduped.
pub const REVIEW_TOMBSTONE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Stable identity for one accepted review request.
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

/// Minimal request metadata needed to resume an accepted review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRequest {
    /// Stable webhook delivery ID or generated manual-review ID.
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
    /// Webhook event type or `manual-review`.
    pub event: String,
    /// Review mode.
    pub mode: ReviewJobMode,
    /// Unix time in milliseconds when the server accepted this work.
    pub accepted_at_ms: i64,
}

/// Atomic admission result for one webhook or an entire manual expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Every request in the batch is durable and may be acknowledged.
    Admitted,
    /// Every request was already known; no duplicate work was added.
    Duplicate,
    /// The bounded unfinished or terminal reservation budget is full.
    Full,
}

/// A request claimed by one server process and fenced by a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedReview {
    /// The accepted request metadata.
    pub request: ReviewRequest,
    /// Random process owner identity.
    pub owner: String,
    /// Monotonic generation for this job's ownership.
    pub generation: u64,
}

/// Terminal result retained as a dedupe tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// Review was published or reconciled as already published.
    Published,
    /// Trust or live eligibility policy declined the review.
    Declined,
    /// The queued revision was superseded before review.
    Superseded,
    /// A bounded review budget or retry policy ended the request.
    Exhausted,
}

/// Atomic journal for accepted server reviews.
#[async_trait::async_trait]
pub trait ReviewJobStore: Send + Sync {
    /// Atomically admit all requests or none, deduping against unfinished and
    /// unexpired terminal IDs in the same scheduler document.
    async fn admit_batch(&self, requests: Vec<ReviewRequest>) -> Result<Admission>;

    /// Claim one eligible request if fewer than four are running globally.
    /// The implementation must never take an unexpired foreign owner.
    async fn claim_next(&self, owner: &str, now_ms: i64) -> Result<Option<OwnedReview>>;

    /// Extend a live claim. A stale generation can never renew another
    /// process's job.
    async fn renew(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Verify the claim is still current and unexpired before paid work or
    /// publication.
    async fn owns(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Return an owned request to pending state, optionally with backoff.
    /// The owner and generation must fence this update.
    async fn defer(&self, owned: &OwnedReview, not_before_ms: i64) -> Result<bool>;

    /// Finish an owned request and retain a bounded dedupe tombstone.
    /// The owner and generation must fence this update.
    async fn finish(
        &self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        completed_at_ms: i64,
    ) -> Result<bool>;
}

#[cfg(test)]
#[path = "review_job_test.rs"]
mod tests;
