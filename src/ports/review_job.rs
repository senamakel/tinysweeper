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
/// Upper bound for any persisted identifier or descriptive field.
pub const REVIEW_JOB_FIELD_LIMIT: usize = 300;

/// Stable identity for one accepted review request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ReviewJobId(pub String);

/// Whether a recovered review should reuse incremental state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewJobMode {
    /// Reuse prior evidence and finding fingerprints.
    Incremental,
    /// Run a full review that ignores prior state.
    Full,
}

/// Minimal request metadata needed to resume an accepted review.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// One unfinished scheduler record and its fenced owner, if running.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScheduledReview {
    /// Accepted request metadata.
    pub request: ReviewRequest,
    /// Owner identity, absent while pending.
    pub owner: Option<String>,
    /// Ownership generation, increased on every claim.
    pub generation: u64,
    /// Owner lease expiry in Unix milliseconds.
    pub owner_until_ms: i64,
    /// Earliest retry time in Unix milliseconds.
    pub not_before_ms: i64,
    /// Failures observed across process restarts.
    pub attempts: u32,
}

/// A completed ID retained to dedupe redeliveries for seven days.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReviewTombstone {
    /// Original request ID.
    pub id: ReviewJobId,
    /// Durable terminal outcome.
    pub outcome: TerminalOutcome,
    /// Unix millisecond expiration time.
    pub expires_at_ms: i64,
}

/// Whole single-document Mongo scheduler state, updated by revision CAS.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReviewSchedulerState {
    /// Monotonic revision used for compare-and-swap writes.
    pub revision: u64,
    /// Pending and running work. This list is never TTL-expired.
    pub unfinished: Vec<ScheduledReview>,
    /// Bounded, expiring delivery dedupe records.
    pub terminal: Vec<ReviewTombstone>,
}

impl ReviewSchedulerState {
    /// Atomically admit a whole batch in memory before the Mongo CAS persists it.
    pub fn admit_batch(&mut self, requests: Vec<ReviewRequest>, now_ms: i64) -> Admission {
        if requests.is_empty() {
            return Admission::Duplicate;
        }
        self.terminal.retain(|record| record.expires_at_ms > now_ms);
        let mut incoming = std::collections::HashSet::new();
        if requests.iter().any(|request| {
            !incoming.insert(request.id.clone()) || !metadata_is_bounded(request)
        }) {
            return Admission::Full;
        }
        let already = requests
            .iter()
            .filter(|request| {
                self.unfinished
                    .iter()
                    .any(|record| record.request.id == request.id)
                    || self.terminal.iter().any(|record| record.id == request.id)
            })
            .count();
        if already == requests.len() {
            return Admission::Duplicate;
        }
        if already != 0
            || self.unfinished.len() + requests.len() > MAX_UNFINISHED_REVIEWS
            || self.terminal.len() + self.unfinished.len() + requests.len() > 1_000
        {
            return Admission::Full;
        }
        self.unfinished.extend(requests.into_iter().map(|request| ScheduledReview {
            request,
            owner: None,
            generation: 0,
            owner_until_ms: 0,
            not_before_ms: 0,
            attempts: 0,
        }));
        Admission::Admitted
    }

    /// Claim the oldest eligible record within the four-process global bound.
    pub fn claim_next(&mut self, owner: &str, now_ms: i64) -> Option<OwnedReview> {
        let running = self
            .unfinished
            .iter()
            .filter(|record| record.owner.is_some() && record.owner_until_ms > now_ms)
            .count();
        if running >= MAX_RUNNING_REVIEWS {
            return None;
        }
        let record = self.unfinished.iter_mut().find(|record| {
            record.not_before_ms <= now_ms
                && (record.owner.is_none() || record.owner_until_ms <= now_ms)
        })?;
        record.generation += 1;
        record.owner = Some(owner.to_owned());
        record.owner_until_ms = now_ms + REVIEW_OWNER_TTL_MS;
        record.attempts = record.attempts.saturating_add(1);
        Some(OwnedReview {
            request: record.request.clone(),
            owner: owner.to_owned(),
            generation: record.generation,
        })
    }

    /// Extend the current unexpired owner's lease.
    pub fn renew(&mut self, owned: &OwnedReview, now_ms: i64) -> bool {
        let Some(record) = self.unfinished.iter_mut().find(|record| owns(record, owned)) else {
            return false;
        };
        if record.owner_until_ms <= now_ms {
            return false;
        }
        record.owner_until_ms = now_ms + REVIEW_OWNER_TTL_MS;
        true
    }

    /// Check the current unexpired claim before paid work or publication.
    pub fn owns(&self, owned: &OwnedReview, now_ms: i64) -> bool {
        self.unfinished
            .iter()
            .find(|record| owns(record, owned))
            .is_some_and(|record| record.owner_until_ms > now_ms)
    }

    /// Return the current owner's request to pending with bounded backoff.
    pub fn defer(&mut self, owned: &OwnedReview, now_ms: i64, not_before_ms: i64) -> bool {
        let Some(record) = self.unfinished.iter_mut().find(|record| owns(record, owned)) else {
            return false;
        };
        if record.owner_until_ms <= now_ms {
            return false;
        }
        record.owner = None;
        record.owner_until_ms = 0;
        record.not_before_ms = not_before_ms;
        true
    }

    /// Complete the current owner's request and reserve its dedupe tombstone.
    pub fn finish(
        &mut self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        now_ms: i64,
        completed_at_ms: i64,
    ) -> bool {
        let Some(index) = self
            .unfinished
            .iter()
            .position(|record| owns(record, owned) && record.owner_until_ms > now_ms)
        else {
            return false;
        };
        let record = self.unfinished.remove(index);
        self.terminal.push(ReviewTombstone {
            id: record.request.id,
            outcome,
            expires_at_ms: completed_at_ms + REVIEW_TOMBSTONE_TTL_MS,
        });
        true
    }
}

fn metadata_is_bounded(request: &ReviewRequest) -> bool {
    request.id.0.len() <= REVIEW_JOB_FIELD_LIMIT
        && request.repo.len() <= REVIEW_JOB_FIELD_LIMIT
        && request.author.len() <= REVIEW_JOB_FIELD_LIMIT
        && request.head_sha.as_ref().is_none_or(|value| value.len() <= REVIEW_JOB_FIELD_LIMIT)
        && request.delivery.as_ref().is_none_or(|value| value.len() <= REVIEW_JOB_FIELD_LIMIT)
        && request.event.len() <= REVIEW_JOB_FIELD_LIMIT
}

fn owns(record: &ScheduledReview, owned: &OwnedReview) -> bool {
    record.request.id == owned.request.id
        && record.owner.as_deref() == Some(owned.owner.as_str())
        && record.generation == owned.generation
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
    async fn defer(&self, owned: &OwnedReview, now_ms: i64, not_before_ms: i64) -> Result<bool>;

    /// Finish an owned request and retain a bounded dedupe tombstone.
    /// The owner and generation must fence this update.
    async fn finish(
        &self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        now_ms: i64,
        completed_at_ms: i64,
    ) -> Result<bool>;
}

#[cfg(test)]
#[path = "review_job_test.rs"]
pub(crate) mod tests;
