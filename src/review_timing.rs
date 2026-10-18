//! Per-review telemetry shared by the server and the read-only review pipeline.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::Instrument;
use tracing::Span;

use crate::ports::model::Usage;

/// Stable phase keys included in every terminal timing record.
pub(crate) const PHASES: &[&str] = &[
    "permit",
    "open_status",
    "checkout",
    "context",
    "knowledge",
    "retrieval",
    "graph",
    "lanes",
    "summary",
    "threads",
    "wireframe",
    "publish",
];

/// Classify a review error for timing and operator dashboards.
pub(crate) fn outcome_for_error(error: &crate::error::Error) -> &'static str {
    if matches!(error, crate::error::Error::Timeout { .. }) {
        "deadline"
    } else {
        "failure"
    }
}

#[derive(Debug, Clone)]
/// Shared, cancellation-safe telemetry for a single review worker.
pub(crate) struct ReviewTiming(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    record: Mutex<Record>,
    worker_span: Span,
}

/// Snapshot of the server's structured telemetry for one review run.
#[derive(Debug, Clone, Default)]
pub(crate) struct Record {
    /// GitHub repository slug.
    pub(crate) repo: String,
    /// Pull-request number.
    pub(crate) pr: u64,
    /// Commit SHA being reviewed, when known.
    pub(crate) head_sha: String,
    /// Review mode selected by the server.
    pub(crate) mode: String,
    /// Terminal outcome, defaulting to `cancelled` until explicitly finished.
    pub(crate) outcome: String,
    /// Worker start instant used to derive total wall time.
    pub(crate) started: Option<Instant>,
    /// Time spent waiting for a review permit.
    pub(crate) queue_wait_ms: u64,
    /// Accumulated duration per top-level phase.
    pub(crate) phases_ms: BTreeMap<String, u64>,
    /// Accumulated duration per review lane.
    pub(crate) lanes_ms: BTreeMap<String, u64>,
    /// Physical model attempts, plus one for pre-dispatch refusals.
    pub(crate) calls_attempted: u64,
    /// Provider calls returning a response, including truncated or invalid output.
    pub(crate) calls_succeeded: u64,
    /// Model requests refused by admission or the provider.
    pub(crate) calls_refused: u64,
    /// Model attempts that failed without a refusal.
    pub(crate) calls_errored: u64,
    /// Aggregated tokens and cost retained by model adapters.
    pub(crate) usage: Usage,
    /// Files changed in the pull request.
    pub(crate) files_total: usize,
    /// Files without any known unanswered coverage.
    pub(crate) files_answered: usize,
    /// Files omitted or unanswered by review lanes.
    pub(crate) files_unanswered: usize,
}

impl ReviewTiming {
    /// Start a timing record for the repository, PR, and review mode.
    pub(crate) fn new(repo: impl Into<String>, pr: u64, mode: impl Into<String>) -> Self {
        let mut record = Record {
            repo: repo.into(),
            pr,
            mode: mode.into(),
            outcome: "cancelled".into(),
            started: Some(Instant::now()),
            ..Record::default()
        };
        for phase in PHASES {
            record.phases_ms.insert((*phase).into(), 0);
        }
        Self(Arc::new(Inner {
            record: Mutex::new(record),
            worker_span: tracing::Span::current(),
        }))
    }

    /// Measure a top-level phase and attach correlation fields.
    pub(crate) fn phase(&self, name: &'static str) -> PhaseGuard {
        let record = self.snapshot();
        PhaseGuard {
            timing: self.clone(),
            name,
            lane: None,
            started: Instant::now(),
            span: tracing::info_span!(
                "review.phase",
                repo = %record.repo,
                pr = record.pr,
                head_sha = %record.head_sha,
                mode = %record.mode,
                phase = name,
                duration_ms = tracing::field::Empty
            ),
        }
    }

    /// Measure one lane without adding overlapping lane time to phase totals.
    pub(crate) fn lane(&self, name: &'static str) -> PhaseGuard {
        self.lane_under(name, &Span::current())
    }

    /// Measure a lane beneath the enclosing `lanes` span without entering it
    /// in thread-local state across an await.
    pub(crate) fn lane_under(&self, name: &'static str, parent: &Span) -> PhaseGuard {
        let record = self.snapshot();
        PhaseGuard {
            timing: self.clone(),
            name: "lanes",
            lane: Some(name),
            started: Instant::now(),
            span: tracing::info_span!(parent: parent,
                "review.phase",
                repo = %record.repo,
                pr = record.pr,
                head_sha = %record.head_sha,
                mode = %record.mode,
                phase = "lane",
                lane = name,
                duration_ms = tracing::field::Empty
            ),
        }
    }

    /// Apply a synchronized update to the telemetry snapshot.
    pub(crate) fn record(&self, update: impl FnOnce(&mut Record)) {
        let head_sha = {
            let mut record = self.0.record.lock().expect("review timing lock");
            update(&mut record);
            record.head_sha.clone()
        };
        if !head_sha.is_empty() {
            self.0.worker_span.record("head_sha", head_sha.as_str());
        }
    }

    /// Clone the current record for assertions or intermediate reporting.
    pub(crate) fn snapshot(&self) -> Record {
        self.0.record.lock().expect("review timing lock").clone()
    }

    /// Mark the terminal outcome emitted when the final handle is dropped.
    pub(crate) fn finish(&self, outcome: &str) {
        self.record(|r| r.outcome = outcome.to_owned());
    }
}

/// Run a future inside a named phase, recording time on cancellation too.
pub(crate) async fn measure<F: Future>(
    timing: Option<&ReviewTiming>,
    name: &'static str,
    future: F,
) -> F::Output {
    if let Some(timing) = timing {
        let guard = timing.phase(name);
        let output = future.instrument(guard.span.clone()).await;
        drop(guard);
        output
    } else {
        future.await
    }
}

/// Run one lane as a child of the enclosing lanes span.
pub(crate) async fn measure_lane_under<F: Future>(
    timing: Option<&ReviewTiming>,
    name: &'static str,
    parent: Option<&Span>,
    future: F,
) -> F::Output {
    if let Some(timing) = timing {
        let guard = match parent {
            Some(parent) => timing.lane_under(name, parent),
            None => timing.lane(name),
        };
        let output = future.instrument(guard.span.clone()).await;
        drop(guard);
        output
    } else {
        future.await
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let r = self.record.get_mut().expect("review timing lock");
        let total_ms = r
            .started
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or_default();
        tracing::info!(target: "tinysweeper::review_timing", repo = %r.repo, pr = r.pr,
            head_sha = %r.head_sha, mode = %r.mode, outcome = %r.outcome, total_ms,
            queue_wait_ms = r.queue_wait_ms,
            phases_ms = %serde_json::to_string(&r.phases_ms).unwrap_or_default(),
            lanes_ms = %serde_json::to_string(&r.lanes_ms).unwrap_or_default(),
            calls_attempted = r.calls_attempted, calls_succeeded = r.calls_succeeded,
            calls_refused = r.calls_refused, calls_errored = r.calls_errored,
            input_tokens = r.usage.input_tokens, output_tokens = r.usage.output_tokens,
            reasoning_tokens = r.usage.reasoning_tokens, cached_tokens = r.usage.cached_tokens,
            files_total = r.files_total, files_answered = r.files_answered,
            files_unanswered = r.files_unanswered, "review timing");
    }
}

/// RAII timer that records elapsed time even when its future is cancelled.
pub(crate) struct PhaseGuard {
    timing: ReviewTiming,
    name: &'static str,
    lane: Option<&'static str>,
    started: Instant,
    /// Tracing span wrapped around the measured future.
    pub(crate) span: Span,
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.span.record("duration_ms", elapsed);
        self.timing.record(|r| {
            if self.name == "permit" {
                r.queue_wait_ms += elapsed;
            }
            if let Some(lane) = self.lane {
                *r.lanes_ms.entry(lane.into()).or_default() += elapsed;
            } else {
                *r.phases_ms.entry(self.name.into()).or_default() += elapsed;
            }
        });
    }
}
