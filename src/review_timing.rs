//! Per-review telemetry shared by the server and the read-only review pipeline.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::Instrument;
use tracing::Span;

use crate::ports::model::Usage;

pub const PHASES: &[&str] = &[
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

pub fn outcome_for_error(error: &crate::error::Error) -> &'static str {
    if matches!(error, crate::error::Error::Timeout { .. }) {
        "deadline"
    } else {
        "failure"
    }
}

#[derive(Debug, Clone)]
pub struct ReviewTiming(Arc<Inner>);

#[derive(Debug)]
struct Inner(Mutex<Record>);

/// Snapshot of the server's structured telemetry for one review run.
#[derive(Debug, Clone, Default)]
pub struct Record {
    pub repo: String,
    pub pr: u64,
    pub head_sha: String,
    pub mode: String,
    pub outcome: String,
    pub started: Option<Instant>,
    pub queue_wait_ms: u64,
    pub phases_ms: BTreeMap<String, u64>,
    pub lanes_ms: BTreeMap<String, u64>,
    pub calls_attempted: u64,
    pub calls_succeeded: u64,
    pub calls_refused: u64,
    pub calls_errored: u64,
    pub usage: Usage,
    pub files_total: usize,
    pub files_answered: usize,
    pub files_unanswered: usize,
}

impl ReviewTiming {
    pub fn new(repo: impl Into<String>, pr: u64, mode: impl Into<String>) -> Self {
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
        Self(Arc::new(Inner(Mutex::new(record))))
    }

    pub fn phase(&self, name: &'static str) -> PhaseGuard {
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

    pub fn lane(&self, name: &'static str) -> PhaseGuard {
        let record = self.snapshot();
        PhaseGuard {
            timing: self.clone(),
            name: "lanes",
            lane: Some(name),
            started: Instant::now(),
            span: tracing::info_span!(
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

    pub fn record(&self, update: impl FnOnce(&mut Record)) {
        update(&mut self.0.0.lock().expect("review timing lock"));
    }

    pub fn snapshot(&self) -> Record {
        self.0.0.lock().expect("review timing lock").clone()
    }

    pub fn finish(&self, outcome: &str) {
        self.record(|r| r.outcome = outcome.to_owned());
    }

}

pub async fn measure<F: Future>(
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

pub async fn measure_lane<F: Future>(
    timing: Option<&ReviewTiming>,
    name: &'static str,
    future: F,
) -> F::Output {
    if let Some(timing) = timing {
        let guard = timing.lane(name);
        let output = future.instrument(guard.span.clone()).await;
        drop(guard);
        output
    } else {
        future.await
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let r = self.0.get_mut().expect("review timing lock");
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

pub struct PhaseGuard {
    timing: ReviewTiming,
    name: &'static str,
    lane: Option<&'static str>,
    started: Instant,
    pub span: Span,
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.span.record("duration_ms", elapsed);
        self.timing.record(|r| {
            if self.name == "permit" {
                r.queue_wait_ms += elapsed;
            }
            *r.phases_ms.entry(self.name.into()).or_default() += elapsed;
            if let Some(lane) = self.lane {
                *r.lanes_ms.entry(lane.into()).or_default() += elapsed;
            }
        });
    }
}
