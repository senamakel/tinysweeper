//! Review-wide execution scope for physical model dispatches.
//!
//! The scope is created from the server's already-established review window and
//! cloned through model wrappers. This source scaffold defines the ownership,
//! deadline and accounting surface; production refusal and waiting policy
//! remain intentionally unimplemented until the control behavior is compiled
//! and observed red.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;

use crate::lanes::large_pr::ReviewMode;
use crate::ports::model::{Model, Usage};
use crate::ports::model_execution::{
    ModelExecutionControl, ModelExecutionPermit, ModelExecutionRefusal,
};

/// Why an execution scope stopped admitting additional review work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewStopReason {
    /// Large-mode candidate selection left no more model groups to review.
    LargePrLimit,
    /// The review-wide physical dispatch count was exhausted.
    CallLimit,
    /// The absolute soft deadline stopped new work.
    SoftDeadline,
}

/// Absolute review window and the operator limits applied to it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReviewExecutionOptions {
    /// The already-established start of this review's hard window.
    pub started_at: Instant,
    /// The already-established server hard deadline.
    pub hard_deadline: Instant,
    /// Review policy mode.
    pub mode: ReviewMode,
    /// Physical call ceiling, absent for normal-mode scheduling.
    pub max_calls: Option<usize>,
    /// Percent of the original hard window available for new work.
    pub soft_deadline_percent: u8,
    /// Maximum finish interval for work already admitted at the soft deadline.
    pub drain_seconds: u64,
}

/// A snapshot of committed and currently reserved provider-call slots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ReviewExecutionSnapshot {
    /// Calls committed immediately before their provider invocation.
    pub committed_calls: usize,
    /// Acquisitions that have not yet reached a provider invocation.
    pub reserved_calls: usize,
    /// The stop reason selected by execution policy, when known.
    pub stop_reason: Option<ReviewStopReason>,
    /// Terminal physical usage received by this review scope.
    pub physical_usage: Usage,
}

#[derive(Debug)]
struct ExecutionState {
    committed_calls: usize,
    reserved_calls: usize,
    stop_reason: Option<ReviewStopReason>,
    physical_usage: Usage,
}

#[derive(Debug)]
struct ExecutionInner {
    started_at: Instant,
    hard_deadline: Instant,
    soft_deadline: Instant,
    mode: ReviewMode,
    max_calls: Option<usize>,
    drain_seconds: u64,
    state: Mutex<ExecutionState>,
}

/// Shared execution limits and accounting for one pull-request review.
#[derive(Debug, Clone)]
pub(crate) struct ReviewExecution {
    inner: Arc<ExecutionInner>,
}

impl ReviewExecution {
    /// Create a scope from a hard deadline established before checkout work.
    pub(crate) fn new(options: ReviewExecutionOptions) -> Self {
        let window = options
            .hard_deadline
            .saturating_duration_since(options.started_at);
        let soft_deadline =
            options.started_at + window.mul_f64(f64::from(options.soft_deadline_percent) / 100.0);
        Self {
            inner: Arc::new(ExecutionInner {
                started_at: options.started_at,
                hard_deadline: options.hard_deadline,
                soft_deadline,
                mode: options.mode,
                max_calls: options.max_calls,
                drain_seconds: options.drain_seconds,
                state: Mutex::new(ExecutionState {
                    committed_calls: 0,
                    reserved_calls: 0,
                    stop_reason: None,
                    physical_usage: Usage::default(),
                }),
            }),
        }
    }

    /// The original absolute review start, before checkout and setup.
    pub(crate) fn started_at(&self) -> Instant {
        self.inner.started_at
    }

    /// The absolute hard deadline inherited from the server job.
    pub(crate) fn hard_deadline(&self) -> Instant {
        self.inner.hard_deadline
    }

    /// The absolute soft deadline for stopping new work.
    pub(crate) fn soft_deadline(&self) -> Instant {
        self.inner.soft_deadline
    }

    /// The mode frozen for this review.
    pub(crate) fn mode(&self) -> ReviewMode {
        self.inner.mode
    }

    /// Maximum time reserved for admitted work to drain.
    pub(crate) fn drain_seconds(&self) -> u64 {
        self.inner.drain_seconds
    }

    /// The fixed physical-call ceiling, if this mode has one.
    pub(crate) fn max_calls(&self) -> Option<usize> {
        self.inner.max_calls
    }

    /// Record a terminal physical call event independently of timing spans.
    pub(crate) fn record_physical_usage(&self, usage: Usage) {
        lock(&self.inner.state).physical_usage.add(usage);
    }

    /// Snapshot the counters used when the proposal is finalized.
    pub(crate) fn snapshot(&self) -> ReviewExecutionSnapshot {
        let state = lock(&self.inner.state);
        ReviewExecutionSnapshot {
            committed_calls: state.committed_calls,
            reserved_calls: state.reserved_calls,
            stop_reason: state.stop_reason,
            physical_usage: state.physical_usage,
        }
    }
}

#[async_trait::async_trait]
impl ModelExecutionControl for ReviewExecution {
    async fn acquire(
        &self,
    ) -> std::result::Result<Box<dyn ModelExecutionPermit>, ModelExecutionRefusal> {
        // Source-preparation scaffold: this creates a reservation but does not
        // yet enforce the stored call ceiling or absolute soft deadline. The
        // corresponding tests intentionally capture those missing behaviors.
        let mut state = lock(&self.inner.state);
        state.reserved_calls = state.reserved_calls.saturating_add(1);
        drop(state);
        Ok(Box::new(ReviewDispatchPermit {
            inner: Arc::clone(&self.inner),
            committed: AtomicBool::new(false),
        }))
    }
}

struct ReviewDispatchPermit {
    inner: Arc<ExecutionInner>,
    committed: AtomicBool,
}

impl ModelExecutionPermit for ReviewDispatchPermit {
    fn mark_dispatched(&self) -> std::result::Result<(), ModelExecutionRefusal> {
        if self.committed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut state = lock(&self.inner.state);
        state.reserved_calls = state.reserved_calls.saturating_sub(1);
        state.committed_calls = state.committed_calls.saturating_add(1);
        Ok(())
    }
}

impl Drop for ReviewDispatchPermit {
    fn drop(&mut self) {
        if !self.committed.load(Ordering::Acquire) {
            let mut state = lock(&self.inner.state);
            state.reserved_calls = state.reserved_calls.saturating_sub(1);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::model_execution::ModelExecutionControl;

    fn options(
        mode: ReviewMode,
        max_calls: Option<usize>,
        started_at: Instant,
        hard_deadline: Instant,
    ) -> ReviewExecutionOptions {
        ReviewExecutionOptions {
            started_at,
            hard_deadline,
            mode,
            max_calls,
            soft_deadline_percent: 80,
            drain_seconds: 30,
        }
    }

    #[tokio::test]
    async fn concurrent_dispatches_do_not_exceed_the_shared_call_ceiling() {
        let started_at = Instant::now();
        let execution = Arc::new(ReviewExecution::new(options(
            ReviewMode::Large,
            Some(3),
            started_at,
            started_at + Duration::from_secs(100),
        )));
        let control: Arc<dyn ModelExecutionControl> = execution.clone();
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..100 {
            let control = Arc::clone(&control);
            tasks.spawn(async move {
                let Ok(permit) = control.acquire().await else {
                    return false;
                };
                permit.mark_dispatched().is_ok()
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.expect("dispatch task");
        }

        assert!(execution.snapshot().committed_calls <= 3);
    }

    #[tokio::test]
    async fn acquisition_uses_the_absolute_soft_deadline_from_review_start() {
        let started_at = Instant::now() - Duration::from_secs(85);
        let hard_deadline = started_at + Duration::from_secs(100);
        let execution =
            ReviewExecution::new(options(ReviewMode::Normal, None, started_at, hard_deadline));

        assert!(execution.soft_deadline() < Instant::now());
        assert!(execution.hard_deadline() > Instant::now());
        assert_eq!(execution.started_at(), started_at);
        assert_eq!(
            execution.acquire().await.err(),
            Some(ModelExecutionRefusal::SoftDeadline)
        );
    }

    #[tokio::test]
    async fn dropped_reservations_are_refunded_but_committed_slots_are_not() {
        let started_at = Instant::now();
        let execution = ReviewExecution::new(options(
            ReviewMode::Large,
            Some(4),
            started_at,
            started_at + Duration::from_secs(100),
        ));

        let abandoned = execution.acquire().await.expect("reservation");
        assert_eq!(execution.snapshot().reserved_calls, 1);
        drop(abandoned);
        assert_eq!(execution.snapshot().reserved_calls, 0);

        let committed = execution.acquire().await.expect("reservation");
        committed.mark_dispatched().expect("commit");
        drop(committed);
        let snapshot = execution.snapshot();
        assert_eq!(snapshot.reserved_calls, 0);
        assert_eq!(snapshot.committed_calls, 1);
    }

    #[tokio::test]
    async fn committing_a_permit_twice_counts_one_dispatch() {
        let started_at = Instant::now();
        let execution = ReviewExecution::new(options(
            ReviewMode::Large,
            Some(4),
            started_at,
            started_at + Duration::from_secs(100),
        ));
        let permit = execution.acquire().await.expect("reservation");

        permit.mark_dispatched().expect("first commit");
        permit.mark_dispatched().expect("idempotent commit");

        assert_eq!(execution.snapshot().committed_calls, 1);
    }

    #[tokio::test]
    async fn execution_clones_share_the_same_reservation_and_usage_ledger() {
        let started_at = Instant::now();
        let execution = ReviewExecution::new(options(
            ReviewMode::Large,
            Some(4),
            started_at,
            started_at + Duration::from_secs(100),
        ));
        let clone = execution.clone();
        let permit = execution.acquire().await.expect("reservation");

        assert_eq!(clone.snapshot().reserved_calls, 1);
        permit.mark_dispatched().expect("commit");
        clone.record_physical_usage(Usage {
            calls_attempted: 1,
            calls_succeeded: 1,
            input_tokens: 17,
            ..Usage::default()
        });

        let snapshot = execution.snapshot();
        assert_eq!(snapshot.committed_calls, 1);
        assert_eq!(snapshot.physical_usage.calls_attempted, 1);
        assert_eq!(snapshot.physical_usage.input_tokens, 17);
    }

    #[test]
    fn execution_options_keep_the_mode_call_cap_and_drain_policy_together() {
        let started_at = Instant::now();
        let execution = ReviewExecution::new(options(
            ReviewMode::Large,
            Some(48),
            started_at,
            started_at + Duration::from_secs(900),
        ));

        assert_eq!(execution.mode(), ReviewMode::Large);
        assert_eq!(execution.max_calls(), Some(48));
        assert_eq!(execution.drain_seconds(), 30);
        assert_eq!(
            execution.soft_deadline(),
            started_at + Duration::from_secs(720)
        );
    }

    #[test]
    fn opaque_legacy_models_decline_the_optional_execution_control() {
        let started_at = Instant::now();
        let execution = ReviewExecution::new(options(
            ReviewMode::Normal,
            None,
            started_at,
            started_at + Duration::from_secs(900),
        ));
        let model: Arc<dyn Model> = Arc::new(crate::harness::mock::MockModel::new());
        let control: Arc<dyn ModelExecutionControl> = Arc::new(execution);

        assert!(model.with_execution_control(control).is_none());
    }
}
