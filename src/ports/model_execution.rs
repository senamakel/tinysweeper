//! Review-scoped control over physical model dispatches.
//!
//! A model wrapper acquires before monetary waiting, then commits the permit
//! immediately before invoking the concrete provider. The same control object
//! must survive clones and budget re-scoping; wrappers do not create a fresh
//! review ceiling. Backends that cannot preserve the control keep the default
//! `None` compatibility path and cannot claim a physical-call guarantee.

use async_trait::async_trait;

/// Why a review-wide policy refused to start a physical model dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelExecutionRefusal {
    /// The review has exhausted its ceiling with committed physical dispatches.
    ///
    /// Acquisitions wait while the ceiling is occupied only by refundable
    /// reservations; a reservation becoming committed or being dropped wakes
    /// those waiters to re-evaluate the ceiling.
    CallLimit,
    /// The absolute review soft deadline has passed, either at acquisition or
    /// when a reserved permit is committed for dispatch.
    SoftDeadline,
    /// The review's logical owner cancelled its execution scope.
    Cancelled,
}

/// A review-scoped source of physical-dispatch permits.
#[async_trait]
pub trait ModelExecutionControl: Send + Sync {
    /// Reserve one dispatch slot before any potentially blocking money wait.
    ///
    /// If outstanding uncommitted reservations temporarily fill the ceiling,
    /// wait for a reservation to commit or be dropped instead of refusing the
    /// request. Return `CallLimit` once committed dispatches exhaust the
    /// ceiling, `SoftDeadline` once the absolute soft deadline has passed, or
    /// `Cancelled` when the review owner stops execution.
    async fn acquire(
        &self,
    ) -> std::result::Result<Box<dyn ModelExecutionPermit>, ModelExecutionRefusal>;
}

/// One reserved physical-dispatch slot.
pub trait ModelExecutionPermit: Send + Sync {
    /// Commit the slot immediately before provider invocation.
    ///
    /// Implementations make this idempotent. Dropping an uncommitted permit
    /// releases its reservation; dropping a committed permit never refunds it.
    /// Recheck the absolute soft deadline here because callers may wait for
    /// money after acquiring. A refusal leaves this permit uncommitted and does
    /// not consume a committed-call slot.
    fn mark_dispatched(&self) -> std::result::Result<(), ModelExecutionRefusal>;
}
