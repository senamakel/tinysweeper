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
    /// The review has committed or reserved its physical-call ceiling.
    CallLimit,
    /// The absolute review soft deadline has passed.
    SoftDeadline,
}

/// A review-scoped source of physical-dispatch permits.
#[async_trait]
pub trait ModelExecutionControl: Send + Sync {
    /// Reserve one dispatch slot before any potentially blocking money wait.
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
    fn mark_dispatched(&self) -> std::result::Result<(), ModelExecutionRefusal>;
}
