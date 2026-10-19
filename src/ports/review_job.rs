//! Durable admission and ownership for server review work.
//!
//! The server uses this port as the source of truth for accepted work. Wakeup
//! channels are hints only: a process can stop after persisting a request and
//! before sending its hint, so workers also poll this bounded journal.

use crate::error::Result;

/// Maximum accepted requests waiting or running across all server processes.
pub const MAX_UNFINISHED_REVIEWS: usize = 260;
/// Delivery and head-state reservations within the fixed eight-megabyte BSON
/// cap. Admission reserves dedupe IDs and future current/history head records
/// together, without evicting live tombstones or terminal heads.
pub const MAX_TERMINAL_REVIEW_RESERVATIONS: usize = 18_000;
/// Maximum reviews that may be running across all server processes.
pub const MAX_RUNNING_REVIEWS: usize = 4;
/// Paid recovery starts allowed for one accepted review across process restarts.
pub const MAX_REVIEW_PAID_ATTEMPTS: u32 = 5;
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

/// Result of consuming one durable paid-work attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaidStart {
    /// This owner may proceed to credentials and review work.
    Started,
    /// The retry budget was exhausted; its owner can now conclude status and finish it.
    Exhausted,
    /// This process no longer owns the unexpired generation.
    OwnershipLost,
}

/// A request claimed by one server process and fenced by a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedReview {
    /// The accepted request metadata.
    pub request: ReviewRequest,
    /// Every accepted delivery coalesced into this review.
    pub accepted_ids: Vec<ReviewJobId>,
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
    /// The wall-clock review deadline was reached for the confirmed head.
    Deadline,
}

/// One unfinished scheduler record and its fenced owner, if running.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScheduledReview {
    /// Accepted request metadata.
    pub request: ReviewRequest,
    /// Every accepted delivery coalesced into this review and reserved for a
    /// terminal tombstone when the canonical work completes.
    #[serde(default)]
    pub accepted_ids: Vec<ReviewJobId>,
    /// Owner identity, absent while pending.
    pub owner: Option<String>,
    /// Ownership generation, increased on every claim.
    pub generation: u64,
    /// Owner lease expiry in Unix milliseconds.
    pub owner_until_ms: i64,
    /// Earliest retry time in Unix milliseconds.
    pub not_before_ms: i64,
    /// Paid-work starts consumed across process restarts.
    pub paid_attempts: u32,
    /// New incremental delivery arrived while this owner was running. The
    /// owner keeps its global slot until it observes and acknowledges this.
    #[serde(default)]
    pub yield_requested: bool,
    /// Most recently observed webhook head hint. It is never authoritative;
    /// the next owner still resolves the live head from Forge.
    #[serde(default)]
    pub latest_head_hint: Option<String>,
    /// Reserved slots for terminal-head history records this accepted work
    /// could create while resolving successive authoritative heads.
    #[serde(default)]
    pub head_history_reservations: usize,
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

/// Current authoritative head and paid budget for one incremental PR.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IncrementalHeadBudget {
    /// Repository in owner/name form.
    pub repo: String,
    /// Pull request number.
    pub number: u64,
    /// Head SHA confirmed from Forge.
    pub head_sha: String,
    /// Paid starts consumed for this exact head across owners.
    pub paid_attempts: u32,
    /// Deadline exhaustion is terminal until an authoritative head change.
    pub deadline_hit: bool,
    /// The terminal result for this exact head, if it already has one.
    #[serde(default)]
    pub terminal_outcome: Option<TerminalOutcome>,
}

/// Recent terminal history preventing delayed delivery of an old head from
/// resetting its budget after the PR advanced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeadTerminalTombstone {
    /// Repository in owner/name form.
    pub repo: String,
    /// Pull request number.
    pub number: u64,
    /// Head SHA with a terminal result.
    pub head_sha: String,
    /// Terminal result for that head.
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
    /// Authoritative current-head budgets, retained until each PR advances.
    #[serde(default)]
    pub incremental_heads: Vec<IncrementalHeadBudget>,
    /// Bounded recent history of terminal heads.
    #[serde(default)]
    pub head_history: Vec<HeadTerminalTombstone>,
}

impl ReviewSchedulerState {
    /// Atomically admit a whole batch in memory before the Mongo CAS persists it.
    pub fn admit_batch(&mut self, requests: Vec<ReviewRequest>, now_ms: i64) -> Admission {
        if requests.is_empty() {
            return Admission::Duplicate;
        }
        self.normalize_legacy_records();
        self.terminal.retain(|record| record.expires_at_ms > now_ms);
        self.head_history.retain(|record| record.expires_at_ms > now_ms);
        let mut incoming = std::collections::HashSet::new();
        if requests
            .iter()
            .any(|request| !incoming.insert(request.id.clone()) || !metadata_is_bounded(request))
        {
            return Admission::Full;
        }
        let already = requests
            .iter()
            .filter(|request| {
                self.unfinished
                    .iter()
                    .any(|record| record.accepted_ids.contains(&request.id))
                    || self.terminal.iter().any(|record| record.id == request.id)
            })
            .count();
        if already == requests.len() {
            return Admission::Duplicate;
        }
        let new_jobs = new_uncoalesced_count(&self.unfinished, &requests);
        let pending_prs = self
            .unfinished
            .iter()
            .filter(|record| record.request.mode == ReviewJobMode::Incremental)
            .map(|record| (record.request.repo.clone(), record.request.number))
            .collect::<std::collections::HashSet<_>>();
        let new_prs_without_head = requests
            .iter()
            .filter(|request| request.mode == ReviewJobMode::Incremental)
            .map(|request| (request.repo.clone(), request.number))
            .filter(|key| {
                !pending_prs.contains(key)
                    && !self.incremental_heads.iter().any(|budget| {
                        budget.repo == key.0 && budget.number == key.1
                    })
            })
            .collect::<std::collections::HashSet<_>>()
            .len();
        let incoming_history_reservations = requests
            .iter()
            .filter(|request| request.mode == ReviewJobMode::Incremental)
            .count();
        if already != 0
            || self.unfinished.len() + new_jobs > MAX_UNFINISHED_REVIEWS
            || self.reserved_capacity()
                + requests.len()
                + incoming_history_reservations
                + new_prs_without_head
                > MAX_TERMINAL_REVIEW_RESERVATIONS
        {
            return Admission::Full;
        }
        for request in requests {
            let coalesce = request.mode == ReviewJobMode::Incremental;
            if let Some(record) = coalesce.then(|| {
                self.unfinished.iter_mut().find(|record| {
                    record.request.mode == ReviewJobMode::Incremental
                        && record.request.repo == request.repo
                        && record.request.number == request.number
                })
            }).flatten() {
                record.accepted_ids.push(request.id);
                record.latest_head_hint = request.head_sha.clone();
                record.head_history_reservations += 1;
                if record.owner.is_some() {
                    if record.request.head_sha != request.head_sha {
                        record.yield_requested = true;
                    }
                } else {
                    record.request = request;
                }
                continue;
            }
            self.unfinished.push(ScheduledReview {
                accepted_ids: vec![request.id.clone()],
                latest_head_hint: request.head_sha.clone(),
                head_history_reservations: usize::from(
                    request.mode == ReviewJobMode::Incremental,
                ),
                request,
                owner: None,
                generation: 0,
                owner_until_ms: 0,
                not_before_ms: 0,
                paid_attempts: 0,
                yield_requested: false,
            });
        }
        Admission::Admitted
    }

    /// Count persisted records and all capacity promised to accepted work.
    /// The reservation makes later live-head transitions fit without evicting
    /// delivery tombstones or terminal-head history.
    pub fn reserved_capacity(&self) -> usize {
        let pending_prs = self
            .unfinished
            .iter()
            .filter(|record| record.request.mode == ReviewJobMode::Incremental)
            .map(|record| (record.request.repo.as_str(), record.request.number))
            .collect::<std::collections::HashSet<_>>();
        let pending_head_slots = pending_prs
            .iter()
            .filter(|(repo, number)| {
                !self.incremental_heads.iter().any(|budget| {
                    budget.repo.as_str() == *repo && budget.number == *number
                })
            })
            .count();
        self.terminal.len()
            + self
                .unfinished
                .iter()
                .map(|record| record.accepted_ids.len().max(1))
                .sum::<usize>()
            + self.incremental_heads.len()
            + self.head_history.len()
            + self
                .unfinished
                .iter()
                .map(|record| {
                    if record.request.mode == ReviewJobMode::Incremental {
                        record
                            .head_history_reservations
                            .max(record.accepted_ids.len().max(1))
                    } else {
                        0
                    }
                })
                .sum::<usize>()
            + pending_head_slots
    }

    /// Fill fields added after the durable scheduler was first deployed.
    /// Missing aggregate IDs mean the record predates supersession support and
    /// therefore reserves its original request ID.
    pub fn normalize_legacy_records(&mut self) {
        for record in &mut self.unfinished {
            if record.accepted_ids.is_empty() {
                record.accepted_ids.push(record.request.id.clone());
            }
            if record.latest_head_hint.is_none() {
                record.latest_head_hint = record.request.head_sha.clone();
            }
            if record.request.mode == ReviewJobMode::Incremental
                && record.head_history_reservations == 0
            {
                record.head_history_reservations = record.accepted_ids.len();
            }
        }
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
        Some(OwnedReview {
            request: record.request.clone(),
            accepted_ids: record.accepted_ids.clone(),
            owner: owner.to_owned(),
            generation: record.generation,
        })
    }

    /// Consume one paid attempt, leaving exhausted work owned for status cleanup.
    pub fn begin_paid(&mut self, owned: &OwnedReview, now_ms: i64) -> PaidStart {
        let Some(index) = self
            .unfinished
            .iter()
            .position(|record| owns(record, owned) && record.owner_until_ms > now_ms)
        else {
            return PaidStart::OwnershipLost;
        };
        if self.unfinished[index].request.mode == ReviewJobMode::Incremental {
            let request = &self.unfinished[index].request;
            if !self.incremental_heads.iter().any(|budget| {
                budget.repo == request.repo && budget.number == request.number
            }) {
                // A webhook SHA is only a hint. Production must confirm a live
                // head from Forge before paid work can start.
                return PaidStart::OwnershipLost;
            }
            let Some(budget) = self.incremental_heads.iter_mut().find(|budget| {
                budget.repo == request.repo && budget.number == request.number
            }) else {
                return PaidStart::OwnershipLost;
            };
            if budget.terminal_outcome.is_some()
                || budget.deadline_hit
                || self.head_history.iter().any(|record| {
                    record.repo == request.repo
                        && record.number == request.number
                        && record.head_sha == budget.head_sha
                        && record.expires_at_ms > now_ms
                })
            {
                return PaidStart::Exhausted;
            }
            if budget.paid_attempts >= MAX_REVIEW_PAID_ATTEMPTS {
                return PaidStart::Exhausted;
            }
            budget.paid_attempts += 1;
            return PaidStart::Started;
        }
        if self.unfinished[index].paid_attempts >= MAX_REVIEW_PAID_ATTEMPTS {
            return PaidStart::Exhausted;
        }
        self.unfinished[index].paid_attempts += 1;
        PaidStart::Started
    }

    /// Bind an owned incremental request to the authoritative live head. A
    /// webhook SHA hint cannot reset a deadline marker or paid-start count.
    pub fn confirm_head(&mut self, owned: &OwnedReview, head_sha: &str, now_ms: i64) -> bool {
        let Some(index) = self
            .unfinished
            .iter()
            .position(|record| owns(record, owned) && record.owner_until_ms > now_ms)
        else {
            return false;
        };
        if self.unfinished[index].request.mode != ReviewJobMode::Incremental {
            return true;
        }
        let repo = self.unfinished[index].request.repo.clone();
        let number = self.unfinished[index].request.number;
        self.head_history.retain(|record| record.expires_at_ms > now_ms);
        if let Some(current) = self.incremental_heads.iter_mut().find(|budget| {
            budget.repo == repo && budget.number == number
        }) {
            if current.head_sha == head_sha {
                self.unfinished[index].request.head_sha = Some(head_sha.to_owned());
                return true;
            }
            if current.terminal_outcome.is_some() || current.deadline_hit {
                if self.unfinished[index].head_history_reservations == 0 {
                    return false;
                }
                self.unfinished[index].head_history_reservations -= 1;
                self.head_history.push(HeadTerminalTombstone {
                    repo: repo.clone(),
                    number,
                    head_sha: current.head_sha.clone(),
                    outcome: current.terminal_outcome.unwrap_or(TerminalOutcome::Deadline),
                    expires_at_ms: now_ms + REVIEW_TOMBSTONE_TTL_MS,
                });
            }
            current.head_sha = head_sha.to_owned();
            let historical_outcome = self.head_history.iter().find(|record| {
                record.repo == repo
                    && record.number == number
                    && record.head_sha == head_sha
                    && record.expires_at_ms > now_ms
            }).map(|record| record.outcome);
            let historical_deadline = historical_outcome == Some(TerminalOutcome::Deadline);
            current.paid_attempts = if historical_deadline {
                MAX_REVIEW_PAID_ATTEMPTS
            } else {
                0
            };
            current.deadline_hit = historical_deadline;
            current.terminal_outcome = historical_outcome;
            self.unfinished[index].request.head_sha = Some(head_sha.to_owned());
            return true;
        }
        if self.unfinished[index].request.mode != ReviewJobMode::Incremental {
            return false;
        }
        self.incremental_heads.push(IncrementalHeadBudget {
            repo,
            number,
            head_sha: head_sha.to_owned(),
            paid_attempts: 0,
            deadline_hit: false,
            terminal_outcome: None,
        });
        self.unfinished[index].request.head_sha = Some(head_sha.to_owned());
        true
    }

    /// Whether a confirmed incremental head already has a terminal result.
    pub fn head_is_terminal(&self, owned: &OwnedReview, now_ms: i64) -> bool {
        self.unfinished
            .iter()
            .find(|record| owns(record, owned) && record.owner_until_ms > now_ms)
            .filter(|record| record.request.mode == ReviewJobMode::Incremental)
            .and_then(|record| {
                self.incremental_heads.iter().find(|budget| {
                    budget.repo == record.request.repo && budget.number == record.request.number
                })
            })
            .is_some_and(|budget| {
                budget.terminal_outcome.is_some() || budget.deadline_hit
            })
    }

    /// Record an owned deadline and persist a marker for the confirmed SHA
    /// beyond delivery tombstones. If a push raced the deadline, preserve the
    /// accepted job for the next owner while keeping that head terminal.
    pub fn finish_deadline(&mut self, owned: &OwnedReview, now_ms: i64) -> bool {
        let Some(index) = self.unfinished.iter().position(|record| {
            owns(record, owned) && record.owner_until_ms > now_ms
        }) else {
            return false;
        };
        let request = self.unfinished[index].request.clone();
        if request.mode == ReviewJobMode::Incremental {
            let Some(budget) = self.incremental_heads.iter_mut().find(|budget| {
                budget.repo == request.repo && budget.number == request.number
            }) else {
                return false;
            };
            budget.deadline_hit = true;
            budget.terminal_outcome = Some(TerminalOutcome::Deadline);
        }
        if self.unfinished[index].yield_requested {
            let record = &mut self.unfinished[index];
            record.owner = None;
            record.owner_until_ms = 0;
            record.not_before_ms = now_ms;
            record.request.head_sha = record.latest_head_hint.clone();
            record.yield_requested = false;
            return true;
        }
        let record = self.unfinished.remove(index);
        self.terminal.extend(record.accepted_ids.into_iter().map(|id| ReviewTombstone {
            id,
            outcome: TerminalOutcome::Deadline,
            expires_at_ms: now_ms + REVIEW_TOMBSTONE_TTL_MS,
        }));
        true
    }

    /// Extend the current unexpired owner's lease.
    pub fn renew(&mut self, owned: &OwnedReview, now_ms: i64) -> bool {
        let Some(record) = self
            .unfinished
            .iter_mut()
            .find(|record| owns(record, owned))
        else {
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

    /// Whether an owner may begin or continue paid model work. A superseding
    /// delivery only asks the owner to yield; ownership stays fenced until it
    /// acknowledges, so the global running count cannot be exceeded.
    pub fn should_continue(&self, owned: &OwnedReview, now_ms: i64) -> bool {
        self.unfinished
            .iter()
            .find(|record| owns(record, owned))
            .is_some_and(|record| {
                record.owner_until_ms > now_ms && !record.yield_requested
            })
    }

    /// Acknowledge an advisory supersession and return this same accepted work
    /// to the queue with the latest hint. Accepted IDs and paid-start history
    /// remain attached to it.
    pub fn defer_yield(&mut self, owned: &OwnedReview, now_ms: i64) -> bool {
        let Some(record) = self
            .unfinished
            .iter_mut()
            .find(|record| owns(record, owned) && record.owner_until_ms > now_ms)
        else {
            return false;
        };
        if !record.yield_requested {
            return false;
        }
        record.owner = None;
        record.owner_until_ms = 0;
        record.not_before_ms = now_ms;
        record.request.head_sha = record.latest_head_hint.clone();
        record.yield_requested = false;
        true
    }

    /// Return the current owner's request to pending with bounded backoff.
    pub fn defer(&mut self, owned: &OwnedReview, now_ms: i64, not_before_ms: i64) -> bool {
        let Some(record) = self
            .unfinished
            .iter_mut()
            .find(|record| owns(record, owned))
        else {
            return false;
        };
        if record.owner_until_ms <= now_ms {
            return false;
        }
        record.owner = None;
        record.owner_until_ms = 0;
        record.not_before_ms = not_before_ms;
        if record.yield_requested {
            record.request.head_sha = record.latest_head_hint.clone();
            record.yield_requested = false;
        }
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
            .position(|record| {
                owns(record, owned) && record.owner_until_ms > now_ms && !record.yield_requested
            })
        else {
            return false;
        };
        let record = self.unfinished.remove(index);
        let existing_terminal = if record.request.mode == ReviewJobMode::Incremental {
            self.incremental_heads
                .iter()
                .find(|budget| {
                    budget.repo == record.request.repo && budget.number == record.request.number
                })
                .and_then(|budget| budget.terminal_outcome)
        } else {
            None
        };
        if existing_terminal.is_none()
            && record.request.mode == ReviewJobMode::Incremental
            && matches!(
                outcome,
                TerminalOutcome::Published
                    | TerminalOutcome::Declined
                    | TerminalOutcome::Exhausted
                    | TerminalOutcome::Deadline
            )
            && let Some(budget) = self.incremental_heads.iter_mut().find(|budget| {
                budget.repo == record.request.repo && budget.number == record.request.number
            })
        {
            budget.terminal_outcome = Some(outcome);
            if outcome == TerminalOutcome::Deadline {
                budget.deadline_hit = true;
            }
        }
        let dedupe_outcome = existing_terminal.unwrap_or(outcome);
        self.terminal.extend(record.accepted_ids.into_iter().map(|id| {
            ReviewTombstone {
                id,
                outcome: dedupe_outcome,
                expires_at_ms: completed_at_ms + REVIEW_TOMBSTONE_TTL_MS,
            }
        }));
        true
    }
}

fn accepted_id_count(records: &[ScheduledReview]) -> usize {
    records.iter().map(|record| record.accepted_ids.len()).sum()
}

fn new_uncoalesced_count(records: &[ScheduledReview], requests: &[ReviewRequest]) -> usize {
    let mut keys = records
        .iter()
        .filter(|record| record.request.mode == ReviewJobMode::Incremental)
        .map(|record| (record.request.repo.clone(), record.request.number))
        .collect::<std::collections::HashSet<_>>();
    requests
        .iter()
        .filter(|request| {
            request.mode != ReviewJobMode::Incremental
                || keys.insert((request.repo.clone(), request.number))
        })
        .count()
}

fn metadata_is_bounded(request: &ReviewRequest) -> bool {
    request.id.0.len() <= REVIEW_JOB_FIELD_LIMIT
        && request.repo.len() <= REVIEW_JOB_FIELD_LIMIT
        && request.author.len() <= REVIEW_JOB_FIELD_LIMIT
        && request
            .head_sha
            .as_ref()
            .is_none_or(|value| value.len() <= REVIEW_JOB_FIELD_LIMIT)
        && request
            .delivery
            .as_ref()
            .is_none_or(|value| value.len() <= REVIEW_JOB_FIELD_LIMIT)
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
    /// Cheaply reject manual work when the durable scheduler has no room.
    /// This is only a preflight; `admit_batch` remains authoritative and atomic.
    async fn has_capacity_for(&self, count: usize) -> Result<bool>;

    /// Atomically admit all requests or none, deduping against unfinished and
    /// unexpired terminal IDs in the same scheduler document.
    async fn admit_batch(&self, requests: Vec<ReviewRequest>) -> Result<Admission>;

    /// Claim one eligible request if fewer than four are running globally.
    /// The implementation must never take an unexpired foreign owner.
    async fn claim_next(&self, owner: &str, now_ms: i64) -> Result<Option<OwnedReview>>;

    /// Consume a paid attempt, retaining exhausted work until its owner concludes status.
    async fn begin_paid(&self, owned: &OwnedReview, now_ms: i64) -> Result<PaidStart>;

    /// Confirm the live head fetched from Forge after the review gate and lease.
    async fn confirm_head(&self, owned: &OwnedReview, head_sha: &str, now_ms: i64) -> Result<bool>;

    /// Whether the confirmed head already has a terminal result.
    async fn head_is_terminal(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Extend a live claim. A stale generation can never renew another
    /// process's job.
    async fn renew(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Verify the claim is still current and unexpired before paid work or
    /// publication.
    async fn owns(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Check ownership and the durable cooperative-yield flag before model
    /// dispatch. False means this owner must stop and return its job to pending.
    async fn should_continue(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Return an owned request to pending state, optionally with backoff.
    /// The owner and generation must fence this update.
    async fn defer(&self, owned: &OwnedReview, now_ms: i64, not_before_ms: i64) -> Result<bool>;

    /// Release a live owner only after it has observed an advisory yield.
    async fn defer_yield(&self, owned: &OwnedReview, now_ms: i64) -> Result<bool>;

    /// Finish an owned request and retain a bounded dedupe tombstone.
    /// The owner and generation must fence this update.
    async fn finish(
        &self,
        owned: &OwnedReview,
        outcome: TerminalOutcome,
        now_ms: i64,
        completed_at_ms: i64,
    ) -> Result<bool>;

    /// Finish a deadline outcome and persist the confirmed-head no-retry marker.
    async fn finish_deadline(
        &self,
        owned: &OwnedReview,
        now_ms: i64,
    ) -> Result<bool>;
}

#[cfg(test)]
#[path = "review_job_test.rs"]
pub(crate) mod tests;
