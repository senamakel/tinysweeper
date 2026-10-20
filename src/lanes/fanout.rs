//! Fan-out: one conversation per unit of review, bounded and isolated.
//!
//! A lane that reviews a forty-file pull request in one conversation reviews
//! the first few files carefully and the rest as an afterthought. Splitting it
//! fixes that, and buys two more things:
//!
//! - **Isolation of failure.** One unit's model call failing must not fail the
//!   lane. The rest are still reviewed and the failure is counted into the
//!   summary, where a human can see it — a lane that returns nothing because
//!   one call timed out is a lane that quietly reports "all clear".
//! - **Isolation of subject.** Each conversation is told exactly which files it
//!   owns (see `isolation_clause` in `harness::prompt`). Without that, every
//!   one of the N reviewers notices the same cross-file problem and reports it.
//!
//! The unit is one file for `security`; for `critique` it is one
//! [`crate::lanes::grouping::FileGroup`] — a handful of related changed files
//! reviewed together so a bug spanning them is visible to one reviewer instead
//! of hidden between two isolated ones. [`per_unit`] is generic over which;
//! [`per_file`] is the plain-path convenience both lanes used before grouping
//! existed, kept because `security` and every test predating grouping still
//! read most naturally as "one file, one conversation".
//!
//! The concurrency cap is the third thing. Each call is a model call, and an
//! unbounded fan-out over a large pull request is an unbounded bill and a rate
//! limit at the same time.

use std::future::Future;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::error::Error;
use crate::findings::types::Finding;
use crate::lanes::LaneOutcome;
use crate::ports::model::Spend;

/// How many files a lane reviews at once.
///
/// Matches open-code-review's cap. The number is about spend and provider rate
/// limits, not CPU: these tasks are almost entirely waiting on a model.
pub const MAX_CONCURRENT_FILES: usize = 8;

/// What reviewing one file produced.
#[derive(Debug, Clone, Default)]
pub struct FileReview {
    /// The file's own one-line verdict.
    pub summary: String,
    /// Its findings, already anchored and filtered.
    pub findings: Vec<Finding>,
    /// Earlier findings this file's revision fixed.
    pub resolved: Vec<String>,
    /// What the call cost, and which model answered.
    pub spend: Spend,
}

/// Why a prepared group did not receive a model review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    /// The global Large-review plan left this group outside its selected set.
    NotSelected,
    /// The original absolute soft deadline stopped new group work.
    SoftDeadline,
    /// The bounded drain ended before this in-flight group returned.
    DrainDeadline,
    /// The shared physical-call ceiling refused a call in this group.
    CallLimit,
    /// The review owner cancelled the active execution scope.
    Cancelled,
}

impl OmissionReason {
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::NotSelected => "not selected by the large-review budget",
            Self::SoftDeadline => "not started before the soft deadline",
            Self::DrainDeadline => "did not finish before the drain deadline",
            Self::CallLimit => "stopped at the physical-call limit",
            Self::Cancelled => "cancelled with the owning review",
        }
    }
}

/// A planned group omitted without claiming that a provider failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedGroup {
    /// Every file whose group received no complete review answer.
    pub paths: Vec<String>,
    /// Host-side reason the group was omitted.
    pub reason: OmissionReason,
}

/// Review `units` concurrently, at most [`MAX_CONCURRENT_FILES`] at a time.
///
/// `T` is one changed file for `security`, and one [`crate::lanes::grouping::FileGroup`]
/// for `critique` — either way, one item is one conversation and `label`
/// names what goes in the failure list and the summary. `member_paths` gives
/// the individual file paths one unit stands for, so a multi-file group's
/// success or failure is still counted and named file-by-file downstream
/// rather than collapsed into one synthetic entry per conversation. Failures
/// are collected rather than propagated: see the module doc.
pub async fn per_unit<T, F, Fut>(
    units: &[T],
    label: impl Fn(&T) -> String,
    member_paths: impl Fn(&T) -> Vec<String>,
    review: F,
) -> FanOut
where
    T: Clone + Send + 'static,
    F: Fn(T) -> Fut,
    Fut: Future<Output = crate::error::Result<FileReview>>,
{
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_FILES));

    // The future is built eagerly but polled only after a permit is held, so
    // the cap bounds work in flight rather than merely futures allocated.
    let tasks = units.iter().cloned().map(|unit| {
        let permits = permits.clone();
        let name = label(&unit);
        let paths = member_paths(&unit);
        let task = review(unit);
        async move {
            let _permit = permits
                .acquire_owned()
                .await
                .expect("the permit pool is never closed");
            (name, paths, task.await)
        }
    });

    let mut out = FanOut::default();
    for (name, paths, result) in futures::future::join_all(tasks).await {
        match result {
            Ok(review) => out.reviews.push((paths, review)),
            Err(err) => out.failures.push((name, paths, err)),
        }
    }
    out
}

/// [`per_unit`] over plain paths, where the label and the sole member path
/// are both the path itself.
///
/// The common case — `security`, and `critique` before grouping — kept as its
/// own name so a call site reads as "one file, one conversation" rather than
/// spelling out an identity label closure every time.
pub async fn per_file<F, Fut>(paths: &[String], review: F) -> FanOut
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = crate::error::Result<FileReview>>,
{
    per_unit(paths, String::clone, |path| vec![path.clone()], review).await
}

/// The results of a fan-out, successes and failures kept apart.
///
/// Each entry carries the individual file paths its unit stood for, so a
/// multi-file [`crate::lanes::grouping::FileGroup`] contributes one entry per
/// member file to the counts and lists `into_outcome` builds, not one per
/// conversation.
#[derive(Debug, Default)]
pub struct FanOut {
    /// One entry per unit that was reviewed: its member file paths, and the
    /// review produced for the whole unit.
    pub reviews: Vec<(Vec<String>, FileReview)>,
    /// The units whose review failed: the unit's label, its member file
    /// paths, and why.
    pub failures: Vec<(String, Vec<String>, Error)>,
    /// Groups the host did not review, kept distinct from provider failures.
    pub omitted: Vec<OmittedGroup>,
}

impl FanOut {
    /// Fold the per-file results into one lane outcome.
    ///
    /// The summary reports the failures explicitly. A partial review that reads
    /// like a complete one is worse than no review at all, because a human
    /// stops looking.
    pub fn into_outcome(self) -> LaneOutcome {
        // A multi-file group is one conversation but several files: counted
        // and named per member path here, so "Reviewed N files" and the
        // unanswered list stay file-accurate rather than reporting one
        // synthetic entry per conversation.
        let completed = !self.reviews.is_empty();
        let reviewed: usize = self.reviews.iter().map(|(paths, _)| paths.len()).sum();
        let one_conversation = self.reviews.len() == 1;
        let mut reviewed_paths = Vec::with_capacity(reviewed);
        let mut findings = Vec::new();
        let mut resolved = Vec::new();
        let mut spend = Spend::default();
        let mut only_summary = None;

        for (paths, review) in self.reviews {
            reviewed_paths.extend(paths);
            spend.merge(review.spend);
            findings.extend(review.findings);
            resolved.extend(review.resolved);
            // A lone unit's own sentence stands in for the count whether it
            // covered one file or a whole group: it is the one verdict this
            // fan-out reached, and reads better than a bare tally.
            only_summary = Some(review.summary);
        }

        // One conversation is the common case for a small pull request or a
        // single group, and its own sentence says more than a count would.
        let mut summary = match (one_conversation, only_summary) {
            (true, Some(single)) if !single.trim().is_empty() => single.trim().to_string(),
            _ => format!(
                "Reviewed {reviewed} file{}; {} finding{}.",
                plural(reviewed),
                findings.len(),
                plural(findings.len())
            ),
        };

        // Every path behind a failed unit, not one synthetic entry per
        // conversation: a failed two-file group must count and name both.
        let mut unanswered: Vec<String> = self
            .failures
            .iter()
            .flat_map(|(_, paths, _)| paths.iter().cloned())
            .collect();
        unanswered.extend(
            self.omitted
                .iter()
                .flat_map(|omitted| omitted.paths.iter().cloned()),
        );

        if !unanswered.is_empty() {
            let total = reviewed + unanswered.len();
            summary = format!(
                "Reviewed {reviewed} of {total} files — {} not reviewed. {summary}",
                unanswered.len()
            );
        }

        if !self.failures.is_empty() {
            summary.push_str(&format!(
                " {} file{} could not be reviewed: {}.",
                unanswered.len(),
                plural(unanswered.len()),
                unanswered.join(", ")
            ));
        }

        if !self.omitted.is_empty() {
            let omitted_count: usize = self.omitted.iter().map(|group| group.paths.len()).sum();
            let reasons = self
                .omitted
                .iter()
                .map(|group| group.reason.description())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            summary.push_str(&format!(
                " {omitted_count} file{} were omitted: {reasons}.",
                plural(omitted_count)
            ));
        }

        let skipped = (reviewed == 0 && (!self.failures.is_empty() || !self.omitted.is_empty()))
            .then(|| {
                "No files received a complete review; see the listed failures and omissions."
                    .to_string()
            });
        let coverage = (!reviewed_paths.is_empty() || !unanswered.is_empty()).then_some(
            crate::lanes::FileCoverage {
                reviewed: reviewed_paths,
                unanswered: unanswered.clone(),
            },
        );
        LaneOutcome {
            summary,
            context_degraded: false,
            completed,
            findings,
            resolved,
            spend,
            skipped,
            pending: Vec::new(),
            unanswered,
            coverage,
            omissions: self.omitted,
        }
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn review_of(summary: &str) -> FileReview {
        FileReview {
            summary: summary.to_string(),
            ..FileReview::default()
        }
    }

    #[tokio::test]
    async fn every_path_is_reviewed() {
        let paths = vec!["a.rs".to_string(), "b.rs".into(), "c.rs".into()];
        let out = per_file(&paths, |path| async move { Ok(review_of(&path)) }).await;

        assert_eq!(out.reviews.len(), 3);
        assert!(out.failures.is_empty());
    }

    #[tokio::test]
    async fn one_files_failure_does_not_fail_the_lane() {
        let paths = vec!["good.rs".to_string(), "bad.rs".into()];
        let out = per_file(&paths, |path| async move {
            if path == "bad.rs" {
                Err(Error::Model("upstream exploded".into()))
            } else {
                Ok(review_of(&path))
            }
        })
        .await;

        assert_eq!(out.reviews.len(), 1);
        assert_eq!(out.failures.len(), 1);

        let outcome = out.into_outcome();
        assert!(outcome.skipped.is_none());
        assert!(
            outcome.summary.contains("bad.rs"),
            "a partial review must say so: {}",
            outcome.summary
        );
        assert_eq!(
            outcome.unanswered,
            vec!["bad.rs".to_string()],
            "the file nobody answered for is named, so the verdict cannot vouch for it"
        );
    }

    #[tokio::test]
    async fn every_failure_makes_the_lane_neutral() {
        let paths = vec!["bad.rs".to_string()];
        let outcome = per_file(&paths, |_| async { Err(Error::Model("nope".into())) })
            .await
            .into_outcome();

        assert!(outcome.skipped.is_some());
        assert_eq!(outcome.unanswered, vec!["bad.rs".to_string()]);
    }

    #[test]
    fn omitted_multifile_groups_keep_every_path_and_host_reason() {
        let outcome = FanOut {
            omitted: vec![OmittedGroup {
                paths: vec!["src/a.rs".into(), "src/a_test.rs".into()],
                reason: OmissionReason::SoftDeadline,
            }],
            ..FanOut::default()
        }
        .into_outcome();

        assert!(!outcome.completed);
        assert!(outcome.skipped.is_some());
        assert_eq!(
            outcome.unanswered,
            ["src/a.rs".to_string(), "src/a_test.rs".to_string()]
        );
        assert_eq!(
            outcome
                .coverage
                .expect("coverage records omissions")
                .unanswered,
            ["src/a.rs".to_string(), "src/a_test.rs".to_string()]
        );
        assert_eq!(outcome.omissions[0].reason, OmissionReason::SoftDeadline);
        assert!(
            outcome
                .summary
                .contains("not started before the soft deadline")
        );
    }

    #[tokio::test]
    async fn a_multi_file_groups_success_counts_every_member_file() {
        // Two two-file groups: the fan-out ran two conversations, but the
        // outcome must report four files reviewed, not two conversations.
        let groups = vec![
            vec!["a.rs".to_string(), "b.rs".to_string()],
            vec!["c.rs".to_string(), "d.rs".to_string()],
        ];
        let outcome = per_unit(
            &groups,
            |g| g.join(" + "),
            |g| g.clone(),
            |g| async move { Ok(review_of(&format!("Reviewed {}.", g.join(" + ")))) },
        )
        .await
        .into_outcome();

        assert!(
            outcome.summary.starts_with("Reviewed 4 files"),
            "{}",
            outcome.summary
        );
    }

    #[tokio::test]
    async fn a_failed_multi_file_group_names_every_member_file_as_unanswered() {
        let groups = vec![vec!["a.rs".to_string(), "b.rs".to_string()]];
        let outcome = per_unit(
            &groups,
            |g| g.join(" + "),
            |g| g.clone(),
            |_| async { Err(Error::Model("upstream exploded".into())) },
        )
        .await
        .into_outcome();

        assert_eq!(
            outcome.unanswered,
            vec!["a.rs".to_string(), "b.rs".to_string()],
            "a failed two-file group must name both files, not one synthetic label"
        );
        assert!(
            outcome
                .summary
                .contains("2 files could not be reviewed: a.rs, b.rs"),
            "{}",
            outcome.summary
        );
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        // A lane fanning out over a large pull request with no cap is an
        // unbounded bill and a provider rate limit at the same time.
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let paths: Vec<String> = (0..MAX_CONCURRENT_FILES * 3)
            .map(|i| format!("f{i}.rs"))
            .collect();

        let out = per_file(&paths, |path| {
            let live = live.clone();
            let peak = peak.clone();
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                live.fetch_sub(1, Ordering::SeqCst);
                Ok(review_of(&path))
            }
        })
        .await;

        assert_eq!(out.reviews.len(), paths.len());
        assert!(
            peak.load(Ordering::SeqCst) <= MAX_CONCURRENT_FILES,
            "peaked at {}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn a_single_file_keeps_its_own_verdict() {
        let paths = vec!["only.rs".to_string()];
        let outcome = per_file(&paths, |_| async { Ok(review_of("Looks fine.")) })
            .await
            .into_outcome();

        assert_eq!(outcome.summary, "Looks fine.");
    }

    #[tokio::test]
    async fn several_files_are_summarised_by_count() {
        let paths = vec!["a.rs".to_string(), "b.rs".into()];
        let outcome = per_file(&paths, |p| async move { Ok(review_of(&p)) })
            .await
            .into_outcome();

        assert!(outcome.summary.starts_with("Reviewed 2 files"));
    }
}
