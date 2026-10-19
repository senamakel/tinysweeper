//! Pure size estimates and deterministic candidate planning for large reviews.
//!
//! This module has no model or forge dependency. It receives the complete
//! bounded diffstat and the already-prepared critique/security candidate
//! groups, so callers can decide the review shape before paid work begins.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::config::types::{Config, LaneId, LargePr};
use crate::evidence::diff::FileDiff;
use crate::forge::types::ChangedFile;
use crate::lanes::grouping::FileGroup;

/// Whether a review follows the ordinary or large-pull-request policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    /// Preserve the existing review policy and candidate order.
    Normal,
    /// Bound the candidate set and use one review pass.
    Large,
}

/// Host-derived size of one pull request and its eligible model work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewEstimate {
    /// Changed files reported by the forge, including missing patches.
    pub files: usize,
    /// Added plus deleted lines reported by the complete diffstat.
    pub changed_lines: u64,
    /// Eligible critique and security groups after deterministic preparation.
    pub groups: usize,
}

/// A candidate group and the host-derived risk used to order it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedGroup {
    /// Lane that owns the group's coverage and findings.
    pub lane: LaneId,
    /// Bounded related-file group passed to one lane conversation.
    pub group: FileGroup,
    /// Highest member risk, computed from host evidence only.
    pub risk: RiskScore,
}

/// One deterministic review plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPlan {
    /// Mode selected from size and candidate count.
    pub mode: ReviewMode,
    /// Complete diffstat and eligible-group estimate.
    pub estimate: ReviewEstimate,
    /// Groups selected for review.
    pub selected: Vec<PlannedGroup>,
    /// Candidate paths left out, grouped by the lane whose coverage is partial.
    pub omitted: BTreeMap<LaneId, Vec<String>>,
}

/// Risk ordering for one changed file or the highest-risk member of a group.
///
/// Fields are compared lexicographically from scanner evidence down to capped
/// file size. The planner uses descending risk, then ascending path, then
/// security before critique when scores tie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RiskScore {
    /// A deterministic scanner finding names this path.
    pub scanner: bool,
    /// A prior posted finding anchors to this path.
    pub prior_finding: bool,
    /// A sensitive path or dangerous sink is present.
    pub sensitive: bool,
    /// The diff changes a public API surface.
    pub public_api: bool,
    /// Added plus deleted lines, capped at 1,000 for ordering.
    pub changed_lines: u16,
}

impl Ord for RiskScore {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.scanner,
            self.prior_finding,
            self.sensitive,
            self.public_api,
            self.changed_lines,
        )
            .cmp(&(
                other.scanner,
                other.prior_finding,
                other.sensitive,
                other.public_api,
                other.changed_lines,
            ))
    }
}

impl PartialOrd for RiskScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Estimate and rank prepared candidate groups before any paid model call.
///
/// `changed_files` must be the complete, bounded forge result rather than the
/// subset with parseable patches. `diffs` is accepted for the eventual
/// host-derived risk calculation; candidate preparation must still come from
/// the same lane helpers that execution uses.
pub fn plan(
    config: &Config,
    changed_files: &[ChangedFile],
    _diffs: &[FileDiff],
    mut candidates: Vec<PlannedGroup>,
) -> ReviewPlan {
    let estimate = ReviewEstimate {
        files: changed_files.len(),
        changed_lines: changed_files.iter().fold(0u64, |total, file| {
            total.saturating_add(file.additions).saturating_add(file.deletions)
        }),
        groups: candidates.len(),
    };
    let policy: &LargePr = &config.review.large_pr;
    let mode = if policy.enabled
        && (estimate.files >= policy.files
            || estimate.changed_lines >= policy.changed_lines
            || estimate.groups >= policy.groups)
    {
        ReviewMode::Large
    } else {
        ReviewMode::Normal
    };

    if mode == ReviewMode::Large {
        candidates.sort_by(|left, right| {
            right
                .risk
                .cmp(&left.risk)
                .then_with(|| left.group.label.cmp(&right.group.label))
                .then_with(|| lane_order(left.lane).cmp(&lane_order(right.lane)))
        });
    }

    // Source-preparation scaffold: keep every eligible group until the
    // selected-set behavior has been compiled and observed red.
    ReviewPlan {
        mode,
        estimate,
        selected: candidates,
        omitted: BTreeMap::new(),
    }
}

fn lane_order(lane: LaneId) -> u8 {
    match lane {
        LaneId::Security => 0,
        LaneId::Critique => 1,
        _ => u8::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(count: usize) -> Vec<PlannedGroup> {
        (0..count)
            .map(|index| PlannedGroup {
                lane: if index % 2 == 0 {
                    LaneId::Critique
                } else {
                    LaneId::Security
                },
                group: FileGroup {
                    label: format!("src/file_{index:02}.rs"),
                    paths: vec![format!("src/file_{index:02}.rs")],
                },
                risk: RiskScore {
                    public_api: true,
                    ..RiskScore::default()
                },
            })
            .collect()
    }

    #[test]
    fn normal_mode_preserves_every_candidate_in_input_order() {
        let config = Config::default();
        let files = [ChangedFile::default()];
        let plan = plan(&config, &files, &[], candidates(2));

        assert_eq!(plan.mode, ReviewMode::Normal);
        assert_eq!(plan.selected.len(), 2);
        assert_eq!(plan.selected[0].group.label, "src/file_00.rs");
        assert!(plan.omitted.is_empty());
    }

    #[test]
    fn large_plan_estimates_full_diffstat_and_selects_twelve_groups_across_lanes() {
        let config = Config::default();
        let files: Vec<_> = (0..60)
            .map(|index| ChangedFile {
                path: format!("src/file_{index:02}.rs"),
                additions: 1,
                deletions: 1,
                patch: (index != 59).then_some("untrusted patch text".into()),
                ..ChangedFile::default()
            })
            .collect();
        let plan = plan(&config, &files, &[], candidates(60));

        assert_eq!(plan.mode, ReviewMode::Large);
        assert_eq!(plan.estimate.files, 60);
        assert_eq!(plan.estimate.changed_lines, 120);
        assert_eq!(plan.estimate.groups, 60);
        assert_eq!(plan.selected.len(), 12);
        assert_eq!(plan.omitted.values().map(Vec::len).sum::<usize>(), 48);
    }

    #[test]
    fn disabled_large_mode_keeps_normal_group_order() {
        let mut config = Config::default();
        config.review.large_pr.enabled = false;
        let files: Vec<_> = (0..60).map(|_| ChangedFile::default()).collect();
        let mut groups = candidates(2);
        groups[0].risk.scanner = true;
        let plan = plan(&config, &files, &[], groups);

        assert_eq!(plan.mode, ReviewMode::Normal);
        assert_eq!(plan.selected[0].group.label, "src/file_00.rs");
    }
}
