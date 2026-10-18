//! Always-offline implementation used to exercise accepted-job recovery.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::{ReviewJob, ReviewJobId, ReviewJobStore};
use crate::error::{Error, Result};

#[derive(Default)]
pub(crate) struct MockReviewJobStore {
    jobs: Mutex<HashMap<ReviewJobId, ReviewJob>>,
    batches: Mutex<HashSet<String>>,
    fail_batch: Mutex<bool>,
    released_leases: Mutex<Vec<ReviewJobId>>,
}

impl MockReviewJobStore {
    pub(crate) fn fail_next_batch(&self) {
        *self.fail_batch.lock().expect("batch failure") = true;
    }

    pub(crate) fn rows(&self) -> Vec<ReviewJob> {
        self.jobs.lock().expect("jobs").values().cloned().collect()
    }

    pub(crate) fn released_leases(&self) -> Vec<ReviewJobId> {
        self.released_leases.lock().expect("leases").clone()
    }
}

#[async_trait::async_trait]
impl ReviewJobStore for MockReviewJobStore {
    async fn enqueue(&self, job: ReviewJob) -> Result<bool> {
        let mut jobs = self.jobs.lock().expect("jobs");
        if jobs.contains_key(&job.id) {
            return Ok(false);
        }
        jobs.insert(job.id.clone(), job);
        Ok(true)
    }

    async fn enqueue_manual_batch(&self, batch_id: &str, jobs: Vec<ReviewJob>) -> Result<()> {
        if std::mem::take(&mut *self.fail_batch.lock().expect("batch failure")) {
            return Err(Error::Forge("simulated batch persistence failure".into()));
        }
        let mut stored = self.jobs.lock().expect("jobs");
        let ids = jobs.iter().map(|job| job.id.clone()).collect::<HashSet<_>>();
        if ids.len() != jobs.len() || ids.iter().any(|id| stored.contains_key(id)) {
            return Err(Error::Forge("duplicate manual review job id".into()));
        }
        stored.extend(jobs.into_iter().map(|job| (job.id.clone(), job)));
        self.batches
            .lock()
            .expect("batches")
            .insert(batch_id.to_owned());
        Ok(())
    }

    async fn recover(&self, limit: usize) -> Result<Vec<ReviewJob>> {
        let batches = self.batches.lock().expect("batches").clone();
        let mut jobs = self
            .jobs
            .lock()
            .expect("jobs")
            .values()
            .filter(|job| {
                !job
                    .id
                    .0
                    .split_once(':')
                    .is_some_and(|(kind, batch)| kind == "manual" && !batches.contains(batch))
            })
            .cloned()
            .collect::<Vec<_>>();
        jobs.sort_by_key(|job| job.accepted_at_ms);
        jobs.truncate(limit);
        Ok(jobs)
    }

    async fn mark_running(&self, _id: &ReviewJobId) -> Result<()> {
        Ok(())
    }

    async fn mark_pending(&self, _id: &ReviewJobId) -> Result<()> {
        Ok(())
    }

    async fn complete(&self, id: &ReviewJobId) -> Result<()> {
        self.jobs.lock().expect("jobs").remove(id);
        Ok(())
    }

    async fn release_stale_lease(&self, id: &ReviewJobId) -> Result<()> {
        self.released_leases
            .lock()
            .expect("leases")
            .push(id.clone());
        Ok(())
    }
}
