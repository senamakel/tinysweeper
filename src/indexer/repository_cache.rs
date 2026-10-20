//! A server-owned checkout cache shared by indexing and reviews.
//!
//! The stable path is selected by the server and is deliberately separate
//! from pull-request input. Repository identifiers must be canonical before
//! they are used as cache keys; remote URLs and credentials remain per-call
//! inputs to the hardened Git runner and are never persisted in the cache.
//!
//! A cache implementation must serialize operations for one repository,
//! fetch and verify the requested immutable commit before checking it out, and
//! keep each review's worktree disposable. Cancellation may drop a checkout
//! while Git is running, so subprocesses must remain kill-on-drop and stale
//! worktree registrations must be pruned before reuse. Submodule objects are
//! separate repositories: they are fetched only after a changed gitlink or an
//! actual lane read requires them, under the same host and allowlist checks as
//! the existing `Checkout` path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::Result;
use crate::indexer::fetch::Checkout;

/// Shared entry point for repository checkouts used by indexing and reviews.
///
/// This initial scaffold keeps the existing transport and disposable checkout
/// behavior while the cache tests pin down object reuse. The server wiring and
/// cached worktree implementation are added in the following slice.
#[derive(Debug, Clone)]
pub struct RepositoryCache {
    root: PathBuf,
    locks: Arc<Mutex<std::collections::HashMap<PathBuf, Weak<AsyncMutex<()>>>>>,
}

impl RepositoryCache {
    /// Use `root` for this process's per-repository object mirrors.
    ///
    /// The directory is created with owner-only permissions on Unix. The path
    /// is supplied by trusted startup configuration, never repository config.
    pub fn at(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|err| {
            crate::error::Error::Forge(format!("could not create repository cache: {err}"))
        })?;
        if std::fs::symlink_metadata(&root)
            .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
        {
            return Err(crate::error::Error::config(
                "repository cache root must be a real directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(
                |err| {
                    crate::error::Error::Forge(format!("could not protect repository cache: {err}"))
                },
            )?;
        }
        Ok(Self {
            root,
            locks: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Resolve the trusted cache root from `TINYSWEEPER_REPOSITORY_CACHE_DIR`
    /// or the current user's private cache directory.
    pub fn from_env() -> Result<Self> {
        let configured = std::env::var_os("TINYSWEEPER_REPOSITORY_CACHE_DIR");
        let home = std::env::var_os("HOME");
        let root = cache_root(configured, home)?;
        Self::at(root)
    }

    /// The server-selected directory holding repository mirrors.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Check out one immutable commit for an indexing or review read.
    ///
    /// Kept as a passthrough in the test-first scaffold; the regression below
    /// demonstrates the duplicate network fetch that the cache must remove.
    pub async fn checkout(
        &self,
        host: &str,
        repo: &str,
        revision: &str,
        token: &str,
    ) -> Result<Checkout> {
        let url = format!("https://{host}/{repo}.git");
        self.checkout_from_url_locked(repo, revision, &url, token, None)
            .await
    }

    #[cfg(test)]
    async fn checkout_from_url(
        &self,
        repo: &str,
        revision: &str,
        url: &str,
        token: &str,
        fetch_count: &std::sync::atomic::AtomicUsize,
    ) -> Result<Checkout> {
        self.checkout_from_url_locked(repo, revision, url, token, Some(fetch_count))
            .await
    }

    async fn checkout_from_url_locked(
        &self,
        repo: &str,
        revision: &str,
        url: &str,
        token: &str,
        fetch_count: Option<&std::sync::atomic::AtomicUsize>,
    ) -> Result<Checkout> {
        validate_repo(repo)?;
        let mirror = self.mirror_path(repo)?;
        let lock = self.lock_for(&mirror);
        let _guard = lock.lock().await;
        if !crate::indexer::fetch::Checkout::mirror_has_revision(&mirror, revision).await? {
            if let Some(parent) = mirror.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    crate::error::Error::Forge(format!("could not create cache owner path: {err}"))
                })?;
                protect_directory(parent)?;
            }
            std::fs::create_dir_all(&mirror).map_err(|err| {
                crate::error::Error::Forge(format!("could not create repository mirror: {err}"))
            })?;
            protect_directory(&mirror)?;
            Checkout::fetch_into_mirror(&mirror, url, revision, token, fetch_count).await?;
        }
        let checkout = Checkout::from_mirror(&mirror, revision).await?;
        drop(_guard);
        Ok(checkout)
    }

    fn mirror_path(&self, repo: &str) -> Result<PathBuf> {
        let (owner, name) = repo.split_once('/').expect("validated owner/name");
        Ok(self.root.join(owner).join(format!("{name}.git")))
    }

    fn lock_for(&self, path: &Path) -> Arc<AsyncMutex<()>> {
        let mut locks = self.locks.lock().expect("repository cache lock map");
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
        lock
    }
}

fn validate_repo(repo: &str) -> Result<()> {
    let Some((owner, name)) = repo.split_once('/') else {
        return Err(crate::error::Error::config(format!("`{repo}` is not owner/name")));
    };
    let component = |value: &str| {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if repo.starts_with('-') || !component(owner) || !component(name) || name.ends_with(".git") {
        return Err(crate::error::Error::config(format!("`{repo}` is not owner/name")));
    }
    Ok(())
}

fn protect_directory(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(crate::error::Error::config(
            "repository cache path contains a symlink or non-directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
            crate::error::Error::Forge(format!("could not protect repository cache path: {err}"))
        })?;
    }
    Ok(())
}

fn cache_root(configured: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    if let Some(configured) = configured.filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(configured));
    }
    let home = home.filter(|path| !path.is_empty()).ok_or_else(|| {
        crate::error::Error::config(
            "HOME or TINYSWEEPER_REPOSITORY_CACHE_DIR must be set for repository caching",
        )
    })?;
    Ok(PathBuf::from(home)
        .join(".cache")
        .join("tinysweeper")
        .join("repositories"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn git(args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .output()
            .expect("run fixture Git command");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn local_bare_repository(root: &Path) -> (PathBuf, String) {
        let source = root.join("source");
        let bare = root.join("owner-repo.git");
        std::fs::create_dir_all(&source).expect("create fixture repository");
        git(&["init", "--quiet", source.to_str().unwrap()]);
        std::fs::write(source.join("README.md"), "fixture head\n").expect("write fixture tree");
        git(&["-C", source.to_str().unwrap(), "add", "README.md"]);
        git(&[
            "-C",
            source.to_str().unwrap(),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture head",
        ]);
        let revision = git(&["-C", source.to_str().unwrap(), "rev-parse", "HEAD"]);
        git(&[
            "clone",
            "--quiet",
            "--bare",
            source.to_str().unwrap(),
            bare.to_str().unwrap(),
        ]);
        (bare, revision)
    }

    #[tokio::test]
    async fn two_reviews_of_the_same_repository_fetch_shared_objects_once() {
        let fixture = tempfile::tempdir().expect("fixture directory");
        let (remote, revision) = local_bare_repository(fixture.path());
        let cache = RepositoryCache::at(fixture.path().join("cache")).expect("cache root");
        let remote = remote.to_str().unwrap();
        let fetches = AtomicUsize::new(0);

        let first = cache
            .checkout_from_url("acme/widgets", &revision, remote, "", &fetches)
            .await
            .expect("first review checkout");
        let second = cache
            .checkout_from_url("acme/widgets", &revision, remote, "", &fetches)
            .await
            .expect("second review checkout");

        assert_eq!(first.revision(), revision);
        assert_eq!(second.revision(), revision);
        assert_eq!(
            std::fs::read(first.path().join("README.md")).unwrap(),
            b"fixture head\n"
        );
        assert_eq!(
            std::fs::read(second.path().join("README.md")).unwrap(),
            b"fixture head\n"
        );
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "the production Git fetch command should contact the local bare remote once"
        );
    }

    #[tokio::test]
    async fn concurrent_reviews_of_the_same_repository_share_one_fetch() {
        let fixture = tempfile::tempdir().expect("fixture directory");
        let (remote, revision) = local_bare_repository(fixture.path());
        let cache = RepositoryCache::at(fixture.path().join("cache")).expect("cache root");
        let remote = remote.to_str().unwrap();
        let fetches = AtomicUsize::new(0);

        let (first, second) = tokio::join!(
            cache.checkout_from_url("acme/widgets", &revision, remote, "", &fetches),
            cache.checkout_from_url("acme/widgets", &revision, remote, "", &fetches),
        );
        let first = first.expect("first concurrent review checkout");
        let second = second.expect("second concurrent review checkout");

        assert_eq!(first.revision(), revision);
        assert_eq!(second.revision(), revision);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_root_override_wins_and_empty_override_uses_the_private_user_cache() {
        assert_eq!(
            cache_root(
                Some("/var/cache/tinysweeper".into()),
                Some("/home/test".into())
            )
            .unwrap(),
            PathBuf::from("/var/cache/tinysweeper")
        );
        assert_eq!(
            cache_root(Some("".into()), Some("/home/test".into())).unwrap(),
            PathBuf::from("/home/test/.cache/tinysweeper/repositories")
        );
        assert!(cache_root(None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_root_is_private_to_the_server_user() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("cache");
        RepositoryCache::at(&root).expect("cache root");
        assert_eq!(
            std::fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
