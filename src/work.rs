//! Detached work: tasks that run to their end even when the request that started them is
//! dropped, are tracked so shutdown can wait for them, and are refused once shutdown begins.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

/// Returned instead of starting work once shutdown has begun.
#[derive(Debug)]
pub struct ShuttingDown;

impl fmt::Display for ShuttingDown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server is shutting down, try again in a minute")
    }
}

impl std::error::Error for ShuttingDown {}

/// The slot a connection holds out of the server's connection cap. Every detached task a
/// request starts holds a clone, so a request dropped by its client keeps the slot until its
/// work is done and floods cannot pile up unbounded work behind the cap. Requests that
/// do not come through the server's accept loop carry no permit.
#[derive(Clone, Default)]
pub struct ConnPermit(pub Option<Arc<OwnedSemaphorePermit>>);

impl<S: Send + Sync> FromRequestParts<S> for ConnPermit {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<ConnPermit, Infallible> {
        Ok(parts
            .extensions
            .get::<ConnPermit>()
            .cloned()
            .unwrap_or_default())
    }
}

/// The one place detached work starts: every task runs to its end even when its
/// request is dropped, is tracked so shutdown can wait for it, and is refused once shutdown
/// has begun.
pub struct Work {
    tracker: TaskTracker,
    shutting_down: AtomicBool,
    live: AtomicUsize,
    peak: AtomicUsize,
}

/// Counts a detached task while it lives.
struct Live(Arc<Work>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Work {
    /// A `Work` that spawns onto `tracker`.
    pub fn new(tracker: TaskTracker) -> Arc<Work> {
        Arc::new(Work {
            tracker,
            shutting_down: AtomicBool::new(false),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }

    /// The tracker shutdown waits on.
    pub fn tracker(&self) -> &TaskTracker {
        &self.tracker
    }

    /// Refuses every new task from now on.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Whether [`Work::begin_shutdown`] has been called.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// How many detached tasks are running now.
    pub fn live_tasks(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// The most detached tasks there have been at once.
    pub fn peak_tasks(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    /// Starts a tracked task, or refuses once shutdown has begun. `TaskTracker::close` alone
    /// does not stop new spawns, so the flag does.
    pub fn spawn<F>(self: &Arc<Work>, work: F) -> Result<JoinHandle<F::Output>, ShuttingDown>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        if self.is_shutting_down() {
            return Err(ShuttingDown);
        }

        let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        let live = Live(self.clone());

        self.peak.fetch_max(now, Ordering::SeqCst);

        Ok(self.tracker.spawn(async move {
            let _live = live;

            work.await
        }))
    }

    /// Runs `work` as detached work holding the request's connection slot, and waits for it.
    /// The wait is all a dropped request gives up; the work still runs to its end.
    pub async fn run_detached<F>(
        self: &Arc<Work>,
        permit: ConnPermit,
        work: F,
    ) -> Result<F::Output, ShuttingDown>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = self.spawn(async move {
            let _slot = permit;

            work.await
        })?;

        Ok(handle.await.expect("detached work panicked"))
    }
}
