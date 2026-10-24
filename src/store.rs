//! The server state in one JSON file shared by the running server and the CLI commands.
//!
//! The file holds the service's own section under [`Section::KEY`], then `owner`, `clients`
//! and `tokens`, then any key this crate does not know. Unknown keys survive every save.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::ServiceInfo;
use crate::sys;

/// The part of the state file that belongs to the service (its upstream session, its login).
///
/// It is stored under [`Section::KEY`], which must not be `owner`, `clients` or `tokens`.
pub trait Section:
    Serialize + DeserializeOwned + Default + Clone + fmt::Debug + PartialEq + Send + Sync + 'static
{
    /// The top-level key of the section in the state file.
    const KEY: &'static str;
}

const RESERVED_KEYS: [&str; 3] = ["owner", "clients", "tokens"];

/// The whole state file.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct State<S> {
    /// The service's own section.
    pub section: S,
    /// The owner's password hash.
    pub owner: OwnerState,
    /// The registered OAuth clients, by client id.
    pub clients: BTreeMap<String, Client>,
    /// The OAuth tokens, by lowercase hex SHA-256 of the raw token.
    pub tokens: BTreeMap<String, Token>,
    /// Top-level keys this crate does not know, kept as they are.
    pub extra: Map<String, Value>,
}

impl<S: Section> Serialize for State<S> {
    fn serialize<Out: Serializer>(&self, serializer: Out) -> Result<Out::Ok, Out::Error> {
        let mut map = serializer.serialize_map(Some(4 + self.extra.len()))?;

        map.serialize_entry(S::KEY, &self.section)?;
        map.serialize_entry("owner", &self.owner)?;
        map.serialize_entry("clients", &self.clients)?;
        map.serialize_entry("tokens", &self.tokens)?;

        for (key, value) in &self.extra {
            map.serialize_entry(key, value)?;
        }

        map.end()
    }
}

impl<'de, S: Section> Deserialize<'de> for State<S> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StateVisitor<S>(PhantomData<fn() -> S>);

        impl<'de, S: Section> Visitor<'de> for StateVisitor<S> {
            type Value = State<S>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the state file object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<State<S>, A::Error> {
                let mut state = State::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "owner" => state.owner = map.next_value()?,
                        "clients" => state.clients = map.next_value()?,
                        "tokens" => state.tokens = map.next_value()?,
                        _ if key == S::KEY => state.section = map.next_value()?,
                        _ => {
                            state.extra.insert(key, map.next_value()?);
                        }
                    }
                }

                Ok(state)
            }
        }

        deserializer.deserialize_map(StateVisitor(PhantomData))
    }
}

/// The owner's login to the OAuth consent page.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnerState {
    /// The bcrypt hash of the owner password; empty until `set-password` runs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
    /// Fields this crate does not know, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An OAuth client registered through dynamic client registration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    /// The id handed out at registration.
    pub client_id: String,
    /// The name the client gave itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    /// The exact redirect URIs the client may use.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// When the client registered.
    pub registered_at: Timestamp,
    /// When a token was last issued to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
    /// Fields this crate does not know, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether a token opens the MCP endpoint or renews a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// A bearer token for the MCP endpoint.
    Access,
    /// A token that is exchanged for a new pair.
    Refresh,
}

/// Stored under the lowercase hex SHA-256 of the raw token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Token {
    /// Access or refresh.
    pub kind: TokenKind,
    /// The client the token was issued to.
    pub client_id: String,
    /// The refresh chain the token belongs to; revoking a family revokes all of it.
    pub family: String,
    /// The granted scope.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// The MCP resource URL the token is bound to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource: String,
    /// When the token stops working.
    pub expires_at: Timestamp,
    /// A used refresh token kept only to detect replay.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rotated: bool,
    /// Fields this crate does not know, kept as they are.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A failed state-file operation, as a message for the operator.
#[derive(Debug)]
pub struct StoreError(String);

impl StoreError {
    fn new(message: String) -> StoreError {
        StoreError(message)
    }

    /// For callers that do their own file work next to the store, such as the lease.
    pub fn message(message: String) -> StoreError {
        StoreError(message)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// What an update closure decided: write the changed state back, or leave the file alone.
pub enum Change<T> {
    /// Write the changed state back and return the value.
    Write(T),
    /// Leave the file alone and return the value.
    Unchanged(T),
}

type RenameHook = Arc<dyn Fn(&Path, &Path) -> io::Result<()> + Send + Sync>;
type SyncHook = Arc<dyn Fn(&File) -> io::Result<()> + Send + Sync>;
type ChownHook = Arc<dyn Fn(&File, &Path, u32, u32) -> io::Result<()> + Send + Sync>;
type OwnerHook = Arc<dyn Fn(&Path) -> io::Result<(u32, u32)> + Send + Sync>;

/// The file-system calls a test needs to fail, stall or observe.
#[derive(Clone)]
pub struct Hooks {
    /// Replaces the temp file with the state file.
    pub rename: RenameHook,
    /// Flushes the temp file to disk.
    pub sync_file: SyncHook,
    /// The effective user id of the process.
    pub euid: Arc<dyn Fn() -> u32 + Send + Sync>,
    /// Changes the owner of a file the store opened, through its descriptor. The path is the
    /// one the file was opened at, for messages and tests; never chown by it.
    pub chown: ChownHook,
    /// The owner and group of the data directory.
    pub dir_owner: OwnerHook,
}

impl Default for Hooks {
    fn default() -> Hooks {
        Hooks {
            rename: Arc::new(|from, to| fs::rename(from, to)),
            sync_file: Arc::new(|file| file.sync_all()),
            euid: Arc::new(sys::effective_uid),
            chown: Arc::new(|file, _, uid, gid| {
                std::os::unix::fs::fchown(file, Some(uid), Some(gid))
            }),
            dir_owner: Arc::new(|path| {
                let metadata = fs::metadata(path)?;

                Ok((metadata.uid(), metadata.gid()))
            }),
        }
    }
}

/// How a [`Store`] waits for its lock and reaches the file system.
#[derive(Clone)]
pub struct StoreOptions {
    /// How long an update waits for the cross-process lock.
    pub lock_wait: Duration,
    /// The file-system calls, replaceable in tests.
    pub hooks: Hooks,
}

impl Default for StoreOptions {
    fn default() -> StoreOptions {
        StoreOptions {
            lock_wait: Duration::from_secs(5),
            hooks: Hooks::default(),
        }
    }
}

const LOCK_RETRY: Duration = Duration::from_millis(10);

struct Inner {
    jobs_live: AtomicUsize,
    jobs_peak: AtomicUsize,
    dir: PathBuf,
    path: PathBuf,
    lock_path: PathBuf,
    options: StoreOptions,
    temp_files_cleaned: AtomicBool,
    /// The owner of a file the store opened. Tests replace it, because the uid that runs
    /// them decides who owns the files they create.
    file_owner: fn(&fs::Metadata) -> u32,
}

/// The state file of one data directory, typed by the service's section.
pub struct Store<S> {
    inner: Arc<Inner>,
    section: PhantomData<fn() -> S>,
}

impl<S> Clone for Store<S> {
    fn clone(&self) -> Store<S> {
        Store {
            inner: self.inner.clone(),
            section: PhantomData,
        }
    }
}

impl<S: Section> Store<S> {
    /// Prepares the data directory: created 0700 if missing, tightened to 0700 if it grants
    /// group or other read or search access, refused if it grants group or other write
    /// access. It does not read the state file.
    ///
    /// # Panics
    ///
    /// When `S::KEY` is `owner`, `clients` or `tokens`: that is a programming error.
    pub fn open(dir: &Path, options: StoreOptions) -> Result<Store<S>, StoreError> {
        assert!(
            !RESERVED_KEYS.contains(&S::KEY),
            "Section::KEY {:?} is reserved for the OAuth state",
            S::KEY
        );

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|error| {
                StoreError::new(format!("create data dir {}: {error}", dir.display()))
            })?;

        let (owner, _) = (options.hooks.dir_owner)(dir).map_err(|error| {
            StoreError::new(format!("inspect data dir {}: {error}", dir.display()))
        })?;
        let euid = (options.hooks.euid)();

        if euid != 0 && euid != owner {
            return Err(StoreError::new(format!(
                "data dir {} belongs to uid {owner}, not you (uid {euid}): run this command as its owner",
                dir.display()
            )));
        }

        let tighten_error = |error: io::Error| {
            StoreError::new(format!("tighten data dir {}: {error}", dir.display()))
        };
        let opened = File::open(dir).map_err(tighten_error)?;

        refuse_if_others_could_write(&opened.metadata().map_err(tighten_error)?, dir)?;
        tighten(&opened, 0o700).map_err(tighten_error)?;

        Ok(Store {
            inner: Arc::new(Inner {
                jobs_live: AtomicUsize::new(0),
                jobs_peak: AtomicUsize::new(0),
                dir: dir.to_path_buf(),
                path: dir.join("state.json"),
                lock_path: dir.join("state.lock"),
                options,
                temp_files_cleaned: AtomicBool::new(false),
                file_owner: MetadataExt::uid,
            }),
            section: PhantomData,
        })
    }

    /// The state file.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// The data directory.
    pub fn data_dir(&self) -> &Path {
        &self.inner.dir
    }

    /// The most store jobs that have been queued or running at once.
    pub fn peak_jobs(&self) -> usize {
        self.inner.jobs_peak.load(Ordering::SeqCst)
    }

    /// Files a root-run process creates in the data dir belong to the dir's owner. The file
    /// must be a regular file with one link, owned by root or the dir's owner already; a
    /// symlink is refused, never followed.
    pub fn chown_to_dir_owner(&self, path: &Path) -> Result<(), StoreError> {
        if (self.inner.options.hooks.euid)() != 0 {
            return Ok(());
        }

        let file = open_data_file(OpenOptions::new().read(true), path)
            .map_err(|error| StoreError::new(format!("open {}: {error}", path.display())))?;

        self.inner.chown_to_dir_owner(&file, path)
    }

    /// Decodes the current file. The atomic rename means it never sees a torn write, so it
    /// takes no lock. The whole job runs on the blocking pool, and a started job runs to
    /// its end even when the caller is dropped.
    pub async fn read<T, F>(&self, read: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&State<S>) -> T + Send + 'static,
    {
        let inner = self.inner.clone();
        let job = JobCount::start(&inner);

        run_job(move || {
            let _job = job;

            Ok(read(&inner.load::<S>()?))
        })
        .await
    }

    /// Applies `update` to a fresh copy of the file under the cross-process lock and writes
    /// it back atomically unless the closure returns `Change::Unchanged`. The whole
    /// transaction is one blocking job that cannot be cancelled once started.
    pub async fn update<T, F>(&self, update: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut State<S>) -> Change<T> + Send + 'static,
    {
        let inner = self.inner.clone();
        let job = JobCount::start(&inner);

        run_job(move || {
            let _job = job;

            inner.update::<S, T>(update)
        })
        .await
    }
}

/// Counts a store job from the moment it is queued until it has run.
struct JobCount(Arc<Inner>);

impl JobCount {
    fn start(inner: &Arc<Inner>) -> JobCount {
        let now = inner.jobs_live.fetch_add(1, Ordering::SeqCst) + 1;

        inner.jobs_peak.fetch_max(now, Ordering::SeqCst);

        JobCount(inner.clone())
    }
}

impl Drop for JobCount {
    fn drop(&mut self) {
        self.0.jobs_live.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn run_job<T, F>(job: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(result) => result,
        Err(error) => Err(StoreError::new(format!("store job failed: {error}"))),
    }
}

impl Inner {
    fn update<S: Section, T>(
        &self,
        update: impl FnOnce(&mut State<S>) -> Change<T>,
    ) -> Result<T, StoreError> {
        let _lock = self.acquire_lock()?;

        if !self.temp_files_cleaned.swap(true, Ordering::Relaxed) {
            self.remove_leftover_temp_files();
        }

        let mut state = self.load::<S>()?;

        match update(&mut state) {
            Change::Write(value) => {
                self.write(&state)?;

                Ok(value)
            }
            Change::Unchanged(value) => Ok(value),
        }
    }

    fn acquire_lock(&self) -> Result<File, StoreError> {
        let lock_path = &self.lock_path;
        let file = open_lock_file(lock_path)?;

        self.chown_to_dir_owner(&file, lock_path)?;

        let deadline = Instant::now() + self.options.lock_wait;

        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(TryLockError::Error(error)) => {
                    return Err(StoreError::new(format!(
                        "lock {}: {error}",
                        lock_path.display()
                    )));
                }
                Err(TryLockError::WouldBlock) => {}
            }

            if Instant::now() >= deadline {
                return Err(StoreError::new(format!(
                    "timed out after {:?} waiting for {}: another process holds it",
                    self.options.lock_wait,
                    lock_path.display()
                )));
            }

            std::thread::sleep(LOCK_RETRY);
        }
    }

    fn remove_leftover_temp_files(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };

        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("state.json.tmp-")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// Reads the state file, first tightening it to 0600 if it grants group or other read
    /// access, so an imported 0644 file stops exposing its secrets. A file the data dir's
    /// owner does not own, or one others could write, is refused before either.
    fn load<S: Section>(&self) -> Result<State<S>, StoreError> {
        let read_error = |error| StoreError::new(format!("read {}: {error}", self.path.display()));
        let (mut file, metadata) = match open_no_follow(OpenOptions::new().read(true), &self.path) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(error) => return Err(read_error(error)),
        };

        // No links left means a save renamed a new file over this one after it was opened:
        // the inode is still a whole snapshot.
        if metadata.nlink() > 1 {
            return Err(read_error(io::Error::other("has more than one link")));
        }

        let file_uid = (self.file_owner)(&metadata);
        let (owner, _) = self.dir_owner()?;

        if file_uid != owner {
            return Err(StoreError::new(format!(
                "{} belongs to uid {file_uid}, not the data dir's owner (uid {owner}): refusing to read it",
                self.path.display()
            )));
        }

        refuse_if_others_could_write(&metadata, &self.path)?;
        tighten(&file, 0o600).map_err(|error| {
            StoreError::new(format!("tighten {}: {error}", self.path.display()))
        })?;

        let mut data = Vec::new();

        file.read_to_end(&mut data).map_err(read_error)?;

        serde_json::from_slice(&data)
            .map_err(|error| StoreError::new(format!("parse {}: {error}", self.path.display())))
    }

    fn write<S: Section>(&self, state: &State<S>) -> Result<(), StoreError> {
        let data = serde_json::to_vec(state)
            .map_err(|error| StoreError::new(format!("encode state: {error}")))?;
        let temp_path = self.dir.join(format!("state.json.tmp-{}", random_suffix()));

        let result = self.write_temp_and_rename(&temp_path, &data);

        if result.is_err() {
            let _ = fs::remove_file(&temp_path);

            return result;
        }

        // The rename is the commit point, so a failure here is only logged.
        if let Err(error) = File::open(&self.dir).and_then(|dir| dir.sync_all()) {
            eprintln!("store: sync {}: {error}", self.dir.display());
        }

        Ok(())
    }

    fn write_temp_and_rename(&self, temp_path: &Path, data: &[u8]) -> Result<(), StoreError> {
        let hooks = &self.options.hooks;
        let mut file = open_data_file(
            OpenOptions::new().write(true).create_new(true).mode(0o600),
            temp_path,
        )
        .map_err(|error| StoreError::new(format!("create {}: {error}", temp_path.display())))?;

        self.chown_to_dir_owner(&file, temp_path)?;

        file.write_all(data)
            .map_err(|error| StoreError::new(format!("write {}: {error}", temp_path.display())))?;
        (hooks.sync_file)(&file)
            .map_err(|error| StoreError::new(format!("sync {}: {error}", temp_path.display())))?;
        drop(file);

        (hooks.rename)(temp_path, &self.path)
            .map_err(|error| StoreError::new(format!("replace {}: {error}", self.path.display())))
    }

    /// Only a file root or the dir's owner already owns is handed over, so a file another
    /// user planted under a store name is never adopted.
    fn chown_to_dir_owner(&self, file: &File, path: &Path) -> Result<(), StoreError> {
        let hooks = &self.options.hooks;
        let euid = (hooks.euid)();

        if euid != 0 {
            return Ok(());
        }

        let (uid, gid) = self.dir_owner()?;
        let metadata = file
            .metadata()
            .map_err(|error| StoreError::new(format!("inspect {}: {error}", path.display())))?;
        let file_uid = (self.file_owner)(&metadata);

        if file_uid != uid && file_uid != euid {
            return Err(StoreError::new(format!(
                "{} belongs to uid {file_uid}, not the data dir's owner (uid {uid}) or root: refusing to take it over",
                path.display()
            )));
        }

        (hooks.chown)(file, path, uid, gid)
            .map_err(|error| StoreError::new(format!("chown {}: {error}", path.display())))
    }

    fn dir_owner(&self) -> Result<(u32, u32), StoreError> {
        (self.options.hooks.dir_owner)(&self.dir).map_err(|error| {
            StoreError::new(format!("inspect data dir {}: {error}", self.dir.display()))
        })
    }
}

/// Opens a file the store keeps in the data dir. The last path component must not be a
/// symlink and the file must be a regular file with one link, so a root-run command never
/// hands a file planted under that name (a link to `/etc/shadow`) to the dir's owner.
fn open_data_file(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    let (file, metadata) = open_no_follow(options, path)?;

    if metadata.nlink() != 1 {
        return Err(io::Error::other("not a regular file with a single link"));
    }

    Ok(file)
}

/// Opens a lock file in the data dir, creating it 0600 if it is missing.
fn open_lock_file(path: &Path) -> Result<File, StoreError> {
    let open_error = |error| StoreError::new(format!("open {}: {error}", path.display()));
    let file = open_data_file(
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600),
        path,
    )
    .map_err(open_error)?;

    refuse_if_others_could_write(&file.metadata().map_err(open_error)?, path)?;

    Ok(file)
}

/// Group or other write access means another user may have changed the file, or may still
/// hold it open for writing; a chmod takes neither back, so the owner has to start fresh.
fn refuse_if_others_could_write(metadata: &fs::Metadata, path: &Path) -> Result<(), StoreError> {
    let mode = metadata.permissions().mode() & 0o777;

    if mode & 0o022 == 0 {
        return Ok(());
    }

    Err(StoreError::new(format!(
        "{path} is writable by group or others (mode {mode:04o}): another user may have changed it \
         or may still hold it open for writing, and a chmod does not close their descriptor. Stop \
         the service, move the data dir aside, create a new one (mode 0700, owned by the service \
         user) and set the service up again, copying in only values you have checked",
        path = path.display()
    )))
}

/// Opens a regular file without following a symlink in the last path component.
fn open_no_follow(options: &mut OpenOptions, path: &Path) -> io::Result<(File, fs::Metadata)> {
    // O_NONBLOCK keeps a FIFO planted under the name from blocking the open; it changes
    // nothing for a regular file.
    let file = options
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                return io::Error::other("is a symbolic link; refusing to follow it");
            }

            error
        })?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }

    Ok((file, metadata))
}

/// Sets `mode` on an open file or dir whose mode grants any group or other access.
fn tighten(file: &File, mode: u32) -> io::Result<()> {
    if file.metadata()?.permissions().mode() & 0o077 == 0 {
        return Ok(());
    }

    file.set_permissions(fs::Permissions::from_mode(mode))
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("the operating system has no randomness");

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Held by the one process that uses the data dir for a long time (`serve`). Two processes
/// renewing one upstream login at once can lose it, so the second one is refused.
pub struct Lease {
    _file: File,
}

impl Lease {
    /// Takes the exclusive lease on the data dir, or fails when another process holds it.
    pub fn acquire<S: Section>(store: &Store<S>, info: &ServiceInfo) -> Result<Lease, StoreError> {
        let path = store.data_dir().join("session.lock");
        let file = open_lock_file(&path)?;

        store.inner.chown_to_dir_owner(&file, &path)?;

        file.try_lock().map_err(|_| {
            StoreError::message(format!(
                "another {} process is using this data dir; stop it first",
                info.command
            ))
        })?;

        Ok(Lease { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::thread::ThreadId;

    use super::*;

    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    struct TestSection {
        rev: i64,
    }

    impl Section for TestSection {
        const KEY: &'static str = "test";
    }

    const INFO: ServiceInfo = ServiceInfo {
        command: "example-mcp",
        display_name: "Example",
        env_prefix: "EXAMPLE_MCP_",
        default_listen: "127.0.0.1:8090",
        default_data_dir: "/var/lib/example-mcp",
        default_tz: "Asia/Jakarta",
        scope: "example",
        favicon: &[],
    };

    fn open(dir: &Path) -> Store<TestSection> {
        Store::open(dir, StoreOptions::default()).unwrap()
    }

    async fn bump_session_rev(store: &Store<TestSection>) {
        store
            .update(|state| {
                state.section.rev += 1;

                Change::Write(())
            })
            .await
            .unwrap();
    }

    async fn session_rev(store: &Store<TestSection>) -> i64 {
        store.read(|state| state.section.rev).await.unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn creates_modes() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        let store = open(&dir);

        bump_session_rev(&store).await;

        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(store.path()), 0o600);
        assert_eq!(mode(&dir.join("state.lock")), 0o600);
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn tightens_an_existing_data_dir() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        open(&dir);

        assert_eq!(mode(&dir), 0o700);
    }

    fn assert_refused_as_writable(error: &StoreError, path: &Path) {
        let message = error.to_string();

        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("writable by group or others"), "{message}");
        assert!(message.contains("a chmod does not close"), "{message}");
        assert!(message.contains("move the data dir aside"), "{message}");
    }

    #[test]
    fn refuses_a_data_dir_others_could_write() {
        for loose in [0o777, 0o770, 0o702] {
            let parent = tempfile::tempdir().unwrap();
            let dir = parent.path().join("data");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();

            let error = Store::<TestSection>::open(&dir, StoreOptions::default())
                .err()
                .unwrap();

            assert_refused_as_writable(&error, &dir);
            assert_eq!(mode(&dir), loose, "not tightened");
        }
    }

    /// Another user opened a world-writable state file before the server started: tightening
    /// would leave that user's descriptor writable, so neither the dir nor the file is used.
    #[test]
    fn refuses_a_shared_data_dir_with_a_shared_state_file() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        fs::create_dir(&dir).unwrap();
        let (path, content) = plant_state_file(&dir);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

        let error = Store::<TestSection>::open(&dir, StoreOptions::default())
            .err()
            .unwrap();

        assert_refused_as_writable(&error, &dir);
        assert_eq!(mode(&dir), 0o777);
        assert_eq!(mode(&path), 0o666);
        assert_eq!(fs::read(&path).unwrap(), content);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_state_file_others_could_write() {
        for loose in [0o666, 0o620, 0o602] {
            let dir = tempfile::tempdir().unwrap();
            let (path, content) = plant_state_file(dir.path());
            fs::set_permissions(&path, fs::Permissions::from_mode(loose)).unwrap();
            let store = open(dir.path());
            let loaded = Arc::new(AtomicBool::new(false));

            let flag = loaded.clone();
            let read_error = store
                .read(move |_| flag.store(true, Ordering::SeqCst))
                .await
                .err()
                .unwrap();
            let flag = loaded.clone();
            let update_error = store
                .update(move |_| {
                    flag.store(true, Ordering::SeqCst);

                    Change::Write(())
                })
                .await
                .err()
                .unwrap();

            assert_refused_as_writable(&read_error, &path);
            assert_refused_as_writable(&update_error, &path);
            assert!(!loaded.load(Ordering::SeqCst), "nothing was loaded");
            assert_eq!(mode(&path), loose, "not tightened");
            assert_eq!(fs::read(&path).unwrap(), content);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_state_lock_others_could_write() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("state.lock");
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).unwrap();
        let store = open(dir.path());

        let error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        assert_refused_as_writable(&error, &lock);
        assert_eq!(mode(&lock), 0o666);
    }

    #[test]
    fn refuses_a_session_lock_others_could_write() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("session.lock");
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o620)).unwrap();
        let store = open(dir.path());

        let error = Lease::acquire(&store, &INFO).err().unwrap();

        assert_refused_as_writable(&error, &lock);
        assert_eq!(mode(&lock), 0o620);
    }

    #[test]
    fn leaves_a_private_data_dir_alone() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        open(&dir);

        assert_eq!(mode(&dir), 0o500);

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tightens_a_readable_state_file_before_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        bump_session_rev(&store).await;

        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(session_rev(&store).await, 1);
        assert_eq!(mode(store.path()), 0o600);

        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o640)).unwrap();
        store.update(|_| Change::Unchanged(())).await.unwrap();

        assert_eq!(mode(store.path()), 0o600, "an update tightens it too");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_symlinked_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        let store = open(dir.path());
        std::os::unix::fs::symlink(&target, store.path()).unwrap();

        let error = store.read(|_| ()).await.err().unwrap();

        assert!(error.to_string().contains("state.json"), "{error}");
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert_untouched(&target);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_hard_linked_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        let store = open(dir.path());
        fs::hard_link(&target, store.path()).unwrap();

        let error = store.read(|_| ()).await.err().unwrap();

        assert!(error.to_string().contains("state.json"), "{error}");
        assert!(error.to_string().contains("more than one link"), "{error}");
        assert_untouched(&target);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_state_file_that_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        fs::create_dir(store.path()).unwrap();

        let error = store.read(|_| ()).await.err().unwrap();

        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    /// A read that opened the file just before a save renamed a new one over it holds an
    /// inode with no links left. That is still a whole snapshot, so the read must succeed.
    #[tokio::test(flavor = "current_thread")]
    async fn reads_during_saves_never_fail() {
        const SAVES: i64 = 300;

        let dir = tempfile::tempdir().unwrap();
        let mut options = StoreOptions::default();
        options.hooks.sync_file = Arc::new(|_| Ok(()));
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();
        bump_session_rev(&store).await;
        let saving = Arc::new(AtomicBool::new(true));

        let (inner, still_saving) = (store.inner.clone(), saving.clone());
        let saver = tokio::task::spawn_blocking(move || {
            let saved = (0..SAVES).try_for_each(|_| {
                inner.update::<TestSection, ()>(|state| {
                    state.section.rev += 1;

                    Change::Write(())
                })
            });

            still_saving.store(false, Ordering::SeqCst);

            saved
        });
        let inner = store.inner.clone();
        let reader = tokio::task::spawn_blocking(move || {
            let (mut reads, mut failures) = (0, Vec::new());

            while saving.load(Ordering::SeqCst) {
                reads += 1;

                if let Err(error) = inner.load::<TestSection>() {
                    failures.push(error.to_string());
                }
            }

            (reads, failures)
        });

        saver.await.unwrap().unwrap();
        let (reads, failures) = reader.await.unwrap();

        assert!(
            failures.is_empty(),
            "{} of {reads} reads failed, the first: {}",
            failures.len(),
            failures[0]
        );
        assert_eq!(session_rev(&store).await, SAVES + 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn atomic_write_keeps_old_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let fail_rename = Arc::new(AtomicBool::new(false));
        let mut options = StoreOptions::default();
        let flag = fail_rename.clone();
        options.hooks.rename = Arc::new(move |from, to| {
            if flag.load(Ordering::SeqCst) {
                return Err(io::Error::other("disk on fire"));
            }

            fs::rename(from, to)
        });
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();
        bump_session_rev(&store).await;
        let before = fs::read(store.path()).unwrap();

        fail_rename.store(true, Ordering::SeqCst);
        let error = store
            .update(|state| {
                state.section.rev = 99;

                Change::Write(())
            })
            .await
            .err()
            .unwrap();

        assert!(error.to_string().contains("disk on fire"));
        assert_eq!(fs::read(store.path()).unwrap(), before);

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();

        assert!(leftovers.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn corrupt_file_refuses_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        fs::write(store.path(), b"{not json").unwrap();

        let read_error = store.read(|_| ()).await.err().unwrap();
        let update_error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        for error in [read_error, update_error] {
            let message = error.to_string();

            assert!(message.contains("parse"), "{message}");
            assert!(
                message.contains(&store.path().display().to_string()),
                "{message}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        let registered: Timestamp = "2026-10-24T01:02:03.5Z".parse().unwrap();

        store
            .update(move |state| {
                state.section.rev = 3;
                state.owner.password_hash = "$2b$12$hash".into();
                state.clients.insert(
                    "c1".into(),
                    Client {
                        client_id: "c1".into(),
                        client_name: "Claude".into(),
                        redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".into()],
                        registered_at: registered,
                        last_used_at: None,
                        extra: Map::new(),
                    },
                );
                state.tokens.insert(
                    "ab".repeat(32),
                    Token {
                        kind: TokenKind::Refresh,
                        client_id: "c1".into(),
                        family: "f1".into(),
                        scope: "test".into(),
                        resource: String::new(),
                        expires_at: registered,
                        rotated: true,
                        extra: Map::new(),
                    },
                );

                Change::Write(())
            })
            .await
            .unwrap();

        let state = store.read(|state| state.clone()).await.unwrap();

        assert_eq!(state.section.rev, 3);
        assert_eq!(state.owner.password_hash, "$2b$12$hash");
        assert_eq!(state.clients["c1"].redirect_uris.len(), 1);
        assert_eq!(
            state.tokens["ab".repeat(32).as_str()].kind,
            TokenKind::Refresh
        );
        assert!(state.tokens["ab".repeat(32).as_str()].rotated);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unchanged_skips_write() {
        let dir = tempfile::tempdir().unwrap();
        let renames = Arc::new(Mutex::new(0));
        let mut options = StoreOptions::default();
        let counter = renames.clone();
        options.hooks.rename = Arc::new(move |from, to| {
            *counter.lock().unwrap() += 1;

            fs::rename(from, to)
        });
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let value = store
            .update(|state| {
                state.section.rev = 5;

                Change::Unchanged(42)
            })
            .await
            .unwrap();

        assert_eq!(value, 42);
        assert_eq!(*renames.lock().unwrap(), 0);
        assert!(!store.path().exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chowns_when_root() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut options = StoreOptions::default();
        let owner = sys::effective_uid();
        options.hooks.euid = Arc::new(|| 0);
        options.hooks.dir_owner = Arc::new(move |_| Ok((owner, 5678)));
        let log = events.clone();
        options.hooks.chown = Arc::new(move |file, path, uid, gid| {
            assert_eq!(
                file.metadata().unwrap().ino(),
                fs::metadata(path).unwrap().ino(),
                "the descriptor is the file at the path"
            );

            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            log.lock()
                .unwrap()
                .push(format!("chown {name} {uid}:{gid}"));

            Ok(())
        });
        let log = events.clone();
        options.hooks.rename = Arc::new(move |from, to| {
            log.lock().unwrap().push("rename".to_string());

            fs::rename(from, to)
        });
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        bump_session_rev(&store).await;

        let events = events.lock().unwrap();

        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[0], format!("chown state.lock {owner}:5678"));
        assert!(events[1].starts_with("chown state.json.tmp-"), "{events:?}");
        assert!(events[1].ends_with(&format!(" {owner}:5678")), "{events:?}");
        assert_eq!(events[2], "rename");
    }

    /// A uid other than the one running the tests: the owner a fake data dir reports, so the
    /// files the tests create belong to someone else.
    fn other_uid() -> u32 {
        sys::effective_uid() + 1
    }

    /// Root-run options for a data dir owned by [`other_uid`], whose chown hook records each
    /// call instead of changing an owner.
    fn recording_root_options() -> (StoreOptions, Arc<Mutex<Vec<String>>>) {
        let chowned = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut options = StoreOptions::default();
        let other = other_uid();
        options.hooks.euid = Arc::new(|| 0);
        options.hooks.dir_owner = Arc::new(move |_| Ok((other, other)));
        let log = chowned.clone();
        options.hooks.chown = Arc::new(move |_, path, _, _| {
            log.lock().unwrap().push(path.display().to_string());

            Ok(())
        });

        (options, chowned)
    }

    /// A file outside the data dir that a planted link points at.
    fn outside_target() -> (tempfile::TempDir, PathBuf) {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("shadow");
        fs::write(&target, b"secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

        (outside, target)
    }

    fn assert_untouched(target: &Path) {
        assert_eq!(fs::read(target).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_symlinked_state_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        std::os::unix::fs::symlink(&target, dir.path().join("state.lock")).unwrap();
        let (options, chowned) = recording_root_options();
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        assert!(error.to_string().contains("state.lock"), "{error}");
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
        assert_untouched(&target);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_hard_linked_state_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        fs::hard_link(&target, dir.path().join("state.lock")).unwrap();
        let (options, chowned) = recording_root_options();
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        assert!(error.to_string().contains("regular file"), "{error}");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
        assert_untouched(&target);
    }

    #[test]
    fn refuses_a_symlinked_session_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        std::os::unix::fs::symlink(&target, dir.path().join("session.lock")).unwrap();
        let (options, chowned) = recording_root_options();
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let error = Lease::acquire(&store, &INFO).err().unwrap();

        assert!(error.to_string().contains("session.lock"), "{error}");
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
        assert_untouched(&target);
    }

    #[test]
    fn chown_to_dir_owner_refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let (_outside, target) = outside_target();
        let link = dir.path().join("cookies.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (options, chowned) = recording_root_options();
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let error = store.chown_to_dir_owner(&link).err().unwrap();

        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
        assert_untouched(&target);
    }

    /// A 0644 state file that the test user owns, holding `rev` 9.
    fn plant_state_file(dir: &Path) -> (PathBuf, Vec<u8>) {
        let path = dir.join("state.json");
        let content = br#"{"test":{"rev":9},"owner":{},"clients":{},"tokens":{}}"#.to_vec();
        fs::write(&path, &content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        (path, content)
    }

    /// A uid that is neither root nor [`other_uid`], whoever runs the tests.
    const STRANGER_UID: u32 = 0xFFFF_FF00;

    /// Makes the store see every file it opens as owned by `owner`, so a test does not depend
    /// on the uid that runs it (root's own files are trusted).
    fn report_file_owner(store: &mut Store<TestSection>, owner: fn(&fs::Metadata) -> u32) {
        Arc::get_mut(&mut store.inner)
            .expect("the store is not shared yet")
            .file_owner = owner;
    }

    fn assert_refused_as_foreign(error: &StoreError, name: &str) {
        let message = error.to_string();

        assert!(message.contains(name), "{message}");
        assert!(
            message.contains(&format!("belongs to uid {STRANGER_UID}")),
            "{message}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_state_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let (path, content) = plant_state_file(dir.path());
        let other = other_uid();
        let mut options = StoreOptions::default();
        options.hooks.euid = Arc::new(move || other);
        options.hooks.dir_owner = Arc::new(move |_| Ok((other, other)));
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| STRANGER_UID);
        let loaded = Arc::new(AtomicBool::new(false));

        let flag = loaded.clone();
        let read_error = store
            .read(move |_| flag.store(true, Ordering::SeqCst))
            .await
            .err()
            .unwrap();
        let flag = loaded.clone();
        let update_error = store
            .update(move |_| {
                flag.store(true, Ordering::SeqCst);

                Change::Write(())
            })
            .await
            .err()
            .unwrap();

        assert_refused_as_foreign(&read_error, "state.json");
        assert_refused_as_foreign(&update_error, "state.json");
        assert!(!loaded.load(Ordering::SeqCst), "nothing was loaded");
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_eq!(mode(&path), 0o644, "not tightened");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_refuses_a_state_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let (path, content) = plant_state_file(dir.path());
        let (options, chowned) = recording_root_options();
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| STRANGER_UID);

        let error = store.read(|_| ()).await.err().unwrap();

        assert_refused_as_foreign(&error, "state.json");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_eq!(mode(&path), 0o644, "not tightened");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_refuses_a_state_lock_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.lock"), b"").unwrap();
        let (options, chowned) = recording_root_options();
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| STRANGER_UID);

        let error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        assert_refused_as_foreign(&error, "state.lock");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
    }

    #[test]
    fn root_refuses_a_session_lock_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("session.lock"), b"").unwrap();
        let (options, chowned) = recording_root_options();
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| STRANGER_UID);

        let error = Lease::acquire(&store, &INFO).err().unwrap();

        assert_refused_as_foreign(&error, "session.lock");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
    }

    #[test]
    fn chown_to_dir_owner_refuses_a_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let cookies = dir.path().join("cookies.json");
        fs::write(&cookies, b"{}").unwrap();
        let (options, chowned) = recording_root_options();
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| STRANGER_UID);

        let error = store.chown_to_dir_owner(&cookies).err().unwrap();

        assert_refused_as_foreign(&error, "cookies.json");
        assert!(chowned.lock().unwrap().is_empty(), "{chowned:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_hands_over_files_root_owns() {
        let dir = tempfile::tempdir().unwrap();
        let cookies = dir.path().join("cookies.json");
        fs::write(&cookies, b"{}").unwrap();
        let (options, chowned) = recording_root_options();
        let mut store = Store::<TestSection>::open(dir.path(), options).unwrap();
        report_file_owner(&mut store, |_| 0);

        store.update(|_| Change::Unchanged(())).await.unwrap();
        let _lease = Lease::acquire(&store, &INFO).unwrap();
        store.chown_to_dir_owner(&cookies).unwrap();

        let names: Vec<String> = chowned
            .lock()
            .unwrap()
            .iter()
            .map(|path| {
                Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        assert_eq!(names, ["state.lock", "session.lock", "cookies.json"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_a_data_dir_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = StoreOptions::default();
        options.hooks.euid = Arc::new(|| 1000);
        options.hooks.dir_owner = Arc::new(|_| Ok((1001, 1001)));

        let error = Store::<TestSection>::open(dir.path(), options)
            .err()
            .unwrap();

        assert!(error.to_string().contains("belongs to uid 1001"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cross_process_lock() {
        let dir = tempfile::tempdir().unwrap();
        let first = open(dir.path());
        let second = open(dir.path());

        let mut tasks = Vec::new();

        for index in 0..40 {
            let store = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            tasks.push(tokio::spawn(async move { bump_session_rev(&store).await }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(session_rev(&first).await, 40);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lock_wait_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let options = StoreOptions {
            lock_wait: Duration::from_millis(150),
            hooks: Hooks::default(),
        };
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();
        let holder = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.path().join("state.lock"))
            .unwrap();
        let release = Arc::new(AtomicBool::new(false));
        let signal = release.clone();
        let thread = std::thread::spawn(move || {
            holder.lock().unwrap();

            while !signal.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        std::thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        let error = store.update(|_| Change::Unchanged(())).await.err().unwrap();

        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.to_string().contains("state.lock"), "{error}");
        assert!(
            error.to_string().contains("another process holds it"),
            "{error}"
        );

        release.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        bump_session_rev(&store).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn update_survives_caller_drop() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = StoreOptions::default();
        options.hooks.sync_file = Arc::new(|file| {
            std::thread::sleep(Duration::from_millis(300));

            file.sync_all()
        });
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();

        let timed_out = tokio::time::timeout(Duration::from_millis(50), async {
            store
                .update(|state| {
                    state.section.rev = 7;

                    Change::Write(())
                })
                .await
        })
        .await;

        assert!(timed_out.is_err());

        tokio::time::sleep(Duration::from_millis(600)).await;

        assert_eq!(session_rev(&store).await, 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn update_runs_off_runtime_thread() {
        let dir = tempfile::tempdir().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<ThreadId>::new()));
        let mut options = StoreOptions::default();
        let log = seen.clone();
        options.hooks.sync_file = Arc::new(move |file| {
            log.lock().unwrap().push(std::thread::current().id());

            file.sync_all()
        });
        let store = Store::<TestSection>::open(dir.path(), options).unwrap();
        let runtime_thread = std::thread::current().id();

        bump_session_rev(&store).await;

        let seen = seen.lock().unwrap();

        assert_eq!(seen.len(), 1);
        assert_ne!(seen[0], runtime_thread);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn leftover_temp_files_removed() {
        let dir = tempfile::tempdir().unwrap();
        let stray = dir.path().join("state.json.tmp-x");
        let unrelated = dir.path().join("notes.txt");
        fs::write(&stray, b"partial").unwrap();
        fs::write(&unrelated, b"keep").unwrap();
        let store = open(dir.path());

        bump_session_rev(&store).await;

        assert!(!stray.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn go_omissions_kept() {
        let json = serde_json::to_string(&State::<TestSection>::default()).unwrap();

        assert_eq!(
            json,
            r#"{"test":{"rev":0},"owner":{},"clients":{},"tokens":{}}"#
        );
    }

    #[test]
    fn unknown_fields_round_trip() {
        let input =
            r#"{"test":{"rev":1},"owner":{"x":1},"clients":{},"tokens":{},"future_top":[1,2]}"#;
        let state: State<TestSection> = serde_json::from_str(input).unwrap();

        assert_eq!(serde_json::to_string(&state).unwrap(), input);
    }

    #[test]
    fn state_keys_in_section_first_order() {
        let registered: Timestamp = "2026-10-24T01:02:03Z".parse().unwrap();
        let mut state = State::<TestSection>::default();
        state.clients.insert(
            "c1".into(),
            Client {
                client_id: "c1".into(),
                client_name: String::new(),
                redirect_uris: Vec::new(),
                registered_at: registered,
                last_used_at: None,
                extra: Map::new(),
            },
        );
        state.tokens.insert(
            "t1".into(),
            Token {
                kind: TokenKind::Access,
                client_id: "c1".into(),
                family: "f1".into(),
                scope: String::new(),
                resource: String::new(),
                expires_at: registered,
                rotated: false,
                extra: Map::new(),
            },
        );
        state.extra.insert("aa_extra".into(), Value::Bool(true));

        let json = serde_json::to_string(&state).unwrap();
        let positions: Vec<usize> = [
            "\"test\":",
            "\"owner\":",
            "\"clients\":",
            "\"tokens\":",
            "\"aa_extra\":",
        ]
        .iter()
        .map(|key| json.find(key).unwrap_or_else(|| panic!("{key} in {json}")))
        .collect();

        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{json}");
    }

    #[test]
    fn missing_keys_default() {
        let state: State<TestSection> = serde_json::from_str("{}").unwrap();

        assert_eq!(state, State::default());
    }

    #[test]
    fn foreign_keys_kept_in_extra() {
        let state: State<TestSection> =
            serde_json::from_str(r#"{"test":{"rev":4},"other":{"a":[1,2]},"n":3}"#).unwrap();

        assert_eq!(state.section.rev, 4);
        assert_eq!(state.extra["other"], serde_json::json!({"a": [1, 2]}));
        assert_eq!(state.extra["n"], 3);
        assert!(!state.extra.contains_key("test"));
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn reserved_section_key_panics() {
        #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
        struct Reserved {}

        impl Section for Reserved {
            const KEY: &'static str = "owner";
        }

        let dir = tempfile::tempdir().unwrap();

        let _ = Store::<Reserved>::open(dir.path(), StoreOptions::default());
    }

    #[test]
    fn lease_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        let other = open(dir.path());

        let first = Lease::acquire(&store, &INFO).unwrap();
        let error = Lease::acquire(&other, &INFO).err().unwrap();

        assert_eq!(
            error.to_string(),
            "another example-mcp process is using this data dir; stop it first"
        );

        drop(first);

        assert!(Lease::acquire(&other, &INFO).is_ok());
    }
}
