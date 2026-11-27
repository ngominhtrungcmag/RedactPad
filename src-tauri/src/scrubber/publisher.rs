use std::{
    ffi::{c_void, CStr, CString},
    fs::File,
    io::{self, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::FileExt},
    },
    path::Path,
    sync::{Condvar, Mutex},
};

use super::{ScrubberError, ScrubberSession};
use crate::detector::{
    stream::{Scanner, CHUNK_SIZE},
    DetectOptions,
};

const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const TEMP: &CStr = c"output";

extern "C" {
    fn acl_get_fd_np(fd: RawFd, acl_type: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: RawFd, acl: *mut c_void, acl_type: libc::c_int) -> libc::c_int;
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_get_entry(
        acl: *mut c_void,
        entry_id: libc::c_int,
        entry: *mut *mut c_void,
    ) -> libc::c_int;
    fn acl_free(acl: *mut c_void) -> libc::c_int;
}

fn checked(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn open_fd(result: libc::c_int) -> io::Result<File> {
    let fd = checked(result)?;
    // A successful open returned a new descriptor owned by this caller.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::uninit();
    // fstat initializes the structure on success.
    checked(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })?;
    Ok(unsafe { stat.assume_init() })
}

fn stat_at(fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::uninit();
    checked(unsafe { libc::fstatat(fd, name.as_ptr(), stat.as_mut_ptr(), flags) })?;
    Ok(unsafe { stat.assume_init() })
}

fn identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev as u32 as u64, stat.st_ino)
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe { acl_free(self.0) };
    }
}

fn empty_acl(fd: RawFd) -> io::Result<bool> {
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(true)
        } else {
            Err(error)
        };
    }
    let acl = Acl(acl);
    let mut entry = std::ptr::null_mut();
    let result = unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) };
    // Darwin reports ENOENT when the requested entry does not exist.
    match result {
        0 => Ok(false),
        _ if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

fn isolate_acl(fd: RawFd) -> io::Result<bool> {
    if !empty_acl(fd)? {
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let acl = Acl(acl);
        checked(unsafe { acl_set_fd_np(fd, acl.0, ACL_TYPE_EXTENDED) })?;
    }
    empty_acl(fd)
}

struct Stage<'a> {
    parent: &'a File,
    name: CString,
    file: Option<File>,
    identity: Option<(u64, u64)>,
    temp_exists: bool,
    armed: bool,
}

impl<'a> Stage<'a> {
    fn create(parent: &'a File) -> io::Result<Self> {
        let mut nonce = [0; 16];
        unsafe { libc::arc4random_buf(nonce.as_mut_ptr().cast(), nonce.len()) };
        let name = CString::new(format!(".redactpad-{:032x}", u128::from_ne_bytes(nonce))).unwrap();
        let fd = parent.as_raw_fd();
        checked(unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) })?;
        Ok(Self {
            parent,
            name,
            file: None,
            identity: None,
            temp_exists: false,
            armed: true,
        })
    }

    fn open(&mut self) -> Result<(), ScrubberError> {
        let fd = self.parent.as_raw_fd();
        let named = stat_at(fd, &self.name, libc::AT_SYMLINK_NOFOLLOW).map_err(output_error)?;
        let file = open_fd(unsafe {
            libc::openat(
                fd,
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
        .map_err(output_error)?;
        let stat = stat_fd(file.as_raw_fd()).map_err(output_error)?;
        if identity(&named) != identity(&stat) {
            return Err(ScrubberError::UnsafeStaging);
        }
        self.identity = Some(identity(&stat));
        let fd = file.as_raw_fd();
        self.file = Some(file);
        if stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o7777 != 0o700
            || !isolate_acl(fd).map_err(output_error)?
        {
            return Err(ScrubberError::UnsafeStaging);
        }
        Ok(())
    }

    fn fd(&self) -> RawFd {
        self.file.as_ref().unwrap().as_raw_fd()
    }

    fn temp(&mut self) -> io::Result<File> {
        let file = open_fd(unsafe {
            libc::openat(
                self.fd(),
                TEMP.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        self.temp_exists = true;
        Ok(file)
    }

    fn cleanup(&mut self, remove_stage: bool) -> bool {
        self.armed = false;
        let temp_clean =
            !self.temp_exists || unsafe { libc::unlinkat(self.fd(), TEMP.as_ptr(), 0) == 0 };
        let parent = self.parent.as_raw_fd();
        let trusted = stat_fd(parent).is_ok_and(|stat| {
            stat.st_uid == unsafe { libc::geteuid() } && stat.st_mode & 0o022 == 0
        }) && empty_acl(parent).unwrap_or(false);
        let still_ours = self.identity.is_some_and(|expected| {
            stat_at(parent, &self.name, libc::AT_SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| identity(&stat) == expected)
        });
        let stage_clean = remove_stage
            && trusted
            && still_ours
            && unsafe { libc::unlinkat(parent, self.name.as_ptr(), libc::AT_REMOVEDIR) == 0 };
        temp_clean && stage_clean
    }
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cleanup(true);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ExportOutcome {
    Cancelled {
        cleanup_warning: bool,
    },
    Published,
    PublishedWithWarning {
        cleanup_warning: bool,
        sync_warning: bool,
    },
    Failed {
        error: ScrubberError,
        cleanup_warning: bool,
    },
}

enum PublishPhase {
    Idle,
    Running,
    Cancelled,
    Publishing,
    Finished(ExportOutcome),
}

pub struct ExportJob {
    phase: Mutex<PublishPhase>,
    finished: Condvar,
}

impl Default for ExportJob {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportJob {
    pub fn new() -> Self {
        Self {
            phase: Mutex::new(PublishPhase::Idle),
            finished: Condvar::new(),
        }
    }

    pub fn cancel(&self) -> ExportOutcome {
        let mut phase = self.phase.lock().unwrap();
        if matches!(*phase, PublishPhase::Idle) {
            *phase = PublishPhase::Finished(ExportOutcome::Cancelled {
                cleanup_warning: false,
            });
        } else if matches!(*phase, PublishPhase::Running) {
            *phase = PublishPhase::Cancelled;
        }
        loop {
            if let PublishPhase::Finished(outcome) = *phase {
                return outcome;
            }
            phase = self.finished.wait(phase).unwrap();
        }
    }

    pub fn cancellation_requested(&self) -> bool {
        matches!(*self.phase.lock().unwrap(), PublishPhase::Cancelled)
    }

    fn begin_publish(&self) -> bool {
        let mut phase = self.phase.lock().unwrap();
        if matches!(*phase, PublishPhase::Cancelled) {
            return false;
        }
        *phase = PublishPhase::Publishing;
        true
    }
}

struct FinishExportOnUnwind<'a>(&'a ExportJob);

impl Drop for FinishExportOnUnwind<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let job = self.0;
        let mut phase = job
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*phase, PublishPhase::Finished(_)) {
            *phase = PublishPhase::Finished(ExportOutcome::Failed {
                error: ScrubberError::OutputIo(None),
                cleanup_warning: true,
            });
        }
        job.phase.clear_poison();
        job.finished.notify_all();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExportStep {
    Staged,
    BeforePublish,
    Publishing,
    Cleanup,
    DirectorySync,
}

pub trait ExportHooks {
    fn step(&self, _step: ExportStep) -> io::Result<()> {
        Ok(())
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        file.write(bytes)
    }
}

impl ExportHooks for () {}

fn output_error(error: io::Error) -> ScrubberError {
    if error.raw_os_error() == Some(libc::EEXIST) {
        ScrubberError::AlreadyExists
    } else {
        ScrubberError::OutputIo(error.raw_os_error())
    }
}

fn destination(path: &Path, session: &ScrubberSession) -> Result<(File, CString), ScrubberError> {
    let raw_name = path
        .as_os_str()
        .as_bytes()
        .rsplit(|&b| b == b'/')
        .next()
        .unwrap();
    if matches!(raw_name, b"" | b"." | b"..") {
        return Err(ScrubberError::InvalidDestination);
    }
    let name = CString::new(raw_name).map_err(|_| ScrubberError::InvalidDestination)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_path = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| ScrubberError::InvalidDestination)?;
    let parent = open_fd(unsafe {
        libc::open(
            parent_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })
    .map_err(output_error)?;
    let fd = parent.as_raw_fd();
    match stat_at(fd, &name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if path
                .canonicalize()
                .is_ok_and(|canonical| canonical == session.canonical_path)
                || identity(&stat) == session.identity
                || stat_at(fd, &name, 0).is_ok_and(|target| identity(&target) == session.identity)
            {
                return Err(ScrubberError::SameFile);
            }
            return Err(ScrubberError::AlreadyExists);
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(error) => return Err(output_error(error)),
    }
    Ok((parent, name))
}

type ExportResult = Result<Option<(bool, bool)>, (ScrubberError, bool)>;

pub fn export_file(session: &ScrubberSession, path: &Path, job: &ExportJob) -> ExportOutcome {
    export_file_with_hooks(session, path, job, &())
}

pub fn export_file_with_hooks(
    session: &ScrubberSession,
    path: &Path,
    job: &ExportJob,
    hooks: &impl ExportHooks,
) -> ExportOutcome {
    {
        let mut phase = job.phase.lock().unwrap();
        loop {
            match *phase {
                PublishPhase::Idle => {
                    *phase = PublishPhase::Running;
                    break;
                }
                PublishPhase::Finished(outcome) => return outcome,
                _ => phase = job.finished.wait(phase).unwrap(),
            }
        }
    }
    let _finish_on_unwind = FinishExportOnUnwind(job);
    let result = run_export(session, path, job, hooks);
    let mut phase = job.phase.lock().unwrap();
    let outcome = match result {
        Ok(Some((false, false))) => ExportOutcome::Published,
        Ok(Some((cleanup_warning, sync_warning))) => ExportOutcome::PublishedWithWarning {
            cleanup_warning,
            sync_warning,
        },
        Ok(None) => ExportOutcome::Cancelled {
            cleanup_warning: false,
        },
        Err((_, cleanup_warning)) if matches!(*phase, PublishPhase::Cancelled) => {
            ExportOutcome::Cancelled { cleanup_warning }
        }
        Err((error, cleanup_warning)) => ExportOutcome::Failed {
            error,
            cleanup_warning,
        },
    };
    *phase = PublishPhase::Finished(outcome);
    job.finished.notify_all();
    outcome
}

fn run_export(
    session: &ScrubberSession,
    path: &Path,
    job: &ExportJob,
    hooks: &impl ExportHooks,
) -> ExportResult {
    let (parent, name) = destination(path, session).map_err(|error| (error, false))?;
    let mut stage = Stage::create(&parent).map_err(|error| (output_error(error), false))?;
    let result = prepare_and_publish(session, job, hooks, &mut stage, &name);
    let hook_cleanup = hooks.step(ExportStep::Cleanup).is_ok();
    let cleanup_warning = !stage.cleanup(hook_cleanup);
    match result {
        Ok(true) => {
            let sync_warning = hooks
                .step(ExportStep::DirectorySync)
                .and_then(|()| checked(unsafe { libc::fsync(parent.as_raw_fd()) }).map(|_| ()))
                .is_err();
            Ok(Some((cleanup_warning, sync_warning)))
        }
        Ok(false) if !cleanup_warning => Ok(None),
        Ok(false) => Err((ScrubberError::UnsafeStaging, true)),
        Err(error) => Err((error, cleanup_warning)),
    }
}

struct HookWriter<'a, H> {
    file: &'a mut File,
    hooks: &'a H,
}

impl<H: ExportHooks> Write for HookWriter<'_, H> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hooks.write(self.file, bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn prepare_and_publish(
    session: &ScrubberSession,
    job: &ExportJob,
    hooks: &impl ExportHooks,
    stage: &mut Stage<'_>,
    name: &CStr,
) -> Result<bool, ScrubberError> {
    stage.open()?;
    hooks.step(ExportStep::Staged).map_err(output_error)?;
    let mut output = stage.temp().map_err(output_error)?;
    let mut writer = HookWriter {
        file: &mut output,
        hooks,
    };
    let mut scanner = Scanner::new(&DetectOptions::default());
    let mut offset = 0;
    let mut buffer = vec![0; CHUNK_SIZE];
    while !job.cancellation_requested() {
        let count = session.file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        offset += count as u64;
        scanner
            .push(&buffer[..count], |bytes, _| writer.write_all(bytes))
            .map_err(output_error)?;
        if let Some(&warning) = scanner.warnings().first() {
            return Err(ScrubberError::BlockingLimitation(warning));
        }
    }
    if job.cancellation_requested() {
        return Ok(false);
    }
    scanner
        .finish(|bytes, _| writer.write_all(bytes))
        .map_err(output_error)?;
    if let Some(&warning) = scanner.warnings().first() {
        return Err(ScrubberError::BlockingLimitation(warning));
    }
    writer.flush().map_err(output_error)?;
    output.sync_all().map_err(output_error)?;
    hooks
        .step(ExportStep::BeforePublish)
        .map_err(output_error)?;
    if !job.begin_publish() {
        return Ok(false);
    }
    hooks.step(ExportStep::Publishing).map_err(output_error)?;
    let open = stat_fd(output.as_raw_fd()).map_err(output_error)?;
    let named = stat_at(stage.fd(), TEMP, libc::AT_SYMLINK_NOFOLLOW).map_err(output_error)?;
    if identity(&open) != identity(&named)
        || open.st_nlink != 1
        || open.st_mode & 0o7777 != 0o600
        || open.st_uid != unsafe { libc::geteuid() }
    {
        return Err(ScrubberError::UnsafeStaging);
    }
    checked(unsafe {
        libc::renameatx_np(
            stage.fd(),
            TEMP.as_ptr(),
            stage.parent.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_EXCL,
        )
    })
    .map_err(output_error)?;
    stage.temp_exists = false;
    Ok(true)
}
