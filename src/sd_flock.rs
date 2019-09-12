//! Self-deleting flock

// FIXME: This needs a custom error type
// - report file open failures when directory doesn't exist
// - we could avoid calling unlock and just drop file handles if perf matters
// - windows ReFs inode detection

use std::cell::{RefCell, RefMut};
use std::fs::{File, OpenOptions};
use std::io::{self, Result};
use std::mem;
use std::path::{Path, PathBuf};
use fs2::FileExt;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

pub struct SdFlock(PathBuf, RefCell<Option<File>>);

type LockFn = fn(&File) -> Result<()>;
    
impl SdFlock {
    pub fn new<P>(p: P) -> SdFlock
        where P: AsRef<Path>
    {
        SdFlock(p.as_ref().to_owned(), RefCell::new(None))
    }

    pub fn lock_shared(&self) -> Result<()> {
        self.lock_finish(self.lock_start(File::lock_shared, false)?)
    }

    pub fn lock_exclusive(&self) -> Result<()> {
        self.lock_finish(self.lock_start(File::lock_exclusive, true)?)
    }

    pub fn try_lock_shared(&self) -> Result<()> {
        self.lock_finish(self.lock_start(File::try_lock_shared, false)?)
    }

    pub fn try_lock_exclusive(&self) -> Result<()> {
        self.lock_finish(self.lock_start(File::try_lock_exclusive, true)?)
    }

    pub fn unlock(&self) -> Result<()> {
        self.1.borrow().as_ref().expect("unlocking unlocked file").unlock()?;

        *self.1.borrow_mut() = None;

        Ok(())
    }

    pub fn file(&mut self) -> &mut File {
        self.1.get_mut().as_mut().expect("borrowing locked file")
    }

    pub (crate) fn borrow_file_mut(&self) -> RefMut<Option<File>> {
        self.1.borrow_mut()
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    fn has_lock(&self) -> bool {
        assert!(self.1.try_borrow_mut().is_ok());
        self.1.borrow_mut().is_some()
    }

    #[cfg(test)]
    fn try_lock_shared_start(&self) -> Result<(File, LockFn, bool)> {
        self.lock_start(File::try_lock_shared, false)
    }

    #[cfg(test)]
    fn try_lock_shared_finish(&self, st: (File, LockFn, bool)) -> Result<()> {
        self.lock_finish(st)
    }

    fn lock_start(&self, lf: LockFn, write: bool) -> Result<(File, LockFn, bool)> {
        assert!(!self.has_lock());
        let f = open(&self.0, write, false)?;
        Ok((f, lf, write))
    }

    fn lock_finish(&self, st: (File, LockFn, bool)) -> Result<()> {
        assert!(self.1.borrow_mut().is_none());

        let mut file = Some(st.0);
        let lock = st.1;
        let write = st.2;

        loop {
            lock(file.as_ref().expect(""))?;

            // Now that we've locked the file, check that it is
            // _really_ the file at the path we expect, and not some
            // deleted file dropped by another process. That delete is
            // done under an exclusive lock, so we know once we have a
            // lock, and the inode of our lockfile is the same as thet
            // inode at the lockfile path, that the file we've locked
            // is the one we expect.
            let file2 = open(&self.0, false, false);

            // This is pretty suspicious. It _appears_ that on
            // windows, when a file path is deleted while a lock on
            // that file's handle is held, trying to create a new file
            // at that location results in denied access until the
            // lock is dropped.  This dance detects that situation,
            // drops the lock and tries again.
            let file2 = if cfg!(windows) {
                if let Err(e) = file2 {
                    if e.kind() == io::ErrorKind::PermissionDenied {

                        let oldfile = mem::replace(&mut file, None);
                        drop(oldfile);

                        let file3 = open(&self.0, write, false);
                        match file3 {
                            Ok(file3) => {
                                debug!("windows lock / drop conflict");
                                let _ = mem::replace(&mut file, Some(file3));
                                continue;
                            }
                            Err(e) => {
                                debug!("failed windows lock / drop conflict");
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(e);
                    }
                } else {
                    file2
                }
            } else {
                file2
            };

            let file2 = file2.expect("");
            
            if same_file(&file.as_ref().expect(""), &file2)? {
                drop(file2);
                *self.1.borrow_mut() = file;
                return Ok(());
            } else {
                // Not the same file. Try again
                // NB: Closing file2 and trying from scratch because
                // file2 is opened without write perms. May be
                // possible to optimize this but need to worry about
                // windows non-advisory locks.
                debug!("lock / drop conflict");
                drop(file2);
                let newfile = Some(open(&self.0, write, false)?);
                let oldfile = mem::replace(&mut file, newfile);
                // Closing the handle will release the lock
                drop(oldfile);
            }
        }
    }
}

impl Drop for SdFlock {
    fn drop(&mut self) {
        assert!(!self.has_lock(), "dropping locked SdFlock");

        // Hold an exclusive lock while deleting the file. When
        // another process takes the lock again they'll reopen the
        // file and see that the inode has changed.
        if self.try_lock_exclusive().is_err() {
            // If we can't get an exclusive lock that means there are
            // other live instances of the lock, and we can count on
            // them to delete the file.
            return;
        }

        // TODO: Should these be non-fatal? It's not horrible to leave
        // the file on disk, while double-panic is.
        #[cfg(unix)]
        {
            use std::fs;
            let r = fs::remove_file(&self.0);
            if let Err(e) = r {
                error!("unable to remove lock file during drop: {}", e);
            }
        }
        #[cfg(windows)]
        {
            // Open a new handle to the lockfile set to delete on
            // close, then immediately close it.
            let f = open(&self.0, false, true);
            if let Err(e) = f {
                error!("unable to open lock file during drop: {}", e);
            } else {
                drop(f);
            }
        }
    }
}

fn open(p: &Path, write: bool, delete: bool) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(write).create(true);

    // On windows at least, to get read + create, we need append
    if !write { opts.append(true); }

    if delete {
        #[cfg(windows)] 
        const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000;
        #[cfg(windows)] 
        opts.custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
    }

    opts.open(p)
}

#[cfg(windows)]
#[allow(bad_style)]
fn same_file(file1: &File, file2: &File) -> Result<bool> {
    extern "system" {
        fn GetFileInformationByHandle(
            hFile: HANDLE,
            lpFileInformation: LPBY_HANDLE_FILE_INFORMATION,
        ) -> BOOL;
    }

    type DWORD = u32;
    type BOOL = i32;
    type LPBY_HANDLE_FILE_INFORMATION = *mut BY_HANDLE_FILE_INFORMATION;

    #[repr(C)]
    struct FILETIME {
        dwLowDateTime: DWORD,
        dwHighDateTime: DWORD,
    }

    #[repr(C)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: DWORD,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: DWORD,
        nFileSizeHigh: DWORD,
        nFileSizeLow: DWORD,
        nNumberOfLinks: DWORD,
        nFileIndexHigh: DWORD,
        nFileIndexLow: DWORD,
    }

    use std::mem;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::raw::HANDLE;

    let handle1 = file1.as_raw_handle();
    let handle2 = file2.as_raw_handle();

    // FIXME: Per MSDN this technique does not work for ReFS
    unsafe {
        let mut info1: BY_HANDLE_FILE_INFORMATION = mem::zeroed();
        let mut info2: BY_HANDLE_FILE_INFORMATION = mem::zeroed();
        let r1 = GetFileInformationByHandle(handle1, &mut info1);
        let r2 = GetFileInformationByHandle(handle2, &mut info2);
        if r1 == 0 || r2 == 0 {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber
           && info1.nFileIndexHigh == info2.nFileIndexHigh
           && info1.nFileIndexLow == info2.nFileIndexLow)
    }
}

#[cfg(unix)]
fn same_file(file1: &File, file2: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let inode1 = file1.metadata()?.ino();
    let inode2 = file2.metadata()?.ino();
    Ok(inode1 == inode2)
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;
    use super::SdFlock;
    use rand::{thread_rng, Rng};
    use std::thread;

    #[test]
    fn shared() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = SdFlock::new(&path);
        let flock2 = SdFlock::new(&path);
        assert!(flock1.try_lock_shared().is_ok());
        assert!(flock2.try_lock_shared().is_ok());
        assert!(flock1.unlock().is_ok());
        assert!(flock2.unlock().is_ok());
    }

    #[test]
    fn exclusive() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = SdFlock::new(&path);
        let flock2 = SdFlock::new(&path);
        assert!(flock1.try_lock_shared().is_ok());
        assert!(flock2.try_lock_exclusive().is_err());
        assert!(flock1.unlock().is_ok());
        assert!(flock2.try_lock_exclusive().is_ok());
        assert!(flock2.unlock().is_ok());
    }

    #[test]
    fn delete_on_drop() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");
        let flock = SdFlock::new(&path);
        assert!(flock.try_lock_shared().is_ok());
        assert!(flock.unlock().is_ok());
        assert!(path.exists());
        drop(flock);
        assert!(!path.exists());
    }

    #[test]
    fn no_delete_on_locked_drop() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = SdFlock::new(&path);
        let flock2 = SdFlock::new(&path);
        assert!(flock1.try_lock_shared().is_ok());
        assert!(path.exists());
        drop(flock2);
        assert!(path.exists());
        assert!(flock1.unlock().is_ok());
        assert!(path.exists());
        drop(flock1);
        assert!(!path.exists());
    }

    // This is testing the logic that solves the race condition
    // between two threads where one opens the lockfile then takes a
    // lock, while another deletes the lock file inbetween.
    #[test]
    fn reacquire() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = SdFlock::new(&path);
        let flock2 = SdFlock::new(&path);
        let flock3 = SdFlock::new(&path);
        // Open the file
        let state = flock1.try_lock_shared_start().unwrap();
        assert!(path.exists());
        // Drop the file
        drop(flock2);
        assert!(!path.exists());
        // Take the lock
        assert!(flock1.try_lock_shared_finish(state).is_ok());
        // Lock is reacquired on the correct file
        assert!(path.exists());
        assert!(flock3.try_lock_exclusive().is_err());
        assert!(flock1.unlock().is_ok());
    }

    #[test]
    fn stress_exclusive() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");

        let joins = (0..100).map(|_| {
            let path = path.clone();
            thread::spawn(move || {
                let flock = SdFlock::new(&path);
                for _ in 0..100 {
                    assert!(flock.lock_exclusive().is_ok());
                    assert!(flock.unlock().is_ok());
                }
            })
        });

        for join in joins {
            assert!(join.join().is_ok());
        }
    }

    #[test]
    fn stress_drop() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");

        let joins = (0..100).map(|_| {
            let path = path.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    drop(SdFlock::new(&path));
                }
            })
        });

        for join in joins {
            assert!(join.join().is_ok());
        }
    }

    #[test]
    fn stress_random() {
        let dir = TempDir::new("sdflock").unwrap();
        let path = dir.path().join("flock");

        let joins = (0..100).map(|_| {
            let path = path.clone();
            thread::spawn(move || {
                let flock = SdFlock::new(&path);
                let mut rng = thread_rng();
                for _ in 0..100 {
                    let rnd = rng.gen_range(0, 3);
                    if rnd == 0 {
                        assert!(flock.lock_shared().is_ok());
                        assert!(flock.unlock().is_ok());
                    } else if rnd == 1 {
                        assert!(flock.lock_exclusive().is_ok());
                        assert!(flock.unlock().is_ok());
                    } else if rnd == 2 {
                        drop(SdFlock::new(&path));
                    } else {
                        panic!()
                    }
                }
            })
        });

        for join in joins {
            assert!(join.join().is_ok());
        }
    }
}

