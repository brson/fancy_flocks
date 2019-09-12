/// A self-deleting flock that tracks whether a protected value needs
/// to be refreshed

use std::ops::DerefMut;
use std::io::{Seek, SeekFrom, Read, Write, Result, ErrorKind};
use std::fs::File;
use std::path::Path;
use std::cell::Cell;
use sd_flock::SdFlock;
use rand::random;

pub struct DirtyFlock(SdFlock, Cell<Epoch>, Cell<LockedExclusive>);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct Epoch {
    era: u64, // Randomly initialized
    rev: u64, // Randomly iniitalized, incremented on write
}

type LockedExclusive = bool;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum State {
    Dirty,
    Clean,
}

impl DirtyFlock {
    pub fn new<P>(p: P) -> DirtyFlock
        where P: AsRef<Path>
    {
        let epoch = Epoch { era: 0, rev: 0 };
        DirtyFlock(SdFlock::new(p), Cell::new(epoch), Cell::new(false))
    }

    pub fn lock_shared(&self) -> Result<State> {
        self.init_take(SdFlock::lock_shared, false)
    }

    pub fn lock_exclusive(&self) -> Result<State> {
        self.init_take(SdFlock::lock_exclusive, true)
    }

    pub fn try_lock_shared(&self) -> Result<State> {
        self.init_take(SdFlock::try_lock_shared, false)
    }

    pub fn try_lock_exclusive(&self) -> Result<State> {
        self.init_take(SdFlock::try_lock_exclusive, true)
    }

    pub fn unlock(&self) -> Result<()> {
        if self.2.get() {
            self.bump_epoch()?;
        }

        self.0.unlock()?;

        self.2.set(false);

        Ok(())
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub fn file(&mut self) -> &mut File {
        self.0.file()
    }

    fn path_file_size(&self) -> Result<u64> {
        match self.0.path().metadata() {
            Ok(m) => Ok(m.len()),
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    Ok(0)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn file_size(&self) -> Result<u64> {
        let mut file = self.0.borrow_file_mut();
        let file = file.deref_mut().as_mut().expect("locked file");
        Ok(file.metadata()?.len())
    }

    fn new_epoch(&self) -> Result<()> {
        // TODO assert exclusive lock
        let epoch = Epoch { era: random(), rev: random() };
        self.write_epoch(epoch)?;
        Ok(())
    }

    fn bump_epoch(&self) -> Result<()> {
        // TODO assert exclusive lock
        let old_epoch = self.1.get();
        let new_epoch = Epoch { era: old_epoch.era, rev: old_epoch.rev + 1 };
        self.write_epoch(new_epoch)?;
        self.1.set(new_epoch);
        Ok(())
    }

    fn read_epoch(&self) -> Result<Epoch> {
        // TODO assert lock
        let buf = &mut [0; 16];
        let mut file = self.0.borrow_file_mut();
        let file = file.deref_mut().as_mut().expect("locked file");
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(buf)?;
        let epoch = array_to_epoch(buf);
        Ok(epoch)
    }

    fn write_epoch(&self, epoch: Epoch) -> Result<()> {
        // TODO assert exclusive lock
        {
            let buf = &mut epoch_to_array(epoch);
            let mut file_ = self.0.borrow_file_mut();
            let file = file_.deref_mut().as_mut().expect("locked file");
            file.seek(SeekFrom::Start(0))?;
            file.write_all(buf)?;
        }
        assert_eq!(self.read_epoch()?, epoch);
        Ok(())
    }

    fn init_take(&self, lock: fn(&SdFlock) -> Result<()>,
                 exclusive: bool) -> Result<State>
    {
        let known_epoch = self.1.get();

        loop {
            // If there's no epoch, create one
            if self.path_file_size()? == 0 {
                // Take the exclusive lock so we can write the epoch.
                // If we can't get the lock we've raced and somebody
                // else will create the epoch.
                if self.0.try_lock_exclusive().is_ok() {
                    match self.file_size() {
                        Ok(sz) if sz == 0 => {
                            // Still need to create the epoch
                            if let Err(e) = self.new_epoch() {
                                self.0.unlock().expect("unlock on error path");
                                return Err(e);
                            }
                        }
                        Ok(_) => {
                            // Somebody else has created the epoch
                        }
                        Err(e) => {
                            self.0.unlock().expect("unlock on error path");
                            return Err(e);
                        }
                    }
                    self.0.unlock().expect("internal unlock");
                }
            }
            
            lock(&self.0)?;

            match self.file_size() {
                Ok(sz) if sz != 0 => {
                    match self.read_epoch() {
                        Ok(epoch) => {
                            self.1.set(epoch);
                            self.2.set(exclusive);
                            if epoch == known_epoch {
                                return Ok(State::Clean);
                            } else {
                                return Ok(State::Dirty);
                            }
                        }
                        Err(e) => {
                            self.0.unlock().expect("unlock on error path");
                            return Err(e);
                        }
                    }
                }
                Ok(_) => {
                    // We raced on deleting the lockfile. Try again
                    self.0.unlock().expect("internal unlock");
                    continue;
                }
                Err(e) => {
                    self.0.unlock().expect("unlock on error path");
                    return Err(e);
                }
            }
        }
    }
}

fn epoch_to_array(epoch: Epoch) -> [u8; 16] {
    [
        (epoch.era >> 0) as u8,
        (epoch.era >> 8) as u8,
        (epoch.era >> 16) as u8,
        (epoch.era >> 24) as u8,
        (epoch.era >> 32) as u8,
        (epoch.era >> 40) as u8,
        (epoch.era >> 48) as u8,
        (epoch.era >> 56) as u8,
        (epoch.rev >> 0) as u8,
        (epoch.rev >> 8) as u8,
        (epoch.rev >> 16) as u8,
        (epoch.rev >> 24) as u8,
        (epoch.rev >> 32) as u8,
        (epoch.rev >> 40) as u8,
        (epoch.rev >> 48) as u8,
        (epoch.rev >> 56) as u8,
    ]
}

fn array_to_epoch(ar: &[u8; 16]) -> Epoch {
    Epoch  {
        era: ((ar[0] as u64) << 0)
            | ((ar[1] as u64) << 8)
            | ((ar[2] as u64) << 16)
            | ((ar[3] as u64) << 24)
            | ((ar[4] as u64) << 32)
            | ((ar[5] as u64) << 40)
            | ((ar[6] as u64) << 48)
            | ((ar[7] as u64) << 56),
        rev: ((ar[8] as u64) << 0)
            | ((ar[9] as u64) << 8)
            | ((ar[10] as u64) << 16)
            | ((ar[11] as u64) << 24)
            | ((ar[12] as u64) << 32)
            | ((ar[13] as u64) << 40)
            | ((ar[14] as u64) << 48)
            | ((ar[15] as u64) << 56)
    }
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;
    use super::*;

    #[test]
    fn smoke() {
        let dir = TempDir::new("dirtyflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = DirtyFlock::new(&path);
        let flock2 = DirtyFlock::new(&path);

        assert_eq!(State::Dirty, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_exclusive().unwrap());
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_exclusive().unwrap());
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());

        assert_eq!(State::Dirty, flock2.try_lock_exclusive().unwrap());
        assert!(flock2.unlock().is_ok());
        assert_eq!(State::Dirty, flock1.try_lock_exclusive().unwrap());
        assert!(flock1.unlock().is_ok());

        assert_eq!(State::Dirty, flock2.try_lock_shared().unwrap());
        assert!(flock2.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_exclusive().unwrap());
        assert!(flock1.unlock().is_ok());

        assert_eq!(State::Dirty, flock2.try_lock_shared().unwrap());
        assert!(flock2.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock2.try_lock_shared().unwrap());
        assert!(flock2.unlock().is_ok());
    }

    #[test]
    fn drop_unlocked() {
        let dir = TempDir::new("dirtyflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = DirtyFlock::new(&path);
        let flock2 = DirtyFlock::new(&path);

        assert_eq!(State::Dirty, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
        drop(flock2); // Deletes the unlocked flock
        assert_eq!(State::Dirty, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
    }

    #[test]
    fn drop_locked() {
        let dir = TempDir::new("dirtyflock").unwrap();
        let path = dir.path().join("flock");
        let flock1 = DirtyFlock::new(&path);
        let flock2 = DirtyFlock::new(&path);

        assert_eq!(State::Dirty, flock1.try_lock_shared().unwrap());
        drop(flock2); // Doesn't delete the locked flock
        assert!(flock1.unlock().is_ok());
        assert_eq!(State::Clean, flock1.try_lock_shared().unwrap());
        assert!(flock1.unlock().is_ok());
    }

}



