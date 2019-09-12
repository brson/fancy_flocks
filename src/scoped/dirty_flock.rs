use std::path::Path;
use std::fs::File;
use std::io::Result;
use dirty_flock::DirtyFlock as UnscopedDirtyFlock;

pub use dirty_flock::State;

pub struct DirtyFlock(UnscopedDirtyFlock);

pub struct DirtyFlockShared<'a>(&'a mut UnscopedDirtyFlock, State);

pub struct DirtyFlockExclusive<'a>(&'a mut UnscopedDirtyFlock, State);

impl DirtyFlock {
    pub fn new<P>(p: P) -> DirtyFlock
        where P: AsRef<Path>
    {
        DirtyFlock(UnscopedDirtyFlock::new(p))
    }

    pub fn lock_shared(&mut self) -> Result<DirtyFlockShared> {
        let state = self.0.lock_shared()?;
        Ok(DirtyFlockShared(&mut self.0, state))
    }

    pub fn try_lock_shared(&mut self) -> Result<DirtyFlockShared> {
        let state = self.0.try_lock_shared()?;
        Ok(DirtyFlockShared(&mut self.0, state))
    }

    pub fn lock_exclusive(&mut self) -> Result<DirtyFlockExclusive> {
        let state = self.0.lock_exclusive()?;
        Ok(DirtyFlockExclusive(&mut self.0, state))
    }

    pub fn try_lock_exclusive(&mut self) -> Result<DirtyFlockExclusive> {
        let state = self.0.try_lock_exclusive()?;
        Ok(DirtyFlockExclusive(&mut self.0, state))
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

impl<'a> DirtyFlockShared<'a> {
    pub fn state(&self) -> State {
        self.1
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub fn file(&mut self) -> &mut File {
        self.0.file()
    }
}

impl<'a> DirtyFlockExclusive<'a> {
    pub fn state(&self) -> State {
        self.1
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub fn file(&mut self) -> &mut File {
        self.0.file()
    }
}

impl<'a> Drop for DirtyFlockShared<'a> {
    fn drop(&mut self) {
        if let Err(e) = self.0.unlock() {
            error!("dropping scoped flock: {}", e);
        }
    }
}

impl<'a> Drop for DirtyFlockExclusive<'a> {
    fn drop(&mut self) {
        if let Err(e) = self.0.unlock() {
            error!("dropping scoped flock: {}", e);
        }
    }
}
