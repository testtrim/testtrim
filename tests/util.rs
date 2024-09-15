use std::{env, path::{Path, PathBuf}};

pub struct ChangeWorkingDirectory {
    current_dir: PathBuf,
}

impl ChangeWorkingDirectory {
    pub fn new(path: &Path) -> Self {
        // FIXME: error handling?
        let current_dir = env::current_dir().unwrap();
        env::set_current_dir(path).unwrap();
        ChangeWorkingDirectory {
            current_dir: current_dir.to_path_buf(),
        }
    }
}

impl Drop for ChangeWorkingDirectory {
    fn drop(&mut self) {
        // FIXME: error handling?
        env::set_current_dir(&self.current_dir).unwrap();
    }
}
