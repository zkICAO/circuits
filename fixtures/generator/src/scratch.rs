//! A private working directory that removes itself.
//!
//! The generator writes private keys while it works. A fixed path under the
//! shared temporary directory would let anyone on the machine place a symlink
//! there first and redirect those writes, and would make two runs at once
//! overwrite each other's keys.

use std::io::Read;
#[cfg(test)]
use std::path::Path;

use std::path::PathBuf;

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(name: &str) -> Self {
        let mut random = [0u8; 16];

        std::fs::File::open("/dev/urandom")
            .expect("cannot open /dev/urandom")
            .read_exact(&mut random)
            .expect("cannot read /dev/urandom");

        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();

        let path = std::env::temp_dir().join(format!("zkicao-{name}-{suffix}"));

        // The mode is applied as the directory is created, so it is never
        // briefly readable under the process umask, and creation is not
        // recursive so anything already at the path is an error rather than
        // something to write through.
        let mut builder = std::fs::DirBuilder::new();

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            builder.mode(0o700);
        }

        builder
            .create(&path)
            .expect("cannot create a working directory");

        Self { path }
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_are_unique_and_private() {
        let a = Scratch::new("test");

        let b = Scratch::new("test");

        assert_ne!(a.path(), b.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(a.path()).unwrap().permissions().mode();

            assert_eq!(
                mode & 0o777,
                0o700,
                "a private key directory must not be readable by others"
            );
        }
    }

    #[test]
    fn a_directory_removes_itself_with_its_keys() {
        let path = {
            let scratch = Scratch::new("test");

            std::fs::write(scratch.join("key.pem"), b"private").unwrap();

            scratch.path().to_path_buf()
        };

        assert!(!path.exists(), "a private key must not outlive the run");
    }
}
