//! Descriptor-based private key files for Linux and WSL's Linux filesystem.
//!
//! The trusted principals are root and the effective service UID. Every path
//! component is opened without following symlinks. The immediate directory is
//! private to the service UID; root-owned sticky directories such as `/tmp` are
//! allowed only as earlier ancestors. Windows filesystem ACLs are outside this
//! Unix permission policy.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub use linux::open_private;
#[cfg(target_os = "linux")]
pub(crate) use linux::write_new_private;

/// Unsupported platforms fail closed before accessing a key file.
#[cfg(not(target_os = "linux"))]
pub fn open_private(_: &std::path::Path) -> crate::Result<std::fs::File> {
    Err(crate::Error::Input)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn write_new_private(_: &std::path::Path, _: &[u8]) -> crate::Result<()> {
    Err(crate::Error::Input)
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::{Error, Result};
    use rustix::{
        fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags},
        process::geteuid,
    };
    use std::{
        ffi::{OsStr, OsString},
        fs::File,
        io::Write,
        os::unix::ffi::OsStrExt,
        path::{Component, Path},
    };

    fn system<T>(result: rustix::io::Result<T>) -> Result<T> {
        result.map_err(|_| Error::Transport)
    }

    fn ancestor_allowed(uid: u32, mode: u32, service_uid: u32) -> bool {
        ((uid == 0 || uid == service_uid) && mode & 0o022 == 0) || (uid == 0 && mode & 0o1000 != 0)
    }

    fn parent_allowed(uid: u32, mode: u32, service_uid: u32, writing: bool) -> bool {
        uid == service_uid && (mode & 0o7777 == 0o700 || (!writing && mode & 0o7777 == 0o500))
    }

    fn private_allowed(uid: u32, mode: u32, service_uid: u32) -> bool {
        uid == service_uid && matches!(mode & 0o7777, 0o400 | 0o600)
    }

    fn validate_private(file: &File, service_uid: u32) -> Result<()> {
        let stat = system(fs::fstat(file))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || !private_allowed(stat.st_uid, stat.st_mode, service_uid)
            || stat.st_nlink != 1
        {
            return Err(Error::Input);
        }
        Ok(())
    }

    /// Resolve a parent once, retaining the validated directory descriptor.
    fn open_parent(path: &Path, writing: bool) -> Result<(File, OsString)> {
        let raw = path.as_os_str().as_bytes();
        if raw.is_empty()
            || raw.last() == Some(&b'/')
            || raw.rsplit(|byte| *byte == b'/').next() == Some(b".")
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(Error::Input);
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut names = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Normal(name) => names.push(name.to_owned()),
                Component::RootDir | Component::CurDir => (),
                Component::ParentDir | Component::Prefix(_) => return Err(Error::Input),
            }
        }
        let leaf = names.pop().ok_or(Error::Input)?;
        let service_uid = geteuid().as_raw();
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = system(fs::open("/", flags, Mode::empty()))?;
        let stat = system(fs::fstat(&directory))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || !ancestor_allowed(stat.st_uid, stat.st_mode, service_uid)
        {
            return Err(Error::Input);
        }
        for name in names {
            directory = system(fs::openat(&directory, &name, flags, Mode::empty()))?;
            let stat = system(fs::fstat(&directory))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                || !ancestor_allowed(stat.st_uid, stat.st_mode, service_uid)
            {
                return Err(Error::Input);
            }
        }
        let stat = system(fs::fstat(&directory))?;
        if !parent_allowed(stat.st_uid, stat.st_mode, service_uid, writing) {
            return Err(Error::Input);
        }
        // O_PATH needs only traversal permissions for earlier ancestors. Open
        // this same directory for reading so the writer can fsync its handle.
        let parent: File = system(fs::openat(
            &directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ))?
        .into();
        let stat = system(fs::fstat(&parent))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || !parent_allowed(stat.st_uid, stat.st_mode, service_uid, writing)
        {
            return Err(Error::Input);
        }
        Ok((parent, leaf))
    }

    /// Open a regular, singly linked private file owned by the effective UID.
    ///
    /// The leaf must have exactly mode 0400 or 0600 and its immediate directory
    /// exactly 0500 or 0700. Validation and subsequent reads use the same file
    /// descriptor. Callers must separately bound and validate the file contents.
    pub fn open_private(path: &Path) -> Result<File> {
        let (parent, leaf) = open_parent(path, false)?;
        let file: File = system(fs::openat(
            &parent,
            &leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        ))?
        .into();
        validate_private(&file, geteuid().as_raw())?;
        Ok(file)
    }

    struct Pending<'a> {
        parent: &'a File,
        name: OsString,
        unpublished: bool,
    }
    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            if self.unpublished {
                let _ = fs::unlinkat(self.parent, &self.name, AtFlags::empty());
            }
        }
    }

    fn create_temporary(parent: &File) -> Result<(File, Pending<'_>)> {
        for _ in 0..16 {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).map_err(|_| Error::Transport)?;
            let name = OsString::from(format!(".spiral-key-{}.tmp", hex::encode(random)));
            let fd = match fs::openat(
                parent,
                &name,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC
                    | OFlags::NOCTTY,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::EXIST) => continue,
                Err(_) => return Err(Error::Transport),
            };
            let pending = Pending {
                parent,
                name,
                unpublished: true,
            };
            let file = File::from(fd);
            // Creation permissions are filtered by umask; set the desired
            // private permissions on the already-created descriptor instead.
            system(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            validate_private(&file, geteuid().as_raw())?;
            return Ok((file, pending));
        }
        Err(Error::Transport)
    }

    fn write_new_at(parent: &File, leaf: &OsStr, bytes: &[u8]) -> Result<()> {
        let (mut file, mut pending) = create_temporary(parent)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        system(fs::renameat_with(
            parent,
            &pending.name,
            parent,
            leaf,
            RenameFlags::NOREPLACE,
        ))?;
        // Publication has happened. A subsequent directory sync failure must
        // not remove the destination, which can already be visible to readers.
        pending.unpublished = false;
        parent.sync_all()?;
        Ok(())
    }

    /// Durably publish a new private file without replacing any existing name.
    ///
    /// The immediate directory must be owned by the effective UID at exactly
    /// 0700. An existing destination (including a symlink, FIFO or directory)
    /// is never replaced. Unsupported NOREPLACE fails closed. Unpublished temp
    /// names are removed on failure on a best-effort basis. If syncing the
    /// directory fails after publication, this returns an error and the final
    /// file may already exist; callers must not assume an error means absence.
    pub(crate) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
        let (parent, leaf) = open_parent(path, true)?;
        write_new_at(&parent, &leaf, bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs::{self as stdfs, DirBuilder, OpenOptions, Permissions},
            io::Read,
            os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            path::PathBuf,
        };

        struct Fixture {
            path: PathBuf,
        }
        impl Fixture {
            fn new() -> Self {
                let mut random = [0; 16];
                getrandom::getrandom(&mut random).unwrap();
                let path = std::env::temp_dir().join(format!(
                    "spiral-keyfiles-{}-{}",
                    std::process::id(),
                    hex::encode(random)
                ));
                DirBuilder::new().mode(0o700).create(&path).unwrap();
                stdfs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
                Self { path }
            }
            fn key(&self, name: &str, contents: &[u8]) -> PathBuf {
                let path = self.path.join(name);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                file.write_all(contents).unwrap();
                file.set_permissions(Permissions::from_mode(0o600)).unwrap();
                path
            }
            fn entries(&self) -> Vec<OsString> {
                let mut names = stdfs::read_dir(&self.path)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                names.sort();
                names
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = stdfs::set_permissions(&self.path, Permissions::from_mode(0o700));
                let _ = stdfs::remove_dir_all(&self.path);
            }
        }

        #[test]
        fn owner_and_mode_policy_is_exact() {
            for mode in [0o400, 0o600] {
                assert!(private_allowed(1001, mode, 1001));
            }
            for mode in [
                0, 0o200, 0o500, 0o640, 0o644, 0o660, 0o700, 0o1600, 0o2600, 0o4600,
            ] {
                assert!(!private_allowed(1001, mode, 1001), "mode {mode:o}");
            }
            assert!(!private_allowed(0, 0o600, 1001));
            assert!(!private_allowed(1002, 0o600, 1001));
            assert!(parent_allowed(1001, 0o700, 1001, true));
            assert!(parent_allowed(1001, 0o500, 1001, false));
            assert!(!parent_allowed(1001, 0o500, 1001, true));
            for mode in [0o755, 0o750, 0o770, 0o1700, 0o2700, 0o4700] {
                assert!(!parent_allowed(1001, mode, 1001, false));
            }
            assert!(!parent_allowed(0, 0o700, 1001, false));
            assert!(ancestor_allowed(0, 0o755, 1001));
            assert!(ancestor_allowed(1001, 0o700, 1001));
            assert!(ancestor_allowed(0, 0o1777, 1001));
            assert!(!ancestor_allowed(0, 0o777, 1001));
            assert!(!ancestor_allowed(1001, 0o1777, 1001));
            assert!(!ancestor_allowed(1002, 0o755, 1001));
        }

        #[test]
        fn private_files_and_read_only_parent_are_accepted() {
            let fixture = Fixture::new();
            let path = fixture.key("auth", &[42; 32]);
            for mode in [0o400, 0o600] {
                stdfs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
                let mut contents = Vec::new();
                open_private(&path)
                    .unwrap()
                    .read_to_end(&mut contents)
                    .unwrap();
                assert_eq!(contents, [42; 32]);
            }
            stdfs::set_permissions(&fixture.path, Permissions::from_mode(0o500)).unwrap();
            assert!(open_private(&path).is_ok());
            assert!(matches!(
                write_new_private(&fixture.path.join("new"), b"key"),
                Err(Error::Input)
            ));
        }

        #[test]
        fn unsafe_file_modes_are_rejected_before_reading() {
            let fixture = Fixture::new();
            let path = fixture.key("auth", b"key");
            for mode in [0o640, 0o644, 0o700, 0o1600, 0o2600, 0o4600] {
                stdfs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
                assert!(matches!(open_private(&path), Err(Error::Input)));
            }
        }

        #[test]
        fn leaf_symlinks_directories_and_hardlinks_are_rejected() {
            let fixture = Fixture::new();
            let path = fixture.key("auth", b"key");
            let link = fixture.path.join("symbolic");
            symlink(&path, &link).unwrap();
            assert!(open_private(&link).is_err());
            let directory = fixture.path.join("directory");
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            assert!(matches!(open_private(&directory), Err(Error::Input)));
            let hardlink = fixture.path.join("hardlink");
            stdfs::hard_link(&path, &hardlink).unwrap();
            assert!(matches!(open_private(&path), Err(Error::Input)));
            assert!(matches!(open_private(&hardlink), Err(Error::Input)));
        }

        #[test]
        fn parent_symlinks_and_writable_ancestors_are_rejected() {
            let fixture = Fixture::new();
            let actual = fixture.path.join("actual");
            DirBuilder::new().mode(0o700).create(&actual).unwrap();
            let path = actual.join("auth");
            write_new_private(&path, b"key").unwrap();
            let link = fixture.path.join("linked");
            symlink(&actual, &link).unwrap();
            assert!(open_private(&link.join("auth")).is_err());
            assert!(write_new_private(&link.join("new"), b"key").is_err());
            stdfs::set_permissions(&fixture.path, Permissions::from_mode(0o777)).unwrap();
            assert!(matches!(open_private(&path), Err(Error::Input)));
            assert!(matches!(
                write_new_private(&actual.join("new"), b"key"),
                Err(Error::Input)
            ));
        }

        #[test]
        fn immediate_parent_must_be_private_even_when_ancestor_is_allowed() {
            let fixture = Fixture::new();
            let path = fixture.key("auth", b"key");
            for mode in [0o755, 0o750, 0o770, 0o1700] {
                stdfs::set_permissions(&fixture.path, Permissions::from_mode(mode)).unwrap();
                assert!(matches!(open_private(&path), Err(Error::Input)));
                assert!(matches!(
                    write_new_private(&fixture.path.join("new"), b"key"),
                    Err(Error::Input)
                ));
            }
        }

        #[test]
        fn ambiguous_paths_are_rejected() {
            let fixture = Fixture::new();
            fixture.key("auth", b"key");
            let paths = [
                PathBuf::new(),
                fixture.path.join("../auth"),
                fixture.path.join("./../auth"),
                PathBuf::from(format!("{}/auth/", fixture.path.display())),
                fixture.path.join("auth/."),
            ];
            for path in paths {
                assert!(matches!(open_private(&path), Err(Error::Input)));
                assert!(matches!(
                    write_new_private(&path, b"key"),
                    Err(Error::Input)
                ));
            }
        }

        #[test]
        fn opened_file_remains_the_validated_inode_after_rename() {
            let fixture = Fixture::new();
            let path = fixture.key("auth", b"original key");
            let mut opened = open_private(&path).unwrap();
            stdfs::rename(&path, fixture.path.join("old")).unwrap();
            fixture.key("auth", b"replacement key");
            let mut contents = Vec::new();
            opened.read_to_end(&mut contents).unwrap();
            assert_eq!(contents, b"original key");
        }

        #[test]
        fn publication_is_private_and_never_overwrites_existing_names() {
            let fixture = Fixture::new();
            let path = fixture.path.join("auth");
            write_new_private(&path, b"original key").unwrap();
            let stat = stdfs::metadata(&path).unwrap();
            assert_eq!(stat.mode() & 0o7777, 0o600);
            assert_eq!(stat.uid(), geteuid().as_raw());
            assert_eq!(stat.nlink(), 1);
            assert!(write_new_private(&path, b"replacement key").is_err());
            assert_eq!(stdfs::read(&path).unwrap(), b"original key");
            let link = fixture.path.join("link");
            symlink(&path, &link).unwrap();
            assert!(write_new_private(&link, b"replacement key").is_err());
            assert!(stdfs::symlink_metadata(&link).unwrap().is_symlink());
            let directory = fixture.path.join("directory");
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            assert!(write_new_private(&directory, b"replacement key").is_err());
            assert!(directory.is_dir());
            assert_eq!(
                fixture.entries(),
                ["auth", "directory", "link"].map(OsString::from)
            );
        }

        #[test]
        fn publication_uses_the_retained_parent_after_its_rename() {
            let mut fixture = Fixture::new();
            let destination = fixture.path.join("auth");
            let (parent, leaf) = open_parent(&destination, true).unwrap();
            let moved = fixture.path.with_extension("moved");
            stdfs::rename(&fixture.path, &moved).unwrap();
            fixture.path = moved;
            write_new_at(&parent, &leaf, b"key").unwrap();
            assert_eq!(stdfs::read(fixture.path.join("auth")).unwrap(), b"key");
            assert!(!destination.exists());
        }

        #[test]
        fn restrictive_umask_does_not_change_published_permissions() {
            const CHILD: &str = "SPIRAL_KEYFILES_UMASK_CHILD";
            if std::env::var_os(CHILD).is_some() {
                rustix::process::umask(Mode::all());
                let fixture = Fixture::new();
                let path = fixture.path.join("auth");
                write_new_private(&path, b"key").unwrap();
                assert_eq!(stdfs::metadata(path).unwrap().mode() & 0o7777, 0o600);
                return;
            }
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "keyfiles::linux::tests::restrictive_umask_does_not_change_published_permissions",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }
}
