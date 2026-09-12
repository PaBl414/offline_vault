//! Vault file I/O with restrictive permissions and atomic replacement.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result, StorageErrorKind};

/// Mode used for a freshly created vault file on Unix: owner read/write only.
#[cfg(unix)]
const VAULT_FILE_MODE: u32 = 0o600;

/// Max bytes we will read from a vault file into memory.
pub const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// Read the entire vault file into memory.
pub fn read_vault(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).map_err(|e| map_io(&e))?;
    if !meta.is_file() {
        return Err(Error::VaultNotFound);
    }
    if meta.len() > MAX_READ_BYTES {
        return Err(Error::VaultFormat);
    }
    fs::read(path).map_err(|e| map_io(&e))
}

/// Whether a vault file exists at `path`.
pub fn vault_exists(path: &Path) -> bool {
    matches!(fs::metadata(path), Ok(m) if m.is_file())
}

/// Write `bytes` atomically to `path` with restrictive permissions.
pub fn write_vault_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::VaultFormat);
    }

    let dir = parent_dir(path)?;
    let tmp_path = temp_path_in(&dir);

    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| map_io(&e))?;
    }

    let write_result = (|| -> Result<()> {
        let mut file = create_secure(&tmp_path)?;
        file.write_all(bytes).map_err(|e| map_io(&e))?;
        file.flush().map_err(|e| map_io(&e))?;
        file.sync_all().map_err(|e| map_io(&e))?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(map_io(&e));
    }

    #[cfg(unix)]
    {
        if let Ok(dir_file) = File::open(&dir) {
            let _ = dir_file.sync_all();
        }
    }

    Ok(())
}

/// Delete the vault file at `path`.
pub fn delete_vault(path: &Path) -> Result<()> {
    fs::remove_file(path).map_err(|e| map_io(&e))
}

fn parent_dir(path: &Path) -> Result<PathBuf> {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => Ok(p.to_path_buf()),
        _ => Err(Error::Storage {
            kind: StorageErrorKind::InvalidInput,
        }),
    }
}

fn temp_path_in(dir: &Path) -> PathBuf {
    let a = crate::crypto::random_bytes::<8>().unwrap_or([0u8; 8]);
    let b = crate::crypto::random_bytes::<8>().unwrap_or([0u8; 8]);
    let mut name = String::with_capacity(4 + 32 + 4);
    name.push_str(".vt.");
    for byte in a.iter().chain(b.iter()) {
        use std::fmt::Write;
        let _ = write!(&mut name, "{:02x}", byte);
    }
    name.push_str(".tmp");
    dir.join(name)
}

fn create_secure(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(VAULT_FILE_MODE);
    }

    opts.open(path).map_err(|e| map_io(&e))
}

fn map_io(err: &std::io::Error) -> Error {
    match err.kind() {
        std::io::ErrorKind::NotFound => Error::VaultNotFound,
        _ => Error::Storage {
            kind: StorageErrorKind::from_io(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = tmpdir();
        let path = dir.path().join("vault.json");
        write_vault_atomic(&path, b"{\"hello\":1}").unwrap();
        assert!(vault_exists(&path));
        assert_eq!(read_vault(&path).unwrap(), b"{\"hello\":1}");
    }

    #[test]
    fn overwrite_replaces_previous_file() {
        let dir = tmpdir();
        let path = dir.path().join("vault.json");
        write_vault_atomic(&path, b"one").unwrap();
        write_vault_atomic(&path, b"two").unwrap();
        assert_eq!(read_vault(&path).unwrap(), b"two");
    }

    #[test]
    fn failed_write_leaves_previous_file_intact() {
        let dir = tmpdir();
        let target = dir.path().join("vault.json");
        write_vault_atomic(&target, b"original").unwrap();

        let blocked = dir.path().join("blocked.json");
        fs::create_dir(&blocked).unwrap();
        let err = write_vault_atomic(&blocked, b"new").unwrap_err();
        let _ = err;

        assert_eq!(read_vault(&target).unwrap(), b"original");
    }

    #[test]
    fn temp_file_is_cleaned_up_on_success() {
        let dir = tmpdir();
        let path = dir.path().join("vault.json");
        write_vault_atomic(&path, b"data").unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "vault.json");
    }

    #[cfg(unix)]
    #[test]
    fn new_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let path = dir.path().join("vault.json");
        write_vault_atomic(&path, b"secret").unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn no_world_readable_window_for_new_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let path = dir.path().join("probe");
        let file = create_secure(&path).unwrap();
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o} at open time");
    }

    #[test]
    fn create_secure_refuses_to_overwrite() {
        let dir = tmpdir();
        let path = dir.path().join("probe");
        let _f = create_secure(&path).unwrap();
        assert!(create_secure(&path).is_err());
    }

    #[test]
    fn read_missing_file_is_vault_not_found() {
        let dir = tmpdir();
        let path = dir.path().join("nope.json");
        assert!(matches!(read_vault(&path), Err(Error::VaultNotFound)));
    }

    #[test]
    fn read_rejects_oversized_file() {
        let dir = tmpdir();
        let path = dir.path().join("big.json");
        let mut f = File::create(&path).unwrap();
        let buf = vec![0u8; 1024 * 1024];
        let mut remaining = MAX_READ_BYTES + 1;
        while remaining > 0 {
            let n = std::cmp::min(remaining, buf.len() as u64) as usize;
            f.write_all(&buf[..n]).unwrap();
            remaining -= n as u64;
        }
        f.sync_all().unwrap();
        drop(f);
        assert!(matches!(read_vault(&path), Err(Error::VaultFormat)));
    }
}
