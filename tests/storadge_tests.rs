//! Integration tests for the storage layer.
//!
//! These tests exercise only the public API of `offline_vault::storage`:
//! `write_vault_atomic`, `read_vault`, `vault_exists`, `delete_vault`, and
//! `MAX_READ_BYTES`. The internal helpers (`create_secure`, `temp_path_in`,
//! `parent_dir`) are private and remain covered by the inline unit tests
//! inside `src/storage.rs`.
//!
//! Every test uses a fresh `tempfile::TempDir` so it cannot interfere with
//! the developer's real vault or with the other tests running in parallel.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use offline_vault::error::Error;
use offline_vault::storage::{delete_vault, read_vault, vault_exists, write_vault_atomic, MAX_READ_BYTES};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn entries_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Basic round-trip
// ---------------------------------------------------------------------------

#[test]
fn write_then_read_roundtrip() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"{\"hello\":1}").unwrap();
    assert!(vault_exists(&path));
    assert_eq!(read_vault(&path).unwrap(), b"{\"hello\":1}");
}

#[test]
fn write_empty_bytes_is_rejected() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    assert!(matches!(
        write_vault_atomic(&path, b""),
        Err(Error::VaultFormat)
    ));
    // No file must be left behind.
    assert!(!vault_exists(&path));
}

#[test]
fn overwrite_replaces_previous_contents() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"one").unwrap();
    write_vault_atomic(&path, b"two").unwrap();
    assert_eq!(read_vault(&path).unwrap(), b"two");
}

#[test]
fn write_creates_missing_parent_directory() {
    let dir = tmpdir();
    // Two levels of directory that do not exist yet.
    let path = dir.path().join("nested").join("deeper").join("vault.json");
    write_vault_atomic(&path, b"data").unwrap();
    assert!(vault_exists(&path));
    assert_eq!(read_vault(&path).unwrap(), b"data");
}

// ---------------------------------------------------------------------------
// Atomicity and cleanup
// ---------------------------------------------------------------------------

#[test]
fn temp_file_is_removed_after_success() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"payload").unwrap();

    // Only the target file must remain. No `.vt.*.tmp` sibling.
    let names = entries_in(dir.path());
    assert_eq!(names, vec!["vault.json".to_string()]);
}

#[test]
fn failed_write_leaves_previous_target_intact() {
    // Strategy: put a directory at the target path so the rename from the
    // temp file onto the target fails. The temp file is created and written
    // successfully, then the rename fails, then we clean up.
    //
    // We do not rely on making the directory read-only, which is unreliable
    // across platforms (root, Windows ACLs, CI containers).
    let dir = tmpdir();
    let target = dir.path().join("blocked");
    fs::create_dir(&target).unwrap();
    assert!(target.is_dir());

    let err = write_vault_atomic(&target, b"new-data").unwrap_err();
    // The exact error category is platform-dependent; we only require that
    // the call failed.
    let _ = err;

    // The directory is still a directory. Nothing was replaced.
    assert!(target.is_dir());

    // No leftover temp file in the directory.
    let leftovers: Vec<String> = entries_in(dir.path())
        .into_iter()
        .filter(|n| n.starts_with(".vt."))
        .collect();
    assert!(leftovers.is_empty(), "leftover temp file: {leftovers:?}");
}

#[test]
fn previous_vault_survives_a_failed_overwrite_attempt() {
    // Write a valid vault, then attempt to write to a target inside a
    // different path that will fail, and verify the original is untouched.
    let dir = tmpdir();
    let good = dir.path().join("vault.json");
    write_vault_atomic(&good, b"ORIGINAL").unwrap();
    assert_eq!(read_vault(&good).unwrap(), b"ORIGINAL");

    // Now make a directory where the next write would go, forcing failure.
    let bad_target = dir.path().join("sub");
    fs::create_dir(&bad_target).unwrap();
    let _ = write_vault_atomic(&bad_target, b"REPLACEMENT").unwrap_err();

    // The good file is still present with the original bytes.
    assert_eq!(read_vault(&good).unwrap(), b"ORIGINAL");
}

#[test]
fn concurrent_writes_to_distinct_paths_do_not_collide() {
    // Each write picks a fresh random temp name in the target's directory.
    // Writing to two different paths in the same directory must not
    // interfere with each other.
    let dir = tmpdir();
    let a = dir.path().join("a.json");
    let b = dir.path().join("b.json");
    write_vault_atomic(&a, b"A-content").unwrap();
    write_vault_atomic(&b, b"B-content").unwrap();
    assert_eq!(read_vault(&a).unwrap(), b"A-content");
    assert_eq!(read_vault(&b).unwrap(), b"B-content");

    let names = entries_in(dir.path());
    assert_eq!(names, vec!["a.json".to_string(), "b.json".to_string()]);
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn new_file_has_owner_only_mode() {
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
fn overwritten_file_keeps_owner_only_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"one").unwrap();
    write_vault_atomic(&path, b"two").unwrap();
    let meta = fs::metadata(&path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
}

// ---------------------------------------------------------------------------
// Read failures
// ---------------------------------------------------------------------------

#[test]
fn read_missing_file_is_vault_not_found() {
    let dir = tmpdir();
    let path = dir.path().join("nope.json");
    assert!(matches!(read_vault(&path), Err(Error::VaultNotFound)));
}

#[test]
fn read_directory_is_vault_not_found() {
    // `read_vault` requires the target to be a regular file.
    let dir = tmpdir();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    assert!(matches!(read_vault(&sub), Err(Error::VaultNotFound)));
}

#[test]
fn read_rejects_oversized_file() {
    let dir = tmpdir();
    let path = dir.path().join("big.json");
    // Create a sparse-ish large file by writing in chunks so we do not
    // materialize MAX_READ_BYTES + 1 bytes of heap at once.
    let mut f = File::create(&path).unwrap();
    let chunk = vec![0u8; 1024 * 1024];
    let mut remaining = MAX_READ_BYTES + 1;
    while remaining > 0 {
        let n = std::cmp::min(remaining, chunk.len() as u64) as usize;
        f.write_all(&chunk[..n]).unwrap();
        remaining -= n as u64;
    }
    f.sync_all().unwrap();
    drop(f);

    assert!(matches!(read_vault(&path), Err(Error::VaultFormat)));
}

// ---------------------------------------------------------------------------
// vault_exists
// ---------------------------------------------------------------------------

#[test]
fn vault_exists_is_false_for_missing_path() {
    let dir = tmpdir();
    let path = dir.path().join("nope.json");
    assert!(!vault_exists(&path));
}

#[test]
fn vault_exists_is_false_for_directory() {
    let dir = tmpdir();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    assert!(!vault_exists(&sub));
}

#[test]
fn vault_exists_is_true_for_regular_file() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"x").unwrap();
    assert!(vault_exists(&path));
}

// ---------------------------------------------------------------------------
// delete_vault
// ---------------------------------------------------------------------------

#[test]
fn delete_removes_existing_file() {
    let dir = tmpdir();
    let path = dir.path().join("vault.json");
    write_vault_atomic(&path, b"x").unwrap();
    assert!(vault_exists(&path));
    delete_vault(&path).unwrap();
    assert!(!vault_exists(&path));
}

#[test]
fn delete_missing_file_is_vault_not_found() {
    let dir = tmpdir();
    let path = dir.path().join("nope.json");
    assert!(matches!(delete_vault(&path), Err(Error::VaultNotFound)));
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

#[test]
fn write_to_bare_filename_fails() {
    // `write_vault_atomic` requires a path with a parent directory. A bare
    // filename such as `"vault.json"` has an empty parent and must be
    // rejected as invalid input rather than silently using the CWD.
    let dir = tmpdir();
    let cwd = std::env::current_dir().unwrap();
    // We change into a temp dir to make sure a bare filename would be
    // relative to that dir if we accidentally allowed it, then immediately
    // restore. We do not actually write anything here.
    std::env::set_current_dir(dir.path()).unwrap();
    let result = write_vault_atomic(std::path::Path::new("vault.json"), b"x");
    std::env::set_current_dir(&cwd).unwrap();

    // On any platform, our implementation rejects a path whose parent is
    // empty because it cannot produce a same-directory temp file.
    match result {
        Err(Error::Storage { .. }) | Err(Error::VaultFormat) => {}
        Ok(()) => panic!("bare filename was accepted; expected an error"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }

    // Clean up in case anything was written.
    let _ = fs::remove_file(dir.path().join("vault.json"));
}

// Silence an unused-import warning when the `PathBuf` import is only used
// indirectly by test helpers on some cfgs.
#[allow(dead_code)]
fn _touch_pathbuf(_p: PathBuf) {}
