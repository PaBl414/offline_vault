
```markdown
# offline-vault

A local, offline-only password manager written entirely in Rust.

`offline-vault` is a native desktop application that stores your passwords in a
single, encrypted vault file on your own machine. It makes no network
connections of any kind: no server, no cloud storage, no telemetry, no
analytics, and no update checkers. Everything is on your disk.

## Security model

- **Master password**: only ever used in memory to derive keys. It is never
  saved, logged, or transmitted.
- **Key derivation**: Argon2id with `time_cost=3`, `memory_cost=65536`
  (64 MiB), `parallelism=1`, `hash_len=32`, and a 16-byte random salt
  generated when the vault is created.
- **Key hierarchy**:
  1. Master password → **Master Key** via Argon2id.
  2. Master Key → **Key Encryption Key (KEK)** via HKDF-SHA256 with
     `info = b"vault-key-encryption"`.
  3. A random 32-byte **Vault Key** is generated once per vault.
  4. The Vault Key is wrapped with AES-256-GCM using the KEK
     (AAD = `b"vault_key"`).
  5. The vault payload is encrypted with AES-256-GCM using the Vault Key
     (AAD = `b"vault"`).
- **AEAD**: AES-256-GCM with a fresh 12-byte OS-random nonce for every
  encryption. The authentication tag is stored together with the ciphertext.
- **Vault file**: JSON with Base64-encoded binary fields. All fields are
  validated before use.
- **Secure memory**: sensitive buffers use `zeroize` to wipe on drop. On
  Unix-like systems and Windows, memory locking (`mlock` / `VirtualLock`) is
  attempted on a best-effort basis; failure to lock does not prevent the
  application from running.
- **File permissions**: on Unix-like systems the vault file is created with
  owner-only permissions (`0600`) before any data is written.
- **Atomic save**: writes go to a temporary file in the same directory, are
  flushed and `fsync`-ed, then atomically renamed over the previous vault.
  A failed save never corrupts the previous vault.
- **Auto-lock**: after 3 minutes of genuine keyboard or mouse inactivity the
  vault locks, the Vault Key is wiped, and decrypted data is dropped.
- **Clipboard**: copied passwords are cleared from the clipboard after 20
  seconds, but only if the clipboard still contains exactly that password.

### Limitations, stated honestly

- Complete physical removal of every copy of a secret from process memory
  cannot be guaranteed on general-purpose operating systems. We minimize
  plaintext lifetime and wipe every buffer we own, but we do not claim more
  than that.
- Memory locking is best-effort. If the OS refuses (`mlock` limits,
  `VirtualLock` quota), the application continues to run.
- The vault is a single file. If you lose it or forget the master password,
  the data is unrecoverable. There is no recovery mechanism by design.

## Requirements

- Stable Rust (see `rust-toolchain.toml`) and Cargo, for building from source.
- A desktop session (X11 or Wayland on Linux; Windows 10/11 on Windows).
- No Python, Node.js, browser, or local server is required at runtime.

## Building on Windows 10/11 (x86_64)

Target triple: `x86_64-pc-windows-msvc`

### 1. Install Rust

The recommended way is `rustup`. In PowerShell:

```powershell
winget install --id Rustlang.Rustup -s winget
```

If `winget` fails (for example because of a certificate error on the
`msstore` source), download the official installer directly:

```powershell
Invoke-WebRequest -OutFile "$env:TEMP\rustup-init.exe" https://win.rustup.rs/x86_64
& "$env:TEMP\rustup-init.exe"
```

Press `1` for the default MSVC toolchain and confirm.

Close and reopen PowerShell so `PATH` picks up `%USERPROFILE%\.cargo\bin`.
Verify:

```powershell
cargo --version
rustc --version
```

### 2. Install the MSVC build tools

Rust on Windows uses the MSVC linker by default. Without it, `cargo build`
will fail at the linking step. Install the Visual Studio Build Tools with the
"Desktop development with C++" workload:

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools
```

Then open the Visual Studio Installer, choose "Modify" for the Build Tools,
and check "Desktop development with C++". This installs MSVC, the Windows SDK,
and `link.exe`.

### 3. Build

```powershell
cd C:\path\to\offline-vault
cargo build --release
```

The binary is placed at:

```text
target\release\offline-vault.exe
```

### 4. Run

```powershell
.\target\release\offline-vault.exe
```

`offline-vault.exe` is a standalone executable. It does not require Rust,
Cargo, Python, or any runtime to be present on the target machine. Copy the
single `.exe` file anywhere and run it. The vault file is created at:

```text
%APPDATA%\offline-vault\vault.json
```

regardless of where the `.exe` itself lives.

### Optional: cross-compile a Linux binary from Windows

Windows cannot produce a Linux ELF binary natively — Rust needs a Linux
linker for that. The two practical options are:

**WSL2** (recommended):

```powershell
wsl --install -d Ubuntu
```

Then inside WSL:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libxcb1-dev libxkbcommon-dev libwayland-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cd /mnt/c/path/to/offline-vault
cargo build --release --target x86_64-unknown-linux-gnu
```

The binary is at `target/x86_64-unknown-linux-gnu/release/offline-vault`.

**Docker + `cross`** (if you already have Docker Desktop):

```powershell
cargo install cross
rustup target add x86_64-unknown-linux-gnu
cross build --release --target x86_64-unknown-linux-gnu
```

## Building on Arch Linux (x86_64)

Target triple: `x86_64-unknown-linux-gnu`

### 1. Install Rust

Either via `rustup`:

```bash
sudo pacman -S rustup
rustup default stable
```

or directly from the distribution:

```bash
sudo pacman -S rust cargo
```

The `rustup` route allows switching toolchains later; the `pacman` route is
simpler if you only need the current stable.

### 2. Install GUI development libraries

`eframe`/`egui` needs a few development packages to build the window and
input layer. On Arch:

```bash
sudo pacman -S libxcb libxkbcommon wayland
```

If you build inside a minimal container without a desktop, also install:

```bash
sudo pacman -S base-devel
```

for `gcc`, which is Rust's default linker on Linux.

### 3. Build

```bash
cd ~/offline-vault
cargo build --release --locked
```

`--locked` guarantees the exact dependency versions from `Cargo.lock` are
used. If `Cargo.lock` is not present yet, run `cargo generate-lockfile`
first.

The binary is at:

```text
target/release/offline-vault
```

### 4. Run

```bash
./target/release/offline-vault
```

The vault file is created at:

```text
~/.local/share/offline-vault/vault.json
```

### 5. Moving a vault from Windows to Arch

The vault file format is identical on every supported platform. Copy:

```text
Windows:  %APPDATA%\offline-vault\vault.json
```

to:

```text
Arch:     ~/.local/share/offline-vault/vault.json
```

For example:

```bash
mkdir -p ~/.local/share/offline-vault
cp /media/usb/vault.json ~/.local/share/offline-vault/
chmod 600 ~/.local/share/offline-vault/vault.json
```

Start the application, enter the same master password, and the vault unlocks.
The Argon2id parameters are stored inside the vault file, so the same password
produces the same Master Key on any platform.

### Optional: build for another Linux distribution

The binary produced on Arch links against the system C library (`glibc`) and
the GUI runtime libraries (`libxcb`, `libxkbcommon`, `libwayland`). A binary
built on Arch will run on Arch and on most other modern distributions, but a
binary built on an older distribution is more likely to run on newer ones than
the reverse. If you need a portable Linux binary, build on the oldest
distribution you intend to support, or build per distribution.

For a fully static binary (no system `libc` dependency), you would need to
build with the `x86_64-unknown-linux-musl` target. That is not covered here
because `eframe`'s GUI dependencies (`xcb`, `wayland`) are not trivially
statically linkable; it is possible but requires more setup.

## Running the tests

```bash
cargo test --all-targets
```

The suite covers:

- Argon2id against a published known-answer vector.
- AES-256-GCM encrypt/decrypt round-trip.
- Wrong-password rejection, opaque error.
- Tamper detection on ciphertext, nonce, AAD, and wrapped key.
- Atomic save semantics, including failed-save preservation.
- Secure-buffer wiping and `Debug` redaction.
- Vault create / save / reopen with the correct password.
- Vault-format validation against malformed inputs.
- Clipboard conditional-clear behavior.
- Nonce uniqueness across successive encryptions.

Tests never print real secrets.

## Using the application

1. Run the executable.
2. On first launch, enter a master password (at least 12 characters) twice
   and click **Create Vault**. The vault file is written atomically with
   restrictive permissions.
3. On later launches, enter the master password to unlock.
4. Add, edit, delete, and search entries in the main window. Passwords and
   TOTP secrets are never shown in the list view.
5. Use **Copy Password** or **Copy Username** to place a value on the
   clipboard. Copied passwords are cleared after 20 seconds if the clipboard
   still contains them.
6. The vault locks automatically after 3 minutes of inactivity, or when you
   press **Lock**.

## Overriding the vault path

Set the `OFFLINE_VAULT_PATH` environment variable to use a vault file
somewhere other than the platform default.

Windows (current session):

```powershell
$env:OFFLINE_VAULT_PATH = "D:\vaults\my-vault.json"
.\target\release\offline-vault.exe
```

Arch (current session):

```bash
OFFLINE_VAULT_PATH=~/vaults/my-vault.json ./target/release/offline-vault
```

## Data file format

The vault file is JSON. Binary fields are Base64-encoded.

```json
{
  "version": 1,
  "kdf": {
    "name": "argon2id",
    "salt": "<base64, 16 bytes>",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 1,
    "hash_len": 32
  },
  "wrapped_key": { "nonce": "<base64, 12 bytes>", "ciphertext": "<base64>" },
  "vault":       { "nonce": "<base64, 12 bytes>", "ciphertext": "<base64>" }
}
```

The decrypted `vault` payload is a JSON array of entries:

```json
[
  {
    "id": "<32 hex chars>",
    "title": "...",
    "username": "...",
    "password": "...",
    "url": "...",
    "totp": "...",
    "notes": "..."
  }
]
```

All fields are validated on load. Malformed or unknown structures are
rejected safely.
