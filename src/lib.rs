//! Library root for `offline-vault`.
//!
//! Every module lives here so that:
//!   * the binary in `src/main.rs` is a thin entry point, and
//!   * integration tests under `tests/` can link against the crate.
//!
//! `#![deny(unsafe_code)]` forbids `unsafe` everywhere except where a module
//! re-enables it locally with `#[allow(unsafe_code)]` on specific items. The
//! only module that does so is `memory_lock`.

#![deny(unsafe_code)]

pub mod app;
pub mod autolock;
pub mod clipboard;
pub mod crypto;
pub mod error;
pub mod memory_lock;
pub mod password_generator;
pub mod security;
pub mod storage;
pub mod ui;
pub mod vault;
