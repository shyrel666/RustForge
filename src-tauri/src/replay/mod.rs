//! Persistent, human-triggered HTTP replay workspace.
//!
//! Network execution, bounded capture, immutable run persistence and run
//! comparison live here so Tauri commands remain a thin transport layer.

pub mod model;
pub mod service;

pub use model::{
    ReplayBodySnapshot, ReplayHeader, ReplayRequestInput, ReplayRequestInputSnapshot, ReplayRun,
    ReplayRunDiff, ReplayRunPage, ReplayRunSummary, ReplayScopeSnapshot, ReplaySession,
    ReplayValueDiff, TlsPolicy,
};
