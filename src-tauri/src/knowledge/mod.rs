//! Version-pinned, offline security-standard knowledge packs.
//!
//! Findings and tasks persist only `{ framework, version, id }`. Human-facing
//! titles and guidance are derived from JSON packs that are embedded in the
//! application and validated before startup; no runtime network fetch occurs.

pub mod model;
pub mod registry;

pub use model::{KnowledgeCard, StandardReference};
pub use registry::{
    lookup, references_from_json, references_to_json, remediation_for, resolve,
    validate_builtin_registry, validate_references, KnowledgeLookup, ReferenceState,
    UnresolvedReference,
};
