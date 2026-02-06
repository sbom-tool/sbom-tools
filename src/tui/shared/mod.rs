//! Shared rendering functions used by both App (diff mode) and ViewApp (view mode).
//!
//! These pure rendering functions take domain types directly (`&QualityReport`,
//! `&Violation`) with no app-specific dependencies, enabling both TUIs to
//! delegate to common code.

pub mod compliance;
pub mod components;
pub mod licenses;
pub mod quality;
pub mod source;
pub mod vulnerabilities;
