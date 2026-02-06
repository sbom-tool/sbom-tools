//! Concrete `ViewState` implementations.
//!
//! This module contains view state machines that implement the `ViewState`
//! trait from `tui::traits`. Each view handles its own key events and
//! state management independently.
//!
//! Currently, the Quality tab serves as a proof of concept. Other tabs
//! can be migrated incrementally as needed.

pub mod quality;

pub(crate) use quality::QualityView;
