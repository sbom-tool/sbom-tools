//! Diff graph vertex representation.

use crate::model::CanonicalId;
use std::hash::{Hash, Hasher};

/// Vertex in the diff graph representing an alignment position.
///
/// Each vertex represents a position pair (`left_pos`, `right_pos`) in the
/// comparison of two SBOMs.
#[derive(Debug, Clone)]
pub struct DiffVertex {
    /// Position in the old (left) SBOM
    pub left_pos: Option<CanonicalId>,
    /// Position in the new (right) SBOM
    pub right_pos: Option<CanonicalId>,
    /// Components that were processed together at this vertex
    pub processed_together: Vec<CanonicalId>,
}

impl DiffVertex {
    /// Create a new diff vertex
    #[must_use]
    pub const fn new(left_pos: Option<CanonicalId>, right_pos: Option<CanonicalId>) -> Self {
        Self {
            left_pos,
            right_pos,
            processed_together: Vec::new(),
        }
    }

    /// Create the start vertex (both positions at beginning)
    #[must_use]
    pub const fn start() -> Self {
        Self::new(None, None)
    }

    /// Check if this is the end vertex (both positions exhausted)
    #[must_use]
    pub fn is_end(&self) -> bool {
        self.left_pos.is_none() && self.right_pos.is_none() && !self.processed_together.is_empty()
    }
}

impl PartialEq for DiffVertex {
    fn eq(&self, other: &Self) -> bool {
        self.left_pos == other.left_pos && self.right_pos == other.right_pos
    }
}

impl Eq for DiffVertex {}

impl Hash for DiffVertex {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.left_pos.hash(state);
        self.right_pos.hash(state);
    }
}

/// Edge in the diff graph representing a diff operation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum DiffEdge {
    /// Component was removed from old SBOM
    ComponentRemoved {
        component_id: CanonicalId,
        cost: u32,
    },
    /// Component was added in new SBOM
    ComponentAdded {
        component_id: CanonicalId,
        cost: u32,
    },
    /// Component version changed
    VersionChanged {
        component_id: CanonicalId,
        old_version: String,
        new_version: String,
        cost: u32,
    },
    /// Component license changed
    LicenseChanged {
        component_id: CanonicalId,
        cost: u32,
    },
    /// Component supplier changed
    SupplierChanged {
        component_id: CanonicalId,
        cost: u32,
    },
    /// New vulnerability introduced
    VulnerabilityIntroduced {
        component_id: CanonicalId,
        vuln_id: String,
        cost: u32,
    },
    /// Existing vulnerability resolved
    VulnerabilityResolved {
        component_id: CanonicalId,
        vuln_id: String,
        reward: i32,
    },
    /// Dependency relationship added
    DependencyAdded {
        from: CanonicalId,
        to: CanonicalId,
        cost: u32,
    },
    /// Dependency relationship removed
    DependencyRemoved {
        from: CanonicalId,
        to: CanonicalId,
        cost: u32,
    },
    /// Component unchanged (zero cost transition)
    ComponentUnchanged { component_id: CanonicalId },
}

#[allow(dead_code)]
impl DiffEdge {
    /// Get the cost of this edge
    pub const fn cost(&self) -> i32 {
        match self {
            Self::ComponentRemoved { cost, .. }
            | Self::ComponentAdded { cost, .. }
            | Self::VersionChanged { cost, .. }
            | Self::LicenseChanged { cost, .. }
            | Self::SupplierChanged { cost, .. }
            | Self::VulnerabilityIntroduced { cost, .. }
            | Self::DependencyAdded { cost, .. }
            | Self::DependencyRemoved { cost, .. } => *cost as i32,
            Self::VulnerabilityResolved { reward, .. } => *reward,
            Self::ComponentUnchanged { .. } => 0,
        }
    }

    /// Check if this edge represents a change (non-zero cost)
    pub const fn is_change(&self) -> bool {
        !matches!(self, Self::ComponentUnchanged { .. })
    }
}
