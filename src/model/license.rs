//! License data structures and SPDX expression handling.
//!
//! Uses the `spdx` crate for proper SPDX expression parsing and license
//! classification, with substring-based fallback for non-standard expressions.

use serde::{Deserialize, Serialize};
use std::fmt;

/// License expression following SPDX license expression syntax
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LicenseExpression {
    /// The raw license expression string
    pub expression: String,
    /// Whether this is a valid SPDX expression
    pub is_valid_spdx: bool,
}

impl LicenseExpression {
    /// Create a new license expression
    pub fn new(expression: String) -> Self {
        let is_valid_spdx = Self::validate_spdx(&expression);
        Self {
            expression,
            is_valid_spdx,
        }
    }

    /// Create from an SPDX license ID
    pub fn from_spdx_id(id: &str) -> Self {
        Self {
            expression: id.to_string(),
            is_valid_spdx: true,
        }
    }

    /// Validate an SPDX expression using the spdx crate.
    ///
    /// Uses lax parsing mode to accept common non-standard expressions
    /// (e.g., "Apache2" instead of "Apache-2.0", "/" instead of "OR").
    fn validate_spdx(expr: &str) -> bool {
        if expr.is_empty() || expr.contains("NOASSERTION") || expr.contains("NONE") {
            return false;
        }
        spdx::Expression::parse_mode(expr, spdx::ParseMode::LAX).is_ok()
    }

    /// Check if this expression includes a permissive license option.
    ///
    /// For OR expressions (e.g., "MIT OR GPL-2.0"), returns true if at least
    /// one branch is permissive (the licensee can choose the permissive option).
    /// Falls back to substring matching for non-parseable expressions.
    pub fn is_permissive(&self) -> bool {
        if let Ok(expr) = spdx::Expression::parse_mode(&self.expression, spdx::ParseMode::LAX) {
            expr.requirements().any(|req| {
                if let spdx::LicenseItem::Spdx { id, .. } = req.req.license {
                    !id.is_copyleft() && (id.is_osi_approved() || id.is_fsf_free_libre())
                } else {
                    false
                }
            })
        } else {
            // Fallback for non-standard expressions
            let expr_lower = self.expression.to_lowercase();
            expr_lower.contains("mit")
                || expr_lower.contains("apache")
                || expr_lower.contains("bsd")
                || expr_lower.contains("isc")
                || expr_lower.contains("unlicense")
        }
    }

    /// Check if this expression requires copyleft compliance.
    ///
    /// Returns true if any license term in the expression is copyleft.
    /// Falls back to substring matching for non-parseable expressions.
    pub fn is_copyleft(&self) -> bool {
        if let Ok(expr) = spdx::Expression::parse_mode(&self.expression, spdx::ParseMode::LAX) {
            expr.requirements().any(|req| {
                if let spdx::LicenseItem::Spdx { id, .. } = req.req.license {
                    id.is_copyleft()
                } else {
                    false
                }
            })
        } else {
            let expr_lower = self.expression.to_lowercase();
            expr_lower.contains("gpl")
                || expr_lower.contains("agpl")
                || expr_lower.contains("lgpl")
                || expr_lower.contains("mpl")
        }
    }

    /// Get the license family classification.
    ///
    /// For compound expressions:
    /// - OR: returns the most permissive option (licensee can choose)
    /// - AND: returns the most restrictive requirement
    ///   Falls back to substring matching for non-parseable expressions.
    pub fn family(&self) -> LicenseFamily {
        if let Ok(expr) = spdx::Expression::parse_mode(&self.expression, spdx::ParseMode::LAX) {
            let mut has_copyleft = false;
            let mut has_weak_copyleft = false;
            let mut has_permissive = false;
            let mut has_or = false;

            for node in expr.iter() {
                match node {
                    spdx::expression::ExprNode::Op(spdx::expression::Operator::Or) => {
                        has_or = true;
                    }
                    spdx::expression::ExprNode::Req(req) => {
                        if let spdx::LicenseItem::Spdx { id, .. } = req.req.license {
                            match classify_spdx_license(id) {
                                LicenseFamily::Copyleft => has_copyleft = true,
                                LicenseFamily::WeakCopyleft => has_weak_copyleft = true,
                                LicenseFamily::Permissive | LicenseFamily::PublicDomain => {
                                    has_permissive = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            // OR: licensee can choose the most permissive option
            if has_or && has_permissive {
                return LicenseFamily::Permissive;
            }

            // AND or single license: return the most restrictive
            if has_copyleft {
                LicenseFamily::Copyleft
            } else if has_weak_copyleft {
                LicenseFamily::WeakCopyleft
            } else if has_permissive {
                LicenseFamily::Permissive
            } else {
                LicenseFamily::Other
            }
        } else {
            // Fallback for non-parseable expressions
            self.family_from_substring()
        }
    }

    /// Substring-based fallback for license family classification.
    fn family_from_substring(&self) -> LicenseFamily {
        let expr_lower = self.expression.to_lowercase();
        if expr_lower.contains("mit")
            || expr_lower.contains("apache")
            || expr_lower.contains("bsd")
            || expr_lower.contains("isc")
            || expr_lower.contains("unlicense")
        {
            LicenseFamily::Permissive
        } else if expr_lower.contains("gpl")
            || expr_lower.contains("agpl")
            || expr_lower.contains("lgpl")
            || expr_lower.contains("mpl")
        {
            LicenseFamily::Copyleft
        } else if expr_lower.contains("proprietary") {
            LicenseFamily::Proprietary
        } else {
            LicenseFamily::Other
        }
    }
}

/// Classify an SPDX license ID into a license family.
fn classify_spdx_license(id: spdx::LicenseId) -> LicenseFamily {
    let name = id.name;

    // Check for public domain dedications
    if name == "CC0-1.0" || name == "Unlicense" || name == "0BSD" {
        return LicenseFamily::PublicDomain;
    }

    if id.is_copyleft() {
        // Distinguish weak copyleft (LGPL, MPL, EPL, CDDL) from strong copyleft (GPL, AGPL)
        let name_upper = name.to_uppercase();
        if name_upper.contains("LGPL")
            || name_upper.starts_with("MPL")
            || name_upper.starts_with("EPL")
            || name_upper.starts_with("CDDL")
            || name_upper.starts_with("EUPL")
            || name_upper.starts_with("OSL")
        {
            LicenseFamily::WeakCopyleft
        } else {
            LicenseFamily::Copyleft
        }
    } else if id.is_osi_approved() || id.is_fsf_free_libre() {
        LicenseFamily::Permissive
    } else {
        LicenseFamily::Other
    }
}

impl fmt::Display for LicenseExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.expression)
    }
}

impl Default for LicenseExpression {
    fn default() -> Self {
        Self {
            expression: "NOASSERTION".to_string(),
            is_valid_spdx: false,
        }
    }
}

/// License family classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LicenseFamily {
    Permissive,
    Copyleft,
    WeakCopyleft,
    Proprietary,
    PublicDomain,
    Other,
}

impl fmt::Display for LicenseFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permissive => write!(f, "Permissive"),
            Self::Copyleft => write!(f, "Copyleft"),
            Self::WeakCopyleft => write!(f, "Weak Copyleft"),
            Self::Proprietary => write!(f, "Proprietary"),
            Self::PublicDomain => write!(f, "Public Domain"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// License information for a component
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseInfo {
    /// Declared licenses from the component metadata
    pub declared: Vec<LicenseExpression>,
    /// Concluded license after analysis
    pub concluded: Option<LicenseExpression>,
    /// License evidence from scanning
    pub evidence: Vec<LicenseEvidence>,
}

impl LicenseInfo {
    /// Create new empty license info
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a declared license
    pub fn add_declared(&mut self, license: LicenseExpression) {
        self.declared.push(license);
    }

    /// Get all unique license expressions
    pub fn all_licenses(&self) -> Vec<&LicenseExpression> {
        let mut licenses: Vec<&LicenseExpression> = self.declared.iter().collect();
        if let Some(concluded) = &self.concluded {
            licenses.push(concluded);
        }
        licenses
    }

    /// Check if there are potential license conflicts across declared expressions.
    ///
    /// A conflict exists when one declared expression requires copyleft compliance
    /// and another declares proprietary terms. Note that a single expression like
    /// "MIT OR GPL-2.0" is NOT a conflict — it offers a choice.
    pub fn has_conflicts(&self) -> bool {
        let families: Vec<LicenseFamily> = self.declared.iter().map(LicenseExpression::family).collect();

        let has_copyleft = families.contains(&LicenseFamily::Copyleft);
        let has_proprietary = families.contains(&LicenseFamily::Proprietary);

        has_copyleft && has_proprietary
    }
}

/// License evidence from source scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseEvidence {
    /// The detected license
    pub license: LicenseExpression,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// File path where detected
    pub file_path: Option<String>,
    /// Line number in the file
    pub line_number: Option<u32>,
}

impl LicenseEvidence {
    /// Create new license evidence
    pub fn new(license: LicenseExpression, confidence: f64) -> Self {
        Self {
            license,
            confidence,
            file_path: None,
            line_number: None,
        }
    }
}
