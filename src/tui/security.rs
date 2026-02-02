//! Security analysis utilities for TUI.
//!
//! Provides blast radius analysis, risk indicators, and security-focused
//! utilities for security analysts working with SBOMs.

use std::collections::{HashMap, HashSet, VecDeque};

/// Component compliance data: (name, version, licenses, vulns\[(id, severity)\]).
pub type ComplianceComponentData = (String, Option<String>, Vec<String>, Vec<(String, String)>);

/// Blast radius analysis result for a component
#[derive(Debug, Clone, Default)]
pub struct BlastRadius {
    /// Direct dependents (components that directly depend on this)
    pub direct_dependents: Vec<String>,
    /// All transitive dependents (full blast radius)
    pub transitive_dependents: HashSet<String>,
    /// Maximum depth of impact
    pub max_depth: usize,
    /// Risk level based on impact
    pub risk_level: RiskLevel,
    /// Critical paths (paths to important components)
    pub critical_paths: Vec<Vec<String>>,
}

impl BlastRadius {
    /// Total number of affected components
    pub fn total_affected(&self) -> usize {
        self.transitive_dependents.len()
    }

    /// Compute blast radius impact description
    pub fn impact_description(&self) -> &'static str {
        match self.transitive_dependents.len() {
            0 => "No downstream impact",
            1..=5 => "Limited impact",
            6..=20 => "Moderate impact",
            21..=50 => "Significant impact",
            _ => "Critical impact - affects many components",
        }
    }
}

/// Risk level for a component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            RiskLevel::Low => "○",
            RiskLevel::Medium => "◐",
            RiskLevel::High => "●",
            RiskLevel::Critical => "◉",
        }
    }
}

/// Risk indicators for a component
#[derive(Debug, Clone, Default)]
pub struct RiskIndicators {
    /// Vulnerability count
    pub vuln_count: usize,
    /// Highest vulnerability severity
    pub highest_severity: Option<String>,
    /// Number of direct dependents
    pub direct_dependent_count: usize,
    /// Number of transitive dependents (blast radius)
    pub transitive_dependent_count: usize,
    /// License risk (unknown, copyleft, etc.)
    pub license_risk: LicenseRisk,
    /// Is this a direct dependency (depth 1)
    pub is_direct_dep: bool,
    /// Dependency depth from root
    pub depth: usize,
    /// Overall risk score (0-100)
    pub risk_score: u8,
    /// Overall risk level
    pub risk_level: RiskLevel,
}

impl RiskIndicators {
    /// Calculate risk score based on various factors
    pub fn calculate_risk_score(&mut self) {
        let mut score: u32 = 0;

        // Vulnerability contribution (0-40 points)
        score += match self.vuln_count {
            0 => 0,
            1 => 15,
            2..=5 => 25,
            _ => 40,
        };

        // Severity contribution (0-30 points)
        if let Some(ref sev) = self.highest_severity {
            let sev_lower = sev.to_lowercase();
            score += if sev_lower.contains("critical") {
                30
            } else if sev_lower.contains("high") {
                20
            } else if sev_lower.contains("medium") {
                10
            } else {
                5
            };
        }

        // Blast radius contribution (0-20 points)
        score += match self.transitive_dependent_count {
            0 => 0,
            1..=5 => 5,
            6..=20 => 10,
            21..=50 => 15,
            _ => 20,
        };

        // License risk contribution (0-10 points)
        score += match self.license_risk {
            LicenseRisk::None => 0,
            LicenseRisk::Low => 2,
            LicenseRisk::Medium => 5,
            LicenseRisk::High => 10,
        };

        self.risk_score = score.min(100) as u8;

        // Determine risk level
        self.risk_level = match self.risk_score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
    }
}

/// License risk level
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LicenseRisk {
    #[default]
    None,
    Low,      // Permissive (MIT, Apache, BSD)
    Medium,   // Weak copyleft (LGPL, MPL)
    High,     // Strong copyleft (GPL, AGPL) or Unknown
}

impl LicenseRisk {
    pub fn from_license(license: &str) -> Self {
        let lower = license.to_lowercase();

        if lower.contains("unlicense")
            || lower.contains("mit")
            || lower.contains("apache")
            || lower.contains("bsd")
            || lower.contains("isc")
            || lower.contains("cc0")
        {
            LicenseRisk::Low
        } else if lower.contains("lgpl") || lower.contains("mpl") || lower.contains("cddl") {
            LicenseRisk::Medium
        } else if lower.contains("gpl") || lower.contains("agpl") || lower.contains("unknown") {
            LicenseRisk::High
        } else {
            LicenseRisk::None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseRisk::None => "Unknown",
            LicenseRisk::Low => "Permissive",
            LicenseRisk::Medium => "Weak Copyleft",
            LicenseRisk::High => "Copyleft/Unknown",
        }
    }
}

/// Flagged item for analyst follow-up
#[derive(Debug, Clone)]
pub struct FlaggedItem {
    /// Component ID or name
    pub component_id: String,
    /// Reason for flagging
    pub reason: String,
    /// Optional analyst note
    pub note: Option<String>,
    /// Timestamp
    pub flagged_at: std::time::Instant,
}

/// Security analysis cache for the TUI
#[derive(Debug, Default)]
pub struct SecurityAnalysisCache {
    /// Cached blast radius for components
    pub blast_radius_cache: HashMap<String, BlastRadius>,
    /// Cached risk indicators
    pub risk_indicators_cache: HashMap<String, RiskIndicators>,
    /// Flagged items for follow-up
    pub flagged_items: Vec<FlaggedItem>,
    /// Components flagged (for quick lookup)
    pub flagged_set: HashSet<String>,
}

impl SecurityAnalysisCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute blast radius for a component using reverse dependency graph
    pub fn compute_blast_radius(
        &mut self,
        component_id: &str,
        reverse_graph: &HashMap<String, Vec<String>>,
    ) -> &BlastRadius {
        if self.blast_radius_cache.contains_key(component_id) {
            return &self.blast_radius_cache[component_id];
        }

        let mut blast = BlastRadius::default();

        // Direct dependents
        if let Some(direct) = reverse_graph.get(component_id) {
            blast.direct_dependents = direct.clone();
        }

        // BFS to find all transitive dependents
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut max_depth = 0usize;

        // Start with direct dependents
        for dep in &blast.direct_dependents {
            queue.push_back((dep.clone(), 1));
        }

        while let Some((node, depth)) = queue.pop_front() {
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node.clone());
            blast.transitive_dependents.insert(node.clone());
            max_depth = max_depth.max(depth);

            // Add this node's dependents
            if let Some(dependents) = reverse_graph.get(&node) {
                for dep in dependents {
                    if !visited.contains(dep) {
                        queue.push_back((dep.clone(), depth + 1));
                    }
                }
            }
        }

        blast.max_depth = max_depth;

        // Determine risk level based on blast radius
        blast.risk_level = match blast.transitive_dependents.len() {
            0 => RiskLevel::Low,
            1..=5 => RiskLevel::Low,
            6..=20 => RiskLevel::Medium,
            21..=50 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        self.blast_radius_cache
            .insert(component_id.to_string(), blast);
        &self.blast_radius_cache[component_id]
    }

    /// Flag a component for follow-up
    pub fn flag_component(&mut self, component_id: &str, reason: &str) {
        if !self.flagged_set.contains(component_id) {
            self.flagged_items.push(FlaggedItem {
                component_id: component_id.to_string(),
                reason: reason.to_string(),
                note: None,
                flagged_at: std::time::Instant::now(),
            });
            self.flagged_set.insert(component_id.to_string());
        }
    }

    /// Unflag a component
    pub fn unflag_component(&mut self, component_id: &str) {
        self.flagged_items
            .retain(|item| item.component_id != component_id);
        self.flagged_set.remove(component_id);
    }

    /// Toggle flag status
    pub fn toggle_flag(&mut self, component_id: &str, reason: &str) {
        if self.flagged_set.contains(component_id) {
            self.unflag_component(component_id);
        } else {
            self.flag_component(component_id, reason);
        }
    }

    /// Check if a component is flagged
    pub fn is_flagged(&self, component_id: &str) -> bool {
        self.flagged_set.contains(component_id)
    }

    /// Add note to a flagged component
    pub fn add_note(&mut self, component_id: &str, note: &str) {
        for item in &mut self.flagged_items {
            if item.component_id == component_id {
                item.note = Some(note.to_string());
                break;
            }
        }
    }

    /// Clear all caches
    pub fn clear(&mut self) {
        self.blast_radius_cache.clear();
        self.risk_indicators_cache.clear();
    }

    /// Invalidate cache for a specific component
    pub fn invalidate(&mut self, component_id: &str) {
        self.blast_radius_cache.remove(component_id);
        self.risk_indicators_cache.remove(component_id);
    }

    /// Get note for a flagged component
    pub fn get_note(&self, component_id: &str) -> Option<&str> {
        self.flagged_items
            .iter()
            .find(|item| item.component_id == component_id)
            .and_then(|item| item.note.as_deref())
    }
}

// ============================================================================
// Vulnerability Prioritization
// ============================================================================

/// Vulnerability priority information for sorting
#[derive(Debug, Clone)]
pub struct VulnPriority {
    /// Parsed CVSS score (0.0-10.0)
    pub cvss_score: f32,
    /// Severity level as numeric value (for sorting)
    pub severity_rank: u8,
    /// Fix urgency score (0-100)
    pub fix_urgency: u8,
    /// Blast radius of affected component
    pub blast_radius: usize,
    /// Whether this is a known exploited vulnerability
    pub is_known_exploited: bool,
}

impl Default for VulnPriority {
    fn default() -> Self {
        Self {
            cvss_score: 0.0,
            severity_rank: 0,
            fix_urgency: 0,
            blast_radius: 0,
            is_known_exploited: false,
        }
    }
}

/// Parse CVSS score from a string (e.g., "9.8", "CVSS:3.1/AV:N/AC:L/...")
pub fn parse_cvss_score(score_str: &str) -> f32 {
    // Try direct float parse first
    if let Ok(score) = score_str.parse::<f32>() {
        return score.clamp(0.0, 10.0);
    }

    // Try to extract from CVSS vector string
    if score_str.contains("CVSS:") {
        // Look for base score at the end or extract from metrics
        // Common format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (no score)
        // or with score appended
        if let Some(last_part) = score_str.split('/').next_back() {
            if let Ok(score) = last_part.parse::<f32>() {
                return score.clamp(0.0, 10.0);
            }
        }
    }

    0.0
}

/// Convert severity string to numeric rank for sorting
pub fn severity_to_rank(severity: &str) -> u8 {
    let s = severity.to_lowercase();
    if s.contains("critical") {
        4
    } else if s.contains("high") {
        3
    } else if s.contains("medium") || s.contains("moderate") {
        2
    } else if s.contains("low") {
        1
    } else {
        0 // Unknown/None
    }
}

/// Calculate fix urgency score (0-100) based on severity and blast radius
pub fn calculate_fix_urgency(severity_rank: u8, blast_radius: usize, cvss_score: f32) -> u8 {
    // Base score from severity (0-40)
    let severity_score = (severity_rank as u32) * 10;

    // CVSS contribution (0-30)
    let cvss_contribution = (cvss_score * 3.0) as u32;

    // Blast radius contribution (0-30)
    let blast_score = match blast_radius {
        0 => 0,
        1..=5 => 10,
        6..=20 => 20,
        _ => 30,
    };

    (severity_score + cvss_contribution + blast_score).min(100) as u8
}

/// Check if a vulnerability ID might be a known exploited vulnerability (KEV)
/// This is a heuristic - real KEV checking would need an API call
pub fn is_likely_known_exploited(vuln_id: &str, severity: &str) -> bool {
    // Critical CVEs with certain patterns are more likely to be exploited
    let is_critical = severity.to_lowercase().contains("critical");
    let is_recent_cve = vuln_id.starts_with("CVE-202"); // 2020+

    // Known high-profile vulnerabilities (simplified check)
    let known_patterns = [
        "CVE-2021-44228", // Log4Shell
        "CVE-2021-45046", // Log4j
        "CVE-2022-22965", // Spring4Shell
        "CVE-2023-44487", // HTTP/2 Rapid Reset
        "CVE-2024-3094",  // XZ Utils
    ];

    known_patterns.iter().any(|p| vuln_id.contains(p))
        || (is_critical && is_recent_cve)
}

// ============================================================================
// Version Downgrade Detection
// ============================================================================

/// Result of version comparison for downgrade detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionChange {
    /// Version increased (normal upgrade)
    Upgrade,
    /// Version decreased (potential attack)
    Downgrade,
    /// Same version
    NoChange,
    /// Cannot determine (unparseable versions)
    Unknown,
}

/// Detect if a version change is a downgrade (potential supply chain attack)
pub fn detect_version_downgrade(old_version: &str, new_version: &str) -> VersionChange {
    if old_version == new_version {
        return VersionChange::NoChange;
    }

    // Try semver parsing first
    if let (Some(old_parts), Some(new_parts)) = (
        parse_version_parts(old_version),
        parse_version_parts(new_version),
    ) {
        // Compare major.minor.patch
        for (old, new) in old_parts.iter().zip(new_parts.iter()) {
            if new > old {
                return VersionChange::Upgrade;
            } else if new < old {
                return VersionChange::Downgrade;
            }
        }
        // If we get here, versions are equal up to the compared parts
        if new_parts.len() < old_parts.len() {
            return VersionChange::Downgrade; // e.g., 1.2.3 -> 1.2
        } else if new_parts.len() > old_parts.len() {
            return VersionChange::Upgrade; // e.g., 1.2 -> 1.2.3
        }
        return VersionChange::NoChange;
    }

    // Fallback: lexicographic comparison (less reliable)
    if new_version < old_version {
        VersionChange::Downgrade
    } else if new_version > old_version {
        VersionChange::Upgrade
    } else {
        VersionChange::Unknown
    }
}

/// Parse version string into numeric parts
fn parse_version_parts(version: &str) -> Option<Vec<u32>> {
    // Remove common prefixes like 'v', 'V', 'version-'
    let cleaned = version
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or(version);

    let parts: Vec<u32> = cleaned
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// Check if a component change represents a security concern
#[derive(Debug, Clone)]
pub struct DowngradeWarning {
    pub component_name: String,
    pub old_version: String,
    pub new_version: String,
    pub severity: DowngradeSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeSeverity {
    /// Minor version downgrade (e.g., 1.2.3 -> 1.2.2)
    Minor,
    /// Major version downgrade (e.g., 2.0.0 -> 1.9.0)
    Major,
    /// Suspicious pattern (e.g., security patch removed)
    Suspicious,
}

impl DowngradeSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Minor => "Minor Downgrade",
            Self::Major => "Major Downgrade",
            Self::Suspicious => "Suspicious",
        }
    }
}

/// Analyze a version change for downgrade severity
pub fn analyze_downgrade(old_version: &str, new_version: &str) -> Option<DowngradeSeverity> {
    if detect_version_downgrade(old_version, new_version) != VersionChange::Downgrade {
        return None;
    }

    let old_parts = parse_version_parts(old_version)?;
    let new_parts = parse_version_parts(new_version)?;

    // Check if major version decreased
    if let (Some(&old_major), Some(&new_major)) = (old_parts.first(), new_parts.first()) {
        if new_major < old_major {
            return Some(DowngradeSeverity::Major);
        }
    }

    // Check for suspicious patterns (security-related version strings)
    let old_lower = old_version.to_lowercase();
    let new_lower = new_version.to_lowercase();
    if (old_lower.contains("security") || old_lower.contains("patch") || old_lower.contains("fix"))
        && !new_lower.contains("security")
        && !new_lower.contains("patch")
        && !new_lower.contains("fix")
    {
        return Some(DowngradeSeverity::Suspicious);
    }

    Some(DowngradeSeverity::Minor)
}

/// Sanitize a vulnerability ID to contain only safe characters.
/// Allows alphanumeric, hyphen, underscore, dot, and colon — sufficient
/// for CVE, GHSA, RUSTSEC, PYSEC, and other standard advisory IDs.
fn sanitize_vuln_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        .collect()
}

/// Format a CVE ID as a URL for opening in browser
pub fn cve_url(cve_id: &str) -> String {
    let safe_id = sanitize_vuln_id(cve_id);
    if safe_id.to_uppercase().starts_with("CVE-") {
        format!("https://nvd.nist.gov/vuln/detail/{}", safe_id.to_uppercase())
    } else if safe_id.to_uppercase().starts_with("GHSA-") {
        format!("https://github.com/advisories/{}", safe_id.to_uppercase())
    } else if safe_id.starts_with("RUSTSEC-") {
        format!("https://rustsec.org/advisories/{}", safe_id)
    } else if safe_id.starts_with("PYSEC-") {
        format!("https://osv.dev/vulnerability/{}", safe_id)
    } else {
        // Generic OSV lookup
        format!("https://osv.dev/vulnerability/{}", safe_id)
    }
}

/// Validate that a URL contains only characters from RFC 3986
/// (unreserved + reserved + percent-encoded). Rejects control characters,
/// spaces, backticks, pipes, and other non-URL characters that could be
/// misinterpreted by platform open commands.
fn is_safe_url(url: &str) -> bool {
    url.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ':' | '/' | '.' | '-' | '_' | '~' | '?' | '#' | '[' | ']' | '@' | '!' | '$'
                    | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | '%'
            )
    })
}

/// Open a URL in the default browser
pub fn open_in_browser(url: &str) -> Result<(), String> {
    if !is_safe_url(url) {
        return Err("URL contains unsafe characters".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }

    #[cfg(target_os = "windows")]
    {
        // Use explorer.exe instead of cmd /C start to avoid shell
        // metacharacter interpretation (e.g. & | > would be dangerous
        // with cmd.exe). explorer.exe receives the URL as a direct
        // process argument with no shell involved.
        std::process::Command::new("explorer")
            .arg(url)
            .spawn()
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }

    Ok(())
}

/// Copy text to system clipboard
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write to clipboard: {}", e))?;
        }
        child
            .wait()
            .map_err(|e| format!("Clipboard command failed: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        // Try xclip first, then xsel
        let result = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn();

        let mut child = match result {
            Ok(child) => child,
            Err(_) => std::process::Command::new("xsel")
                .args(["--clipboard", "--input"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("Failed to copy to clipboard: {}", e))?,
        };

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write to clipboard: {}", e))?;
        }
        child
            .wait()
            .map_err(|e| format!("Clipboard command failed: {}", e))?;
    }

    #[cfg(target_os = "windows")]
    {
        // Use clip.exe with stdin to avoid command injection via string interpolation
        use std::io::Write;
        let mut child = std::process::Command::new("clip")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write to clipboard: {}", e))?;
        }
        child
            .wait()
            .map_err(|e| format!("Clipboard command failed: {}", e))?;
    }

    Ok(())
}

// ============================================================================
// Attack Path Visualization
// ============================================================================

/// An attack path from an entry point to a vulnerable component
#[derive(Debug, Clone)]
pub struct AttackPath {
    /// The path of component names from entry point to target
    pub path: Vec<String>,
    /// The entry point (root component)
    pub entry_point: String,
    /// The vulnerable component (target)
    pub target: String,
    /// Path length (number of hops)
    pub depth: usize,
    /// Risk score based on path characteristics
    pub risk_score: u8,
}

impl AttackPath {
    /// Format the path as a readable string
    pub fn format(&self) -> String {
        self.path.join(" → ")
    }

    /// Get a short description of the path
    pub fn description(&self) -> String {
        if self.depth == 1 {
            "Direct dependency".to_string()
        } else {
            format!("{} hops", self.depth)
        }
    }
}

/// Find attack paths from root components to a vulnerable component
pub fn find_attack_paths(
    target: &str,
    forward_graph: &HashMap<String, Vec<String>>,
    root_components: &[String],
    max_paths: usize,
    max_depth: usize,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    // BFS from each root to find paths to target
    for root in root_components {
        if root == target {
            // Direct hit - root is the vulnerable component
            paths.push(AttackPath {
                path: vec![root.clone()],
                entry_point: root.clone(),
                target: target.to_string(),
                depth: 0,
                risk_score: 100, // Highest risk - direct exposure
            });
            continue;
        }

        // BFS to find path from this root to target
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        queue.push_back((root.clone(), vec![root.clone()]));
        visited.insert(root.clone());

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > max_depth {
                continue;
            }

            // Check all dependencies of current node
            if let Some(deps) = forward_graph.get(&current) {
                for dep in deps {
                    if dep == target {
                        // Found a path!
                        let mut full_path = path.clone();
                        full_path.push(dep.clone());
                        let depth = full_path.len() - 1;

                        // Risk score decreases with depth
                        let risk_score = match depth {
                            1 => 90,
                            2 => 70,
                            3 => 50,
                            4 => 30,
                            _ => 10,
                        };

                        paths.push(AttackPath {
                            path: full_path,
                            entry_point: root.clone(),
                            target: target.to_string(),
                            depth,
                            risk_score,
                        });

                        if paths.len() >= max_paths {
                            // Sort by risk score before returning
                            paths.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
                            return paths;
                        }
                    } else if !visited.contains(dep) {
                        visited.insert(dep.clone());
                        let mut new_path = path.clone();
                        new_path.push(dep.clone());
                        queue.push_back((dep.clone(), new_path));
                    }
                }
            }
        }
    }

    // Sort by risk score (highest first), then by depth (shortest first)
    paths.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.depth.cmp(&b.depth))
    });
    paths
}

/// Identify root components (components with no dependents)
pub fn find_root_components(
    all_components: &[String],
    reverse_graph: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    all_components
        .iter()
        .filter(|comp| {
            reverse_graph
                .get(*comp)
                .map(|deps| deps.is_empty())
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

// ============================================================================
// Compliance / Policy Checking
// ============================================================================

/// A policy rule for compliance checking
#[derive(Debug, Clone)]
pub enum PolicyRule {
    /// Ban specific licenses (e.g., GPL in proprietary projects)
    BannedLicense {
        pattern: String,
        reason: String,
    },
    /// Require specific licenses
    RequiredLicense {
        allowed: Vec<String>,
        reason: String,
    },
    /// Ban specific components by name pattern
    BannedComponent {
        pattern: String,
        reason: String,
    },
    /// Minimum version requirement for a component
    MinimumVersion {
        component_pattern: String,
        min_version: String,
        reason: String,
    },
    /// No pre-release versions (0.x.x)
    NoPreRelease {
        reason: String,
    },
    /// Maximum vulnerability severity allowed
    MaxVulnerabilitySeverity {
        max_severity: String,
        reason: String,
    },
    /// Require SBOM completeness (minimum fields)
    RequireFields {
        fields: Vec<String>,
        reason: String,
    },
}

impl PolicyRule {
    pub fn name(&self) -> &'static str {
        match self {
            PolicyRule::BannedLicense { .. } => "Banned License",
            PolicyRule::RequiredLicense { .. } => "License Allowlist",
            PolicyRule::BannedComponent { .. } => "Banned Component",
            PolicyRule::MinimumVersion { .. } => "Minimum Version",
            PolicyRule::NoPreRelease { .. } => "No Pre-Release",
            PolicyRule::MaxVulnerabilitySeverity { .. } => "Max Vulnerability Severity",
            PolicyRule::RequireFields { .. } => "Required Fields",
        }
    }

    pub fn severity(&self) -> PolicySeverity {
        match self {
            PolicyRule::BannedLicense { .. } => PolicySeverity::High,
            PolicyRule::RequiredLicense { .. } => PolicySeverity::Medium,
            PolicyRule::BannedComponent { .. } => PolicySeverity::Critical,
            PolicyRule::MinimumVersion { .. } => PolicySeverity::Medium,
            PolicyRule::NoPreRelease { .. } => PolicySeverity::Low,
            PolicyRule::MaxVulnerabilitySeverity { .. } => PolicySeverity::High,
            PolicyRule::RequireFields { .. } => PolicySeverity::Low,
        }
    }
}

/// Severity of a policy violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PolicySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicySeverity::Low => "Low",
            PolicySeverity::Medium => "Medium",
            PolicySeverity::High => "High",
            PolicySeverity::Critical => "Critical",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            PolicySeverity::Low => "○",
            PolicySeverity::Medium => "◐",
            PolicySeverity::High => "●",
            PolicySeverity::Critical => "◉",
        }
    }
}

/// A policy violation
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    /// The rule that was violated
    pub rule_name: String,
    /// Severity of the violation
    pub severity: PolicySeverity,
    /// Component that violated the rule (if applicable)
    pub component: Option<String>,
    /// Description of what violated the rule
    pub description: String,
    /// Suggested remediation
    pub remediation: String,
}

/// Security policy configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityPolicy {
    /// Name of this policy
    pub name: String,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
}

impl SecurityPolicy {
    /// Create a default enterprise security policy
    pub fn enterprise_default() -> Self {
        Self {
            name: "Enterprise Security Policy".to_string(),
            rules: vec![
                PolicyRule::BannedLicense {
                    pattern: "GPL".to_string(),
                    reason: "GPL licenses incompatible with proprietary software".to_string(),
                },
                PolicyRule::BannedLicense {
                    pattern: "AGPL".to_string(),
                    reason: "AGPL requires source disclosure for network services".to_string(),
                },
                PolicyRule::MaxVulnerabilitySeverity {
                    max_severity: "High".to_string(),
                    reason: "Critical vulnerabilities must be remediated before deployment"
                        .to_string(),
                },
                PolicyRule::NoPreRelease {
                    reason: "Pre-release versions (0.x) may have unstable APIs".to_string(),
                },
            ],
        }
    }

    /// Create a strict security policy
    pub fn strict() -> Self {
        Self {
            name: "Strict Security Policy".to_string(),
            rules: vec![
                PolicyRule::BannedLicense {
                    pattern: "GPL".to_string(),
                    reason: "GPL licenses not allowed".to_string(),
                },
                PolicyRule::BannedLicense {
                    pattern: "AGPL".to_string(),
                    reason: "AGPL licenses not allowed".to_string(),
                },
                PolicyRule::BannedLicense {
                    pattern: "LGPL".to_string(),
                    reason: "LGPL licenses not allowed".to_string(),
                },
                PolicyRule::MaxVulnerabilitySeverity {
                    max_severity: "Medium".to_string(),
                    reason: "High/Critical vulnerabilities not allowed".to_string(),
                },
                PolicyRule::NoPreRelease {
                    reason: "Pre-release versions not allowed in production".to_string(),
                },
                PolicyRule::BannedComponent {
                    pattern: "lodash".to_string(),
                    reason: "Use native JS methods or lighter alternatives".to_string(),
                },
            ],
        }
    }

    /// Create a permissive policy (minimal checks)
    pub fn permissive() -> Self {
        Self {
            name: "Permissive Policy".to_string(),
            rules: vec![PolicyRule::MaxVulnerabilitySeverity {
                max_severity: "Critical".to_string(),
                reason: "Critical vulnerabilities should be reviewed".to_string(),
            }],
        }
    }
}

/// Result of a compliance check
#[derive(Debug, Clone, Default)]
pub struct ComplianceResult {
    /// Policy name that was checked
    pub policy_name: String,
    /// Total components checked
    pub components_checked: usize,
    /// Violations found
    pub violations: Vec<PolicyViolation>,
    /// Compliance score (0-100)
    pub score: u8,
    /// Whether the SBOM passes the policy
    pub passes: bool,
}

impl ComplianceResult {
    /// Count violations by severity
    pub fn count_by_severity(&self, severity: PolicySeverity) -> usize {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    /// Get summary of violations
    pub fn summary(&self) -> String {
        if self.violations.is_empty() {
            "All checks passed".to_string()
        } else {
            let critical = self.count_by_severity(PolicySeverity::Critical);
            let high = self.count_by_severity(PolicySeverity::High);
            let medium = self.count_by_severity(PolicySeverity::Medium);
            let low = self.count_by_severity(PolicySeverity::Low);
            format!(
                "{} critical, {} high, {} medium, {} low",
                critical, high, medium, low
            )
        }
    }
}

/// Check compliance of components against a policy
pub fn check_compliance(
    policy: &SecurityPolicy,
    components: &[ComplianceComponentData],
) -> ComplianceResult {
    let mut result = ComplianceResult {
        policy_name: policy.name.clone(),
        components_checked: components.len(),
        violations: Vec::new(),
        score: 100,
        passes: true,
    };

    for (name, version, licenses, vulns) in components {
        for rule in &policy.rules {
            match rule {
                PolicyRule::BannedLicense { pattern, reason } => {
                    for license in licenses {
                        if license.to_uppercase().contains(&pattern.to_uppercase()) {
                            result.violations.push(PolicyViolation {
                                rule_name: rule.name().to_string(),
                                severity: rule.severity(),
                                component: Some(name.clone()),
                                description: format!(
                                    "License '{}' matches banned pattern '{}'",
                                    license, pattern
                                ),
                                remediation: format!(
                                    "Replace with component using permissive license. {}",
                                    reason
                                ),
                            });
                        }
                    }
                }
                PolicyRule::RequiredLicense { allowed, reason } => {
                    let has_allowed = licenses
                        .iter()
                        .any(|l| allowed.iter().any(|a| l.to_uppercase().contains(&a.to_uppercase())));
                    if !licenses.is_empty() && !has_allowed {
                        result.violations.push(PolicyViolation {
                            rule_name: rule.name().to_string(),
                            severity: rule.severity(),
                            component: Some(name.clone()),
                            description: format!(
                                "License '{}' not in allowed list",
                                licenses.join(", ")
                            ),
                            remediation: format!(
                                "Use component with allowed license: {}. {}",
                                allowed.join(", "),
                                reason
                            ),
                        });
                    }
                }
                PolicyRule::BannedComponent { pattern, reason } => {
                    if name.to_lowercase().contains(&pattern.to_lowercase()) {
                        result.violations.push(PolicyViolation {
                            rule_name: rule.name().to_string(),
                            severity: rule.severity(),
                            component: Some(name.clone()),
                            description: format!(
                                "Component '{}' matches banned pattern '{}'",
                                name, pattern
                            ),
                            remediation: reason.clone(),
                        });
                    }
                }
                PolicyRule::MinimumVersion {
                    component_pattern,
                    min_version,
                    reason,
                } => {
                    if name.to_lowercase().contains(&component_pattern.to_lowercase()) {
                        if let Some(ver) = version {
                            if let (Some(current), Some(min)) =
                                (parse_version_parts(ver), parse_version_parts(min_version))
                            {
                                let is_below = current
                                    .iter()
                                    .zip(min.iter())
                                    .any(|(c, m)| c < m);
                                if is_below {
                                    result.violations.push(PolicyViolation {
                                        rule_name: rule.name().to_string(),
                                        severity: rule.severity(),
                                        component: Some(name.clone()),
                                        description: format!(
                                            "Version '{}' below minimum '{}'",
                                            ver, min_version
                                        ),
                                        remediation: format!(
                                            "Upgrade to version {} or higher. {}",
                                            min_version, reason
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
                PolicyRule::NoPreRelease { reason } => {
                    if let Some(ver) = version {
                        if let Some(parts) = parse_version_parts(ver) {
                            if parts.first() == Some(&0) {
                                result.violations.push(PolicyViolation {
                                    rule_name: rule.name().to_string(),
                                    severity: rule.severity(),
                                    component: Some(name.clone()),
                                    description: format!("Pre-release version '{}' (0.x.x)", ver),
                                    remediation: format!(
                                        "Upgrade to stable version (1.0+). {}",
                                        reason
                                    ),
                                });
                            }
                        }
                    }
                }
                PolicyRule::MaxVulnerabilitySeverity { max_severity, reason } => {
                    let max_rank = severity_to_rank(max_severity);
                    for (vuln_id, vuln_sev) in vulns {
                        let vuln_rank = severity_to_rank(vuln_sev);
                        if vuln_rank > max_rank {
                            result.violations.push(PolicyViolation {
                                rule_name: rule.name().to_string(),
                                severity: PolicySeverity::Critical,
                                component: Some(name.clone()),
                                description: format!(
                                    "{} has {} severity (max allowed: {})",
                                    vuln_id, vuln_sev, max_severity
                                ),
                                remediation: format!(
                                    "Remediate {} or upgrade component. {}",
                                    vuln_id, reason
                                ),
                            });
                        }
                    }
                }
                PolicyRule::RequireFields { .. } => {
                    // This would check SBOM-level fields, not per-component
                    // Handled separately
                }
            }
        }
    }

    // Calculate score
    let violation_penalty: u32 = result
        .violations
        .iter()
        .map(|v| match v.severity {
            PolicySeverity::Critical => 25,
            PolicySeverity::High => 15,
            PolicySeverity::Medium => 8,
            PolicySeverity::Low => 3,
        })
        .sum();

    result.score = 100u8.saturating_sub(violation_penalty.min(100) as u8);
    result.passes = result.count_by_severity(PolicySeverity::Critical) == 0
        && result.count_by_severity(PolicySeverity::High) == 0;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blast_radius_impact_description() {
        let mut blast = BlastRadius::default();
        assert_eq!(blast.impact_description(), "No downstream impact");

        blast.transitive_dependents.insert("a".to_string());
        assert_eq!(blast.impact_description(), "Limited impact");

        for i in 0..25 {
            blast.transitive_dependents.insert(format!("comp_{}", i));
        }
        assert_eq!(blast.impact_description(), "Significant impact");
    }

    #[test]
    fn test_risk_indicators_score() {
        let mut indicators = RiskIndicators::default();
        indicators.vuln_count = 3;
        indicators.highest_severity = Some("High".to_string());
        indicators.transitive_dependent_count = 15;
        indicators.calculate_risk_score();

        assert!(indicators.risk_score > 0);
        assert!(indicators.risk_level != RiskLevel::Low);
    }

    #[test]
    fn test_license_risk() {
        assert_eq!(LicenseRisk::from_license("MIT"), LicenseRisk::Low);
        assert_eq!(LicenseRisk::from_license("Apache-2.0"), LicenseRisk::Low);
        assert_eq!(LicenseRisk::from_license("LGPL-3.0"), LicenseRisk::Medium);
        assert_eq!(LicenseRisk::from_license("GPL-3.0"), LicenseRisk::High);
    }

    #[test]
    fn test_cve_url() {
        assert!(cve_url("CVE-2021-44228").contains("nvd.nist.gov"));
        assert!(cve_url("GHSA-abcd-1234-efgh").contains("github.com"));
        assert!(cve_url("RUSTSEC-2021-0001").contains("rustsec.org"));
    }

    #[test]
    fn test_sanitize_vuln_id_strips_shell_metacharacters() {
        // Normal IDs pass through unchanged
        assert_eq!(sanitize_vuln_id("CVE-2021-44228"), "CVE-2021-44228");
        assert_eq!(sanitize_vuln_id("GHSA-abcd-1234-efgh"), "GHSA-abcd-1234-efgh");

        // Shell metacharacters are stripped
        assert_eq!(sanitize_vuln_id("CVE-2021&whoami"), "CVE-2021whoami");
        assert_eq!(sanitize_vuln_id("CVE|calc.exe"), "CVEcalc.exe");
        assert_eq!(sanitize_vuln_id("id;rm -rf /"), "idrm-rf");
        assert_eq!(sanitize_vuln_id("$(malicious)"), "malicious");
        assert_eq!(sanitize_vuln_id("foo`bar`"), "foobar");
    }

    #[test]
    fn test_cve_url_with_injected_id() {
        // Ensure shell metacharacters in vuln IDs don't appear in the URL
        let url = cve_url("CVE-2021-44228&calc");
        assert!(!url.contains('&'));
        // sanitize_vuln_id strips '&', cve_url uppercases CVE IDs
        assert!(url.contains("CVE-2021-44228CALC"));
    }

    #[test]
    fn test_is_safe_url() {
        assert!(is_safe_url("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
        assert!(is_safe_url("https://example.com/path?q=1&a=2"));
        // Shell injection attempts
        assert!(!is_safe_url("https://evil.com\"; rm -rf /"));
        assert!(!is_safe_url("https://x.com\nmalicious"));
        // Backtick and pipe are not valid URL characters
        assert!(!is_safe_url("url`calc`"));
        assert!(!is_safe_url("url|cmd"));
    }

    #[test]
    fn test_security_cache_flagging() {
        let mut cache = SecurityAnalysisCache::new();

        assert!(!cache.is_flagged("comp1"));
        cache.flag_component("comp1", "Suspicious activity");
        assert!(cache.is_flagged("comp1"));

        cache.toggle_flag("comp1", "test");
        assert!(!cache.is_flagged("comp1"));
    }
}
