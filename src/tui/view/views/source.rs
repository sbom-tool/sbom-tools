//! Source tab rendering for ViewApp with SBOM Map panel.

use crate::model::CreatorType;
use crate::model::NormalizedSbom;
use crate::tui::app_states::source::{JsonTreeNode, SourceViewMode};
use crate::tui::shared::source::render_source_panel;
use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, SbomStats, ViewApp};
use ratatui::{
    buffer::Buffer,
    prelude::*,
    widgets::{Block, Borders},
};
use std::collections::HashMap;
use unicode_width::UnicodeWidthChar;

/// Render the source tab for a single SBOM with map panel.
pub fn render_source(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let is_source_focused = app.focus_panel == FocusPanel::Left;
    render_source_panel(
        frame,
        chunks[0],
        &mut app.source_state,
        "SBOM Source",
        is_source_focused,
    );
    render_source_map(frame, chunks[1], app, !is_source_focused);
}

/// A section in the SBOM map derived from the JSON tree root's children.
struct MapSection {
    key: String,
    is_expandable: bool,
    /// True if Object ({}), false if Array ([])
    is_object: bool,
    child_count: usize,
    line_start: usize,
}

/// Build map sections from the JSON tree root's children.
fn build_map_sections(
    state: &crate::tui::app_states::source::SourcePanelState,
) -> Vec<MapSection> {
    let tree = match &state.json_tree {
        Some(t) => t,
        None => return Vec::new(),
    };

    let children = match tree.children() {
        Some(c) => c,
        None => return Vec::new(),
    };

    let line_starts = compute_raw_line_starts(&state.raw_lines);

    children
        .iter()
        .map(|child| {
            let key = match child {
                JsonTreeNode::Object { key, .. }
                | JsonTreeNode::Array { key, .. }
                | JsonTreeNode::Leaf { key, .. } => key.clone(),
            };
            let is_expandable = child.is_expandable();
            let is_object = matches!(child, JsonTreeNode::Object { .. });
            let child_count = match child {
                JsonTreeNode::Object { children, .. } => children.len(),
                JsonTreeNode::Array { len, .. } => *len,
                _ => 0,
            };
            let line_start = line_starts
                .iter()
                .find(|(k, _)| k == &key)
                .map(|(_, l)| *l)
                .unwrap_or(0);

            MapSection {
                key,
                is_expandable,
                is_object,
                child_count,
                line_start,
            }
        })
        .collect()
}

/// Find the starting line number for each top-level key in pretty-printed JSON.
fn compute_raw_line_starts(raw_lines: &[String]) -> Vec<(String, usize)> {
    let mut result = Vec::new();
    for (i, line) in raw_lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if line.starts_with("  \"") && !line.starts_with("    ") {
            if let Some(end) = trimmed.find("\":") {
                let key = trimmed[1..end].to_string();
                result.push((key, i));
            }
        }
    }
    result
}

/// Determine which section the cursor is currently inside (tree mode).
fn current_section_from_node_id(node_id: &str) -> Option<String> {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Determine which section a raw line belongs to.
fn current_section_for_raw_line(line_idx: usize, sections: &[MapSection]) -> Option<String> {
    let mut current = None;
    for s in sections {
        if s.line_start <= line_idx {
            current = Some(s.key.clone());
        } else {
            break;
        }
    }
    current
}

/// Extract the array index from a node_id if inside a section array.
/// e.g., "root.components.[42].name" => Some(42)
fn extract_array_index(node_id: &str) -> Option<usize> {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() >= 3 {
        let idx_part = parts[2];
        if idx_part.starts_with('[') && idx_part.ends_with(']') {
            idx_part[1..idx_part.len() - 1].parse().ok()
        } else {
            None
        }
    } else {
        None
    }
}

/// Build a semantic breadcrumb from a node_id, replacing array indices with labels.
/// e.g., "root.components.[5].name" → "components > lodash@4.17.21 > name"
fn semantic_breadcrumb(node_id: &str, sbom: &NormalizedSbom) -> String {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() < 2 {
        return "root".to_string();
    }

    let mut result = Vec::new();
    let mut prev_section = "";

    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.starts_with('[') && part.ends_with(']') {
            if let Ok(idx) = part[1..part.len() - 1].parse::<usize>() {
                let label = match prev_section {
                    "components" => sbom.components.values().nth(idx).map(|c| {
                        if let Some(ref v) = c.version {
                            format!("{}@{}", c.name, v)
                        } else {
                            c.name.clone()
                        }
                    }),
                    _ => None,
                };
                result.push(label.unwrap_or_else(|| part.to_string()));
            } else {
                result.push(part.to_string());
            }
        } else {
            if i == 1 {
                prev_section = part;
            }
            result.push(part.to_string());
        }
    }

    result.join(" > ")
}

/// Pre-compute search match counts per section.
/// Requires flat cache to be warm (call ensure_flat_cache() before this).
fn compute_section_match_counts(
    state: &crate::tui::app_states::source::SourcePanelState,
    sections: &[MapSection],
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    if state.search_matches.is_empty() {
        return counts;
    }

    match state.view_mode {
        SourceViewMode::Tree => {
            for &idx in &state.search_matches {
                if let Some(item) = state.cached_flat_items.get(idx) {
                    if let Some(section) = current_section_from_node_id(&item.node_id) {
                        *counts.entry(section).or_insert(0) += 1;
                    }
                }
            }
        }
        SourceViewMode::Raw => {
            for &line_idx in &state.search_matches {
                if let Some(section) = current_section_for_raw_line(line_idx, sections) {
                    *counts.entry(section).or_insert(0) += 1;
                }
            }
        }
    }

    counts
}

/// Get the current section based on cursor position and view mode.
/// Requires flat cache to be warm (call ensure_flat_cache() before this).
fn get_current_section(app: &ViewApp, sections: &[MapSection]) -> Option<String> {
    match app.source_state.view_mode {
        SourceViewMode::Tree => {
            app.source_state
                .cached_flat_items
                .get(app.source_state.selected)
                .and_then(|item| current_section_from_node_id(&item.node_id))
        }
        SourceViewMode::Raw => {
            current_section_for_raw_line(app.source_state.selected, sections)
        }
    }
}

// ============================================================================
// Map Panel Rendering
// ============================================================================

/// Render the SBOM map panel on the right side.
fn render_source_map(frame: &mut Frame, area: Rect, app: &mut ViewApp, is_focused: bool) {
    // Ensure flat cache is warm (normally already done by render_source_panel)
    app.source_state.ensure_flat_cache();

    let scheme = colors();
    let border_color = if is_focused {
        scheme.accent
    } else {
        scheme.border
    };

    let block = Block::default()
        .title(" SBOM Map ")
        .title_style(Style::default().fg(border_color).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 6 || inner.height < 4 {
        return;
    }

    let sections = build_map_sections(&app.source_state);

    // Non-JSON empty state
    if sections.is_empty() && app.source_state.json_tree.is_none() {
        render_non_json_map(frame.buffer_mut(), inner, app, is_focused, &scheme);
        return;
    }

    // Clamp map_selected
    let navigable_count = sections.iter().filter(|s| s.is_expandable).count();
    if navigable_count > 0 && app.source_state.map_selected >= navigable_count {
        app.source_state.map_selected = navigable_count - 1;
    }

    // Determine current section from cursor position
    let current_section = get_current_section(app, &sections);

    // Pre-compute search match counts per section
    let section_match_counts = if !app.source_state.search_matches.is_empty() {
        compute_section_match_counts(&app.source_state, &sections)
    } else {
        HashMap::new()
    };

    // Compute effective total for progress bar
    let effective_total = if app.source_state.view_mode == SourceViewMode::Raw {
        app.source_state.raw_lines.len()
    } else if app.source_state.visible_count > 0 {
        app.source_state.visible_count
    } else {
        app.source_state.total_node_count
    };

    let buf = frame.buffer_mut();
    let mut y = inner.y;
    let max_y = inner.y + inner.height;
    let x = inner.x;
    let width = inner.width;
    let right_edge = x + width;

    // Reserve bottom rows for progress bar + hints
    let hints_rows: u16 = if is_focused { 1 } else { 0 };
    let progress_y = max_y.saturating_sub(1 + hints_rows);
    let context_max_y = progress_y;

    // === Compact Header (1-2 lines) ===
    y = render_compact_header(buf, x, y, width, app, &scheme);

    if y >= context_max_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, effective_total, &scheme);
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Separator ===
    render_separator(buf, x, y, width, &scheme);
    y += 1;

    if y >= context_max_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, effective_total, &scheme);
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Sections (single-line per section, scrollable) ===
    let total_expandable = navigable_count;

    // Reserve space below sections: 1 separator + at least 2 context rows
    let section_end_y = context_max_y.saturating_sub(3);
    let available_rows = section_end_y.saturating_sub(y) as usize;

    if total_expandable > available_rows && available_rows > 2 {
        // Scrolling needed — reserve up to 2 rows for indicators
        let capacity = available_rows.saturating_sub(2);

        // Adjust scroll offset to keep selected visible
        if capacity > 0 {
            if app.source_state.map_selected >= app.source_state.map_scroll_offset + capacity {
                app.source_state.map_scroll_offset =
                    app.source_state.map_selected + 1 - capacity;
            }
            if app.source_state.map_selected < app.source_state.map_scroll_offset {
                app.source_state.map_scroll_offset = app.source_state.map_selected;
            }
            app.source_state.map_scroll_offset = app
                .source_state
                .map_scroll_offset
                .min(total_expandable.saturating_sub(capacity));
        }

        // Scroll-up indicator
        if app.source_state.map_scroll_offset > 0 && y < section_end_y {
            render_str(
                buf, x, y, " \u{25b2} more", width,
                Style::default().fg(scheme.text_muted),
            );
            y += 1;
        }
    } else {
        app.source_state.map_scroll_offset = 0;
    }

    let capacity = if total_expandable > available_rows {
        available_rows.saturating_sub(2)
    } else {
        total_expandable
    };
    let mut nav_idx = 0usize;
    let mut rendered = 0usize;

    for section in &sections {
        if !section.is_expandable {
            continue;
        }

        // Skip sections before scroll offset
        if nav_idx < app.source_state.map_scroll_offset {
            nav_idx += 1;
            continue;
        }

        // Stop when capacity reached
        if rendered >= capacity || y >= section_end_y {
            break;
        }

        let is_current = current_section.as_deref() == Some(&section.key);
        let is_map_selected = is_focused && nav_idx == app.source_state.map_selected;
        let match_count = section_match_counts
            .get(&section.key)
            .copied()
            .unwrap_or(0);

        // Build section line components
        let count_str = if section.is_object {
            format!("{{{}}}", section.child_count)
        } else {
            format!("[{}]", section.child_count)
        };
        let match_str = if match_count > 0 {
            format!("({})", match_count)
        } else {
            String::new()
        };
        let marker = if is_current { " \u{25c0}" } else { "" };
        let badge = section_badge(
            &section.key,
            &app.stats,
            &app.sbom,
            (width as usize).saturating_sub(
                section.key.len() + count_str.len() + match_str.len() + marker.len() + 8,
            ),
        );

        // Left side: " ▸ key_name"
        let left = format!(" \u{25b8} {}", section.key);
        let style = if is_map_selected {
            Style::default().fg(scheme.primary).bold()
        } else if match_count > 0 {
            Style::default().fg(scheme.accent)
        } else {
            Style::default().fg(scheme.text)
        };
        render_str(buf, x, y, &left, width, style);

        // Right side: " count match  badge marker" — right-aligned
        let mut right = format!(" {}{}", count_str, match_str);
        if !badge.is_empty() {
            right.push_str(&format!("  {}", badge));
        }
        right.push_str(marker);

        let right_len = right.len() as u16;
        if width > right_len {
            let rx = right_edge - right_len;

            // Render count portion
            let count_full = format!(" {}", count_str);
            let count_style = if is_current {
                Style::default().fg(scheme.accent)
            } else {
                Style::default().fg(scheme.muted)
            };
            render_str(buf, rx, y, &count_full, right_edge - rx, count_style);

            let mut cx = rx + count_full.len() as u16;

            // Render match count in accent
            if match_count > 0 {
                render_str(
                    buf, cx, y, &match_str, right_edge - cx,
                    Style::default().fg(scheme.accent),
                );
                cx += match_str.len() as u16;
            }

            // Render badge in muted
            if !badge.is_empty() {
                let bt = format!("  {}", badge);
                render_str(
                    buf, cx, y, &bt, right_edge - cx,
                    Style::default().fg(scheme.muted),
                );
                cx += bt.len() as u16;
            }

            // Render marker in accent bold
            if is_current {
                render_str(
                    buf, cx, y, marker, right_edge - cx,
                    Style::default().fg(scheme.accent).bold(),
                );
            }
        }

        // Highlight selected row
        if is_map_selected {
            for col in x..right_edge {
                if let Some(cell) = buf.cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                }
            }
        }

        y += 1;
        nav_idx += 1;
        rendered += 1;
    }

    // Scroll-down indicator
    let remaining_expandable =
        total_expandable - app.source_state.map_scroll_offset - rendered;
    if remaining_expandable > 0 && y < section_end_y {
        render_str(
            buf, x, y, " \u{25bc} more", width,
            Style::default().fg(scheme.text_muted),
        );
        y += 1;
    }

    if y >= context_max_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, effective_total, &scheme);
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Separator before context ===
    render_separator(buf, x, y, width, &scheme);
    y += 1;

    // === Context area (dynamic, fills remaining space) ===
    render_context(buf, x, y, width, context_max_y, app, &sections, &scheme);

    // === Progress bar (bottom-anchored) ===
    render_progress_bar(
        buf, x, progress_y, width,
        app.source_state.selected, effective_total, &scheme,
    );

    // === Keyboard hints (when focused) ===
    if is_focused {
        render_hints(buf, x, max_y - 1, width, &scheme);
    }
}

// ============================================================================
// Header
// ============================================================================

/// Compact 2-line header: format+version+date, tool name.
fn render_compact_header(
    buf: &mut Buffer,
    x: u16,
    mut y: u16,
    width: u16,
    app: &ViewApp,
    scheme: &crate::tui::theme::ColorScheme,
) -> u16 {
    let doc = &app.sbom.document;

    // Line 1: format + version + date
    let format_line = format!(
        " {} {} \u{2502} {}",
        doc.format,
        doc.format_version,
        doc.created.format("%Y-%m-%d"),
    );
    render_str(
        buf, x, y, &format_line, width,
        Style::default().fg(scheme.primary).bold(),
    );
    y += 1;

    // Line 2: tool name (optional)
    if let Some(tool) = doc
        .creators
        .iter()
        .find(|c| c.creator_type == CreatorType::Tool)
    {
        let tool_line = format!(
            " Tool: {}",
            truncate_map_str(&tool.name, (width as usize).saturating_sub(8))
        );
        render_str(
            buf, x, y, &tool_line, width,
            Style::default().fg(scheme.text_muted),
        );
        y += 1;
    }

    y
}

// ============================================================================
// Section Badge
// ============================================================================

/// Compute inline badge text for a section line.
///
/// Returns a compact summary string to display next to the section count:
/// - components: top ecosystem names (e.g., "npm maven")
/// - vulnerabilities: severity counts (e.g., "2C 1H 3M")
/// - metadata: tool short name
fn section_badge(
    key: &str,
    stats: &SbomStats,
    sbom: &NormalizedSbom,
    max_len: usize,
) -> String {
    if max_len == 0 {
        return String::new();
    }

    match key {
        "components" => {
            let mut ecosystems: Vec<_> = stats.ecosystem_counts.iter().collect();
            ecosystems.sort_by(|a, b| b.1.cmp(a.1));

            let mut badge = String::new();
            for (eco, _) in ecosystems.iter().take(3) {
                if !badge.is_empty() {
                    badge.push(' ');
                }
                if badge.len() + eco.len() > max_len {
                    break;
                }
                badge.push_str(eco);
            }
            badge
        }
        "vulnerabilities" => {
            let mut parts = Vec::new();
            if stats.critical_count > 0 {
                parts.push(format!("{}C", stats.critical_count));
            }
            if stats.high_count > 0 {
                parts.push(format!("{}H", stats.high_count));
            }
            if stats.medium_count > 0 {
                parts.push(format!("{}M", stats.medium_count));
            }
            if stats.low_count > 0 {
                parts.push(format!("{}L", stats.low_count));
            }
            let result = parts.join(" ");
            if result.len() > max_len {
                truncate_map_str(&result, max_len)
            } else {
                result
            }
        }
        "metadata" => sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Tool)
            .map(|c| truncate_map_str(&c.name, max_len.min(12)))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

// ============================================================================
// Context Area
// ============================================================================

/// Render the dynamic context area below sections.
///
/// Shows semantic breadcrumb + contextual information:
/// - Component details when inside components section
/// - Vulnerability info when inside vulnerabilities section
/// - Document summary at root level or generic sections
#[allow(clippy::too_many_arguments)]
fn render_context(
    buf: &mut Buffer,
    x: u16,
    mut y: u16,
    width: u16,
    max_y: u16,
    app: &ViewApp,
    sections: &[MapSection],
    scheme: &crate::tui::theme::ColorScheme,
) {
    if y >= max_y {
        return;
    }

    // Get selected node info (uses cached flat items, already warm from render_source_panel)
    let (section_name, array_idx, node_id_full) = match app.source_state.view_mode {
        SourceViewMode::Tree => {
            if let Some(item) = app.source_state.cached_flat_items.get(app.source_state.selected) {
                let section = current_section_from_node_id(&item.node_id);
                let idx = extract_array_index(&item.node_id);
                (section, idx, Some(item.node_id.clone()))
            } else {
                (None, None, None)
            }
        }
        SourceViewMode::Raw => {
            let section = current_section_for_raw_line(app.source_state.selected, sections);
            (section, None, None)
        }
    };

    // Semantic breadcrumb
    let breadcrumb = if let Some(ref nid) = node_id_full {
        let bc = semantic_breadcrumb(nid, &app.sbom);
        if bc.is_empty() {
            "root".to_string()
        } else {
            bc
        }
    } else if let Some(ref s) = section_name {
        s.clone()
    } else {
        "root".to_string()
    };
    render_str(
        buf, x, y,
        &format!(
            " {}",
            truncate_map_str(&breadcrumb, (width as usize).saturating_sub(2))
        ),
        width,
        Style::default().fg(scheme.text).bold(),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    // Component context
    if let (Some(section), Some(idx)) = (&section_name, array_idx) {
        if section == "components" {
            if let Some(comp) = app.sbom.components.values().nth(idx) {
                let is_primary = app
                    .sbom
                    .primary_component_id
                    .as_ref()
                    .map(|pid| pid == &comp.canonical_id)
                    .unwrap_or(false);

                // Name + version + ecosystem
                let name_ver = if let Some(ref v) = comp.version {
                    if is_primary {
                        format!(" \u{2605} {}@{}", comp.name, v)
                    } else {
                        format!(" {}@{}", comp.name, v)
                    }
                } else if is_primary {
                    format!(" \u{2605} {}", comp.name)
                } else {
                    format!(" {}", comp.name)
                };
                let eco_suffix = comp
                    .ecosystem
                    .as_ref()
                    .map(|e| format!(" ({})", e))
                    .unwrap_or_default();
                render_str(
                    buf, x, y,
                    &format!("{}{}", name_ver, eco_suffix),
                    width,
                    Style::default().fg(scheme.primary),
                );
                y += 1;
                if y >= max_y {
                    return;
                }

                // License
                let license = if comp.licenses.declared.is_empty() {
                    "Unknown".to_string()
                } else {
                    comp.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                render_str(
                    buf, x, y,
                    &format!(
                        " License: {}",
                        truncate_map_str(&license, (width as usize).saturating_sub(11))
                    ),
                    width,
                    Style::default().fg(scheme.success),
                );
                y += 1;
                if y >= max_y {
                    return;
                }

                // Vulnerability count
                let vuln_count = comp.vulnerabilities.len();
                if vuln_count > 0 {
                    render_str(
                        buf, x, y,
                        &format!(
                            " {} vulnerabilit{}",
                            vuln_count,
                            if vuln_count == 1 { "y" } else { "ies" }
                        ),
                        width,
                        Style::default().fg(scheme.error),
                    );
                } else {
                    render_str(
                        buf, x, y,
                        " No vulnerabilities",
                        width,
                        Style::default().fg(scheme.muted),
                    );
                }
                y += 1;
                if y >= max_y {
                    return;
                }

                // PURL
                if let Some(ref purl) = comp.identifiers.purl {
                    render_str(
                        buf, x, y,
                        &format!(
                            " purl: {}",
                            truncate_map_str(purl, (width as usize).saturating_sub(8))
                        ),
                        width,
                        Style::default().fg(scheme.text_muted),
                    );
                    y += 1;
                    if y >= max_y {
                        return;
                    }
                }

                // Extras: type, supplier, hashes, refs
                let mut extras = Vec::new();
                extras.push(format!("type:{}", comp.component_type));
                if let Some(ref supplier) = comp.supplier {
                    extras.push(format!(
                        "supplier:{}",
                        truncate_map_str(&supplier.name, 12)
                    ));
                }
                if !comp.hashes.is_empty() {
                    extras.push(format!("{}h", comp.hashes.len()));
                }
                if !comp.external_refs.is_empty() {
                    extras.push(format!("{}refs", comp.external_refs.len()));
                }
                render_str(
                    buf, x, y,
                    &format!(
                        " {}",
                        truncate_map_str(&extras.join("  "), (width as usize).saturating_sub(2))
                    ),
                    width,
                    Style::default().fg(scheme.text_muted),
                );
                return;
            }
        }

        if section == "vulnerabilities" {
            render_str(
                buf, x, y,
                &format!(" Vulnerability [{}]", idx),
                width,
                Style::default().fg(scheme.warning),
            );
            return;
        }
    }

    // Raw mode: show current line info
    if app.source_state.view_mode == SourceViewMode::Raw {
        let line_num = app.source_state.selected + 1;
        let total = app.source_state.raw_lines.len();
        render_str(
            buf, x, y,
            &format!(" Line {}/{}", line_num, total),
            width,
            Style::default().fg(scheme.muted),
        );
        y += 1;
        if y >= max_y {
            return;
        }

        if let Some(raw_line) = app.source_state.raw_lines.get(app.source_state.selected) {
            let trimmed = raw_line.trim();
            let preview = truncate_map_str(trimmed, (width as usize).saturating_sub(2));
            if !preview.is_empty() {
                render_str(
                    buf, x, y,
                    &format!(" {}", preview),
                    width,
                    Style::default().fg(scheme.text_muted),
                );
            }
        }
        return;
    }

    // Document summary (root level or non-component section)
    render_str(
        buf, x, y,
        &format!(" {} components", app.stats.component_count),
        width,
        Style::default().fg(scheme.text),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    if app.stats.vuln_count > 0 {
        render_str(
            buf, x, y,
            &format!(" {} vulnerabilities", app.stats.vuln_count),
            width,
            Style::default().fg(scheme.error),
        );
        y += 1;
        if y >= max_y {
            return;
        }
    }

    render_str(
        buf, x, y,
        &format!(" {} licenses", app.stats.license_count),
        width,
        Style::default().fg(scheme.text_muted),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    let edge_count = app.sbom.edges.len();
    if edge_count > 0 {
        render_str(
            buf, x, y,
            &format!(" {} dependency edges", edge_count),
            width,
            Style::default().fg(scheme.text_muted),
        );
    }
}

// ============================================================================
// Progress Bar
// ============================================================================

/// Render a progress bar showing document position.
/// Format: ` ░░░▓▓░░░░░░░░░  12/77  16%`
fn render_progress_bar(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    current: usize,
    total: usize,
    scheme: &crate::tui::theme::ColorScheme,
) {
    if width < 10 || total == 0 {
        return;
    }

    let pos = current + 1; // 1-indexed
    let pct = (pos * 100) / total;

    // Right-aligned text: "  12/77  16%"
    let right_text = format!("  {}/{}  {}%", pos, total, pct);
    let right_len = right_text.len() as u16;

    // Bar takes remaining width
    let bar_width = width.saturating_sub(right_len + 2) as usize; // 1 padding each side

    if bar_width < 3 {
        // No room for bar, just show numbers
        let text = format!(" {}/{}  {}%", pos, total, pct);
        render_str(
            buf, x, y, &text, width,
            Style::default().fg(scheme.text_muted),
        );
        return;
    }

    let filled = ((bar_width * pos) / total).min(bar_width);

    let mut bar = String::with_capacity(bar_width + 1);
    bar.push(' '); // leading space
    for i in 0..bar_width {
        if i < filled {
            bar.push('\u{2593}'); // ▓
        } else {
            bar.push('\u{2591}'); // ░
        }
    }

    // Render bar
    render_str(
        buf, x, y, &bar, width,
        Style::default().fg(scheme.muted),
    );

    // Render right text (right-aligned)
    let right_x = x + width - right_len;
    render_str(
        buf, right_x, y, &right_text, right_len,
        Style::default().fg(scheme.text_muted),
    );
}

// ============================================================================
// Helpers
// ============================================================================

/// Render a horizontal separator line.
fn render_separator(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let sep: String = "\u{2500}".repeat(width as usize);
    render_str(buf, x, y, &sep, width, Style::default().fg(scheme.muted));
}

/// Render inline keyboard hints for the map panel.
fn render_hints(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    render_str(
        buf, x, y,
        " Enter:jump  t:tree  u:vulns",
        width,
        Style::default().fg(scheme.text_muted),
    );
}

/// Render map panel content for non-JSON formats.
fn render_non_json_map(
    buf: &mut Buffer,
    inner: Rect,
    app: &ViewApp,
    is_focused: bool,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let width = inner.width;
    let max_y = inner.y + inner.height;
    let x = inner.x;
    let mut y = inner.y + 1;

    // Reserve bottom rows
    let hints_rows: u16 = if is_focused { 1 } else { 0 };
    let progress_y = max_y.saturating_sub(1 + hints_rows);

    // Format info
    render_str(
        buf, x, y,
        &format!(" Format: {}", app.sbom.document.format),
        width,
        Style::default().fg(scheme.primary).bold(),
    );
    y += 1;
    if y >= progress_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, app.source_state.raw_lines.len(), scheme);
        if is_focused { render_hints(buf, x, max_y - 1, width, scheme); }
        return;
    }

    let line_count = app.source_state.raw_lines.len();
    render_str(
        buf, x, y,
        &format!(" {} lines (raw mode only)", line_count),
        width,
        Style::default().fg(scheme.text_muted),
    );
    y += 1;
    if y >= progress_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, line_count, scheme);
        if is_focused { render_hints(buf, x, max_y - 1, width, scheme); }
        return;
    }

    // Separator
    render_separator(buf, x, y, width, scheme);
    y += 1;
    if y >= progress_y {
        render_progress_bar(buf, x, progress_y, width, app.source_state.selected, line_count, scheme);
        if is_focused { render_hints(buf, x, max_y - 1, width, scheme); }
        return;
    }

    // Stats
    render_str(
        buf, x, y,
        &format!(" {} components", app.stats.component_count),
        width,
        Style::default().fg(scheme.text),
    );
    y += 1;

    if y < progress_y && app.stats.vuln_count > 0 {
        render_str(
            buf, x, y,
            &format!(" {} vulnerabilities", app.stats.vuln_count),
            width,
            Style::default().fg(scheme.error),
        );
        y += 1;
    }

    if y < progress_y {
        render_str(
            buf, x, y,
            &format!(" {} unique licenses", app.stats.license_count),
            width,
            Style::default().fg(scheme.text_muted),
        );
    }

    // Progress bar
    render_progress_bar(
        buf, x, progress_y, width,
        app.source_state.selected, line_count, scheme,
    );

    // Hints
    if is_focused {
        render_hints(buf, x, max_y - 1, width, scheme);
    }
}

/// Truncate a string for map display.
fn truncate_map_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len && max_len > 3 {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else if s.len() > max_len {
        s[..max_len].to_string()
    } else {
        s.to_string()
    }
}

/// Write a string into the buffer starting at (x, y), limited to max_width.
fn render_str(buf: &mut Buffer, x: u16, y: u16, s: &str, max_width: u16, style: Style) {
    let mut cx = x;
    let limit = x + max_width;
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
        if cx + w > limit {
            break;
        }
        if let Some(cell) = buf.cell_mut((cx, y)) {
            cell.set_char(ch).set_style(style);
        }
        cx += w;
    }
}
