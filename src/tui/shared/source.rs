//! Shared source rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! Provides interactive JSON tree rendering and raw text rendering for the Source tab.

use crate::tui::app_states::source::{
    JsonTreeNode, JsonValueType, SourceChangeStatus, SourcePanelState, SourceSortMode,
    SourceViewMode,
};
use crate::tui::theme::colors;
use ratatui::{
    buffer::Buffer,
    prelude::*,
    widgets::{Block, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// A flattened JSON tree item for rendering.
#[derive(Debug, Clone)]
pub struct FlatJsonItem {
    pub node_id: String,
    pub depth: usize,
    pub display_key: String,
    pub value_preview: String,
    pub value_type: Option<JsonValueType>,
    pub is_expandable: bool,
    pub is_expanded: bool,
    pub child_count_label: String,
    /// Smart preview label for collapsed array elements (e.g., "lodash@4.17.21").
    pub preview: String,
    pub is_last_sibling: bool,
    pub ancestors_last: Vec<bool>,
}

/// Flatten the JSON tree into a list respecting expand/collapse state.
#[allow(clippy::too_many_arguments)]
pub fn flatten_json_tree(
    node: &JsonTreeNode,
    parent_path: &str,
    depth: usize,
    expanded: &std::collections::HashSet<String>,
    items: &mut Vec<FlatJsonItem>,
    is_last_sibling: bool,
    ancestors_last: &[bool],
    sort_mode: SourceSortMode,
    parent_key: &str,
) {
    let node_id = node.node_id(parent_path);
    let is_expanded = expanded.contains(&node_id);

    let value_preview = match node {
        JsonTreeNode::Leaf { value, .. } => value.clone(),
        _ => String::new(),
    };

    let value_type = match node {
        JsonTreeNode::Leaf { value_type, .. } => Some(*value_type),
        _ => None,
    };

    // Smart preview for collapsed array element objects
    let preview = if node.is_expandable() {
        node.preview_label(parent_key)
    } else {
        String::new()
    };

    items.push(FlatJsonItem {
        node_id: node_id.clone(),
        depth,
        display_key: node.display_key(),
        value_preview,
        value_type,
        is_expandable: node.is_expandable(),
        is_expanded,
        child_count_label: node.child_count_label(),
        preview,
        is_last_sibling,
        ancestors_last: ancestors_last.to_vec(),
    });

    if is_expanded && let Some(children) = node.children() {
        let mut current_ancestors = ancestors_last.to_vec();
        current_ancestors.push(is_last_sibling);

        // Determine the key to pass as parent context for child previews
        let this_key = node.key();
        let child_parent_key = if this_key.is_empty() {
            // Array element (index-based) — pass through the parent key
            parent_key
        } else {
            this_key
        };

        // Optionally sort children by key
        let sorted_children: Vec<&JsonTreeNode>;
        let children_ref: &[&JsonTreeNode] = match sort_mode {
            SourceSortMode::None => {
                sorted_children = children.iter().collect();
                &sorted_children
            }
            SourceSortMode::KeyAsc => {
                sorted_children = {
                    let mut v: Vec<&JsonTreeNode> = children.iter().collect();
                    v.sort_by_key(|a| a.display_key());
                    v
                };
                &sorted_children
            }
            SourceSortMode::KeyDesc => {
                sorted_children = {
                    let mut v: Vec<&JsonTreeNode> = children.iter().collect();
                    v.sort_by_key(|b| std::cmp::Reverse(b.display_key()));
                    v
                };
                &sorted_children
            }
        };

        for (i, child) in children_ref.iter().enumerate() {
            let child_is_last = i == children_ref.len() - 1;
            flatten_json_tree(
                child,
                &node_id,
                depth + 1,
                expanded,
                items,
                child_is_last,
                &current_ancestors,
                sort_mode,
                child_parent_key,
            );
        }
    }
}

/// Render a source panel (dispatches to tree or raw based on view mode).
pub fn render_source_panel(
    frame: &mut Frame,
    area: Rect,
    state: &mut SourcePanelState,
    title: &str,
    is_focused: bool,
) {
    match state.view_mode {
        SourceViewMode::Tree => render_source_tree(frame, area, state, title, is_focused),
        SourceViewMode::Raw => render_source_raw(frame, area, state, title, is_focused),
    }
}

/// Render the JSON tree view.
fn render_source_tree(
    frame: &mut Frame,
    area: Rect,
    state: &mut SourcePanelState,
    title: &str,
    is_focused: bool,
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let has_tree = state.json_tree.is_some() || state.xml_tree.is_some();
    let mode_hint = if has_tree { " 'v':Raw " } else { "" };
    let node_info = if state.total_node_count > 0 {
        format!(" ({} nodes)", state.total_node_count)
    } else {
        String::new()
    };
    let filter_label = state.filter_label();
    let sort_label = state.sort_mode.label();
    let indicators = format!(
        "{}{}",
        if filter_label.is_empty() {
            String::new()
        } else {
            format!(" {filter_label}")
        },
        if sort_label.is_empty() {
            String::new()
        } else {
            format!(" {sort_label}")
        },
    );
    // We'll render the block after computing status bar (needs item_count)
    // Compute a preliminary inner to find dimensions
    let preliminary_block = Block::default().borders(Borders::ALL);
    let preliminary_inner = preliminary_block.inner(area);
    drop(preliminary_block);

    // Pre-compute item count for status bar
    state.ensure_flat_cache();
    let pre_item_count = state.cached_flat_items.len();
    let percent = ((state.selected + 1) * 100)
        .checked_div(pre_item_count)
        .unwrap_or(0);
    let status_bar = format!(
        " Ln {}/{} ({}%) ",
        state.selected + 1,
        pre_item_count,
        percent
    );

    // Fit the title to the border width by dropping whole suffix parts
    // (hint, then node count, then indicators) — ratatui otherwise clips it
    // mid-word ("(135 nod").
    let title_budget = area.width.saturating_sub(2) as usize;
    let full_title = format!(" {title} [Tree]{node_info}{indicators}{mode_hint}");
    let fitted_title = [
        full_title.clone(),
        format!(" {title} [Tree]{node_info}{indicators}"),
        format!(" {title} [Tree]{indicators}"),
        format!(" {title} [Tree]"),
        format!(" {title}"),
    ]
    .into_iter()
    .find(|t| UnicodeWidthStr::width(t.as_str()) <= title_budget)
    .unwrap_or(full_title);

    let block = Block::default()
        .title(fitted_title)
        .title_style(Style::default().fg(border_color).bold())
        .title_bottom(
            Line::from(status_bar)
                .right_aligned()
                .style(Style::default().fg(scheme.text_muted)),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);
    let _ = preliminary_inner;

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    if state.json_tree.is_none() && state.xml_tree.is_none() {
        let msg = ratatui::widgets::Paragraph::new(
            "Content is not valid JSON or XML. Press 'v' for raw text view.",
        )
        .style(Style::default().fg(scheme.text_muted));
        frame.render_widget(msg, inner);
        return;
    }

    // State should be pre-computed via prepare_source_render() before frame render
    let item_count = state.cached_flat_items.len();

    // Change summary bar (only in diff mode with sufficient height)
    let (summary_area, inner) = if !state.change_annotations.is_empty() && inner.height > 5 {
        (
            Some(Rect {
                x: inner.x,
                y: inner.y,
                width: inner.width,
                height: 1,
            }),
            Rect {
                x: inner.x,
                y: inner.y + 1,
                width: inner.width,
                height: inner.height.saturating_sub(1),
            },
        )
    } else {
        (None, inner)
    };

    if let Some(sa) = summary_area {
        // Ensure change_indices is populated (lazily built on first n/N press,
        // but the summary bar needs it immediately)
        if state.change_indices.is_empty() && !state.change_annotations.is_empty() {
            state.build_change_indices();
        }
        render_change_summary_bar(frame, sa, state, item_count, &scheme);
    }

    // Render JSON path breadcrumb
    let inner = if inner.height > 3 {
        let breadcrumb = state
            .cached_flat_items
            .get(state.selected)
            .map_or_else(String::new, |selected_item| {
                breadcrumb_from_node_id(&selected_item.node_id)
            });
        if !breadcrumb.is_empty() {
            let bc_style = Style::default().fg(scheme.text_muted).italic();
            let bc_width = inner.width as usize;
            let bc_display = if UnicodeWidthStr::width(breadcrumb.as_str()) > bc_width {
                // Take chars from the end, measured by display width
                let target = bc_width.saturating_sub(3);
                let mut width = 0;
                let trimmed: String = breadcrumb
                    .chars()
                    .rev()
                    .take_while(|ch| {
                        let w = UnicodeWidthChar::width(*ch).unwrap_or(1);
                        if width + w > target {
                            return false;
                        }
                        width += w;
                        true
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("...{trimmed}")
            } else {
                breadcrumb
            };
            render_str(
                frame.buffer_mut(),
                inner.x,
                inner.y,
                &bc_display,
                inner.width,
                bc_style,
            );
        }
        Rect {
            x: inner.x,
            y: inner.y + 1,
            width: inner.width,
            height: inner.height - 1,
        }
    } else {
        inner
    };

    // Scroll/viewport already adjusted by prepare_source_render()
    let visible_height = inner.height as usize;

    // When the scrollbar will render it overdraws the last column AFTER the
    // text pass — reserve it up front so row tails elide with '…' instead of
    // being silently eaten ("4.17.21" reading as "4.17").
    let text_right = if item_count > visible_height {
        inner.x + inner.width.saturating_sub(1)
    } else {
        inner.x + inner.width
    };

    // Render visible rows
    for (i, item) in state
        .cached_flat_items
        .iter()
        .skip(state.scroll_offset)
        .take(visible_height)
        .enumerate()
    {
        let y = inner.y + i as u16;
        let abs_idx = state.scroll_offset + i;
        let is_selected = abs_idx == state.selected;

        // Render collapsed placeholder (skip normal rendering)
        if item.node_id.starts_with("__collapsed_") {
            let indent = "      ";
            let display = format!("{indent}{}", item.display_key);
            let style = if is_selected {
                Style::default()
                    .fg(scheme.muted)
                    .italic()
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(scheme.muted).italic()
            };
            render_str(frame.buffer_mut(), inner.x, y, &display, inner.width, style);
            continue;
        }

        // Render gap placeholder for panel alignment (skip normal rendering)
        if item.node_id.starts_with("__gap_") {
            let style = Style::default()
                .fg(scheme.muted)
                .add_modifier(Modifier::DIM);
            // Gutter space + indent to align with component depth
            let indent = "      ";
            let display = format!("{indent}{}", item.display_key);
            render_str(frame.buffer_mut(), inner.x, y, &display, inner.width, style);
            continue;
        }

        let mut x = inner.x;

        // Change gutter indicator (only in diff mode)
        if !state.change_annotations.is_empty() {
            let change_status = state.find_annotation(&item.node_id);
            let (ch, color) = match change_status {
                Some(SourceChangeStatus::Added) => ("+", scheme.added),
                Some(SourceChangeStatus::Removed) => ("-", scheme.removed),
                Some(SourceChangeStatus::Modified) => ("~", scheme.modified),
                None => (" ", scheme.muted),
            };
            let span = Span::styled(ch, Style::default().fg(color).bold());
            frame.buffer_mut().set_span(x, y, &span, 1);
            x += 1;
        }

        // Line number (when enabled)
        if state.show_line_numbers {
            let total = state.cached_flat_items.len();
            let gutter_w = format!("{total}").len();
            let num_str = format!("{:>gutter_w$} ", abs_idx + 1);
            let line_num_style = if !state.change_annotations.is_empty() {
                // In diff mode: bold + colored for changed lines, dimmed for unchanged
                match state.find_annotation(&item.node_id) {
                    Some(SourceChangeStatus::Added) => Style::default().fg(scheme.added).bold(),
                    Some(SourceChangeStatus::Removed) => Style::default().fg(scheme.removed).bold(),
                    Some(SourceChangeStatus::Modified) => {
                        Style::default().fg(scheme.modified).bold()
                    }
                    None => Style::default().fg(scheme.muted),
                }
            } else {
                Style::default().fg(scheme.text_muted)
            };
            render_str(
                frame.buffer_mut(),
                x,
                y,
                &num_str,
                inner.width,
                line_num_style,
            );
            x += num_str.len() as u16;
        }

        // Bookmark indicator
        if state.bookmarks.contains(&abs_idx) {
            render_str(
                frame.buffer_mut(),
                x,
                y,
                "\u{2605} ",
                inner.width.saturating_sub(x - inner.x),
                Style::default().fg(scheme.warning),
            );
        }

        // Selection indicator (compact: 1 char, normal: 2 chars)
        let compact = state.compact_mode;
        let (sel_str, sel_width): (&str, u16) = if compact {
            if is_selected { (">", 1) } else { (" ", 1) }
        } else if is_selected {
            ("> ", 2)
        } else {
            ("  ", 2)
        };
        render_str(
            frame.buffer_mut(),
            x,
            y,
            sel_str,
            inner.width.saturating_sub(x - inner.x),
            Style::default().fg(scheme.accent).bold(),
        );
        x += sel_width;

        // Tree connector lines (compact: 2-char, normal: 3-char)
        if item.depth > 0 {
            let connector_style = Style::default().fg(scheme.muted);
            let connector_width: u16 = if compact { 2 } else { 3 };
            // Draw ancestor continuation lines
            for d in 0..item.depth - 1 {
                let is_ancestor_last = item.ancestors_last.get(d + 1).copied().unwrap_or(false);
                let connector = if compact {
                    if is_ancestor_last { "  " } else { "│ " }
                } else if is_ancestor_last {
                    "   "
                } else {
                    "│  "
                };
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    connector,
                    inner.width.saturating_sub(x - inner.x),
                    connector_style,
                );
                x += connector_width;
            }
            // Draw branch connector for this node
            let branch = if compact {
                if item.is_last_sibling { "└ " } else { "├ " }
            } else if item.is_last_sibling {
                "└─ "
            } else {
                "├─ "
            };
            render_str(
                frame.buffer_mut(),
                x,
                y,
                branch,
                inner.width.saturating_sub(x - inner.x),
                connector_style,
            );
            x += connector_width;
        }

        // Expand/collapse indicator (compact: 1 char no trailing space, normal: 2 chars)
        if item.is_expandable {
            let (indicator, ind_width): (&str, u16) = if compact {
                if item.is_expanded {
                    ("\u{25bc}", 1)
                } else {
                    ("\u{25b6}", 1)
                }
            } else if item.is_expanded {
                ("\u{25bc} ", 2)
            } else {
                ("\u{25b6} ", 2)
            };
            render_str(
                frame.buffer_mut(),
                x,
                y,
                indicator,
                inner.width.saturating_sub(x - inner.x),
                Style::default().fg(scheme.accent),
            );
            x += ind_width;
        }

        let remaining = text_right;

        // Key name
        if !item.display_key.is_empty() && x < remaining {
            let key_style = Style::default().fg(scheme.primary);
            render_str(
                frame.buffer_mut(),
                x,
                y,
                &item.display_key,
                remaining - x,
                key_style,
            );
            let key_width = UnicodeWidthStr::width(item.display_key.as_str());
            let max_w = (remaining - x) as usize;
            x += key_width.min(max_w) as u16;

            if (!item.value_preview.is_empty() || item.is_expandable) && x + 2 < remaining {
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    ": ",
                    remaining - x,
                    Style::default().fg(scheme.text_muted),
                );
                x += 2;
            }
        }

        // Value or child count (with smart preview for collapsed array elements)
        if x < remaining {
            let max_w = (remaining - x) as usize;
            if item.is_expandable
                && !item.is_expanded
                && !item.preview.is_empty()
                && state.version_diffs.contains_key(&item.node_id)
            {
                // Inline version diff for modified components
                let (old_v, new_v) = &state.version_diffs[&item.node_id];
                let preview = &item.preview;
                // Parse preview: "name@version (type)" or just "name@version"
                let (name_part, type_suffix) = if let Some(at_pos) = preview.find('@') {
                    let name = &preview[..at_pos];
                    let rest = &preview[at_pos + 1..];
                    let suffix = rest.find(" (").map_or("", |p| &rest[p..]);
                    (name, suffix)
                } else {
                    (preview.as_str(), "")
                };
                // Render: name  old_v -> new_v  (type)
                let buf = frame.buffer_mut();
                render_str(
                    buf,
                    x,
                    y,
                    name_part,
                    remaining - x,
                    Style::default().fg(scheme.text),
                );
                x += (UnicodeWidthStr::width(name_part).min(max_w)) as u16;
                if x < remaining {
                    render_str(buf, x, y, " ", remaining - x, Style::default());
                    x += 1;
                }
                if x < remaining {
                    render_str(
                        buf,
                        x,
                        y,
                        old_v,
                        remaining - x,
                        Style::default()
                            .fg(scheme.muted)
                            .add_modifier(Modifier::DIM),
                    );
                    x += (UnicodeWidthStr::width(old_v.as_str()).min((remaining - x) as usize))
                        as u16;
                }
                if x + 3 < remaining {
                    render_str(
                        buf,
                        x,
                        y,
                        " \u{2192} ",
                        remaining - x,
                        Style::default().fg(scheme.modified),
                    );
                    x += 3;
                }
                if x < remaining {
                    render_str(
                        buf,
                        x,
                        y,
                        new_v,
                        remaining - x,
                        Style::default().fg(scheme.modified).bold(),
                    );
                    x += (UnicodeWidthStr::width(new_v.as_str()).min((remaining - x) as usize))
                        as u16;
                }
                if !type_suffix.is_empty() && x < remaining {
                    render_str(
                        buf,
                        x,
                        y,
                        type_suffix,
                        remaining - x,
                        Style::default().fg(scheme.muted),
                    );
                }
            } else if item.is_expandable && !item.is_expanded && !item.preview.is_empty() {
                // Smart preview for collapsed array elements
                let preview_str = crate::tui::widgets::truncate_str(&item.preview, max_w);
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    &preview_str,
                    remaining - x,
                    Style::default().fg(scheme.text),
                );
            } else if item.is_expandable {
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    &item.child_count_label,
                    remaining - x,
                    Style::default().fg(scheme.text_muted),
                );
            } else if !item.value_preview.is_empty() {
                let val_style = match item.value_type {
                    Some(JsonValueType::String) => Style::default().fg(scheme.success),
                    Some(JsonValueType::Number) => Style::default().fg(scheme.accent),
                    Some(JsonValueType::Boolean) => Style::default().fg(scheme.warning),
                    Some(JsonValueType::Null) => Style::default().fg(scheme.text_muted),
                    None => Style::default().fg(scheme.text),
                };
                let display_val = crate::tui::widgets::truncate_str(&item.value_preview, max_w);
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    &display_val,
                    remaining - x,
                    val_style,
                );
                let val_w = UnicodeWidthStr::width(display_val.as_str());
                x += val_w.min(max_w) as u16;
            }
        }

        // Link indicator for navigable references (e.g., " → lodash@4.17.21")
        if let Some(label) = state.link_labels.get(&abs_idx) {
            let short_label = shorten_path_label(label, 40);
            let link_text = format!(" \u{2192} {short_label}");
            if x + 4 < remaining {
                let avail = (remaining - x) as usize;
                let truncated = crate::tui::widgets::truncate_str(&link_text, avail);
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    &truncated,
                    remaining - x,
                    Style::default().fg(scheme.primary).italic(),
                );
            }
        }

        // Diff change annotation: bold text on changed lines (difftastic-style)
        // Instead of heavy background fills, use bold+colored text for emphasis
        // and dim unchanged lines for contrast
        if !state.change_annotations.is_empty()
            && let Some(status) = state.find_annotation(&item.node_id)
        {
            let fg = match status {
                SourceChangeStatus::Added => scheme.added,
                SourceChangeStatus::Removed => scheme.removed,
                SourceChangeStatus::Modified => scheme.modified,
            };
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_fg(fg);
                    cell.modifier.insert(ratatui::style::Modifier::BOLD);
                }
            }
            // Unchanged lines: keep original syntax highlighting (don't override)
        }

        // Highlight selected row background
        if is_selected {
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                }
            }
        }

        // Search match highlighting (substring-level)
        if !state.search_matches.is_empty()
            && state.search_query.len() >= 2
            && state.search_matches.binary_search(&abs_idx).is_ok()
        {
            let is_current = state.search_matches.get(state.search_current) == Some(&abs_idx);
            let display_text = format!(
                "{}: {}{}",
                item.display_key, item.value_preview, item.child_count_label
            );
            highlight_search_in_row(
                frame.buffer_mut(),
                y,
                inner.x,
                remaining,
                &display_text,
                &state.search_query,
                is_current,
                &scheme,
            );
        }
    }

    // Search bar
    render_search_bar(frame, inner, state, &scheme);

    // Scrollbar
    if item_count > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));
        let mut sb_state = ScrollbarState::new(item_count).position(state.selected);
        frame.render_stateful_widget(scrollbar, inner, &mut sb_state);
    }
}

/// Render the raw text view with line numbers, indent guides, bracket matching,
/// structural dimming, and code folding.
fn render_source_raw(
    frame: &mut Frame,
    area: Rect,
    state: &mut SourcePanelState,
    title: &str,
    is_focused: bool,
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.border_focused
    } else {
        scheme.border
    };

    let has_json_tree = state.json_tree.is_some();
    let has_xml_tree = state.xml_tree.is_some();
    let has_tree = has_json_tree || has_xml_tree;
    let mode_hint = if has_tree { " 'v':Tree " } else { "" };
    let wrap_hint = if state.word_wrap { " [Wrap]" } else { "" };
    let col_hint = if !state.word_wrap && state.h_scroll_offset > 0 {
        format!(" col:{}", state.h_scroll_offset)
    } else {
        String::new()
    };
    let fold_hint = if !state.folded_lines.is_empty() {
        format!(" [{} folded]", state.folded_lines.len())
    } else {
        String::new()
    };

    // Status bar
    let total_lines = state.raw_lines.len();
    let percent = ((state.selected + 1) * 100)
        .checked_div(total_lines)
        .unwrap_or(0);
    let col_info = if !state.word_wrap && state.h_scroll_offset > 0 {
        format!(" Col {}", state.h_scroll_offset)
    } else {
        String::new()
    };
    let status_bar = format!(
        " Ln {}/{}{} ({}%) ",
        state.selected + 1,
        total_lines,
        col_info,
        percent
    );

    let block = Block::default()
        .title(format!(
            " {title} [Raw] ({total_lines} lines){col_hint}{wrap_hint}{fold_hint}{mode_hint} ",
        ))
        .title_style(Style::default().fg(border_color).bold())
        .title_bottom(
            Line::from(status_bar)
                .right_aligned()
                .style(Style::default().fg(scheme.text_muted)),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    // State should be pre-computed via prepare_source_render() before frame render

    // Change summary bar (only in diff mode with sufficient height)
    let (summary_area, inner) = if !state.change_annotations.is_empty() && inner.height > 5 {
        (
            Some(Rect {
                x: inner.x,
                y: inner.y,
                width: inner.width,
                height: 1,
            }),
            Rect {
                x: inner.x,
                y: inner.y + 1,
                width: inner.width,
                height: inner.height.saturating_sub(1),
            },
        )
    } else {
        (None, inner)
    };

    if let Some(sa) = summary_area {
        if state.change_indices.is_empty() && !state.change_annotations.is_empty() {
            state.build_change_indices();
        }
        render_change_summary_bar(frame, sa, state, total_lines, &scheme);
    }

    // Breadcrumb bar for raw mode (like tree view has)
    let inner = if inner.height > 3 && has_json_tree {
        let breadcrumb = state
            .raw_line_node_ids
            .get(state.selected)
            .filter(|nid| !nid.is_empty())
            .map_or_else(String::new, |nid| breadcrumb_from_node_id(nid));
        if !breadcrumb.is_empty() {
            let bc_style = Style::default().fg(scheme.text_muted).italic();
            let bc_width = inner.width as usize;
            let bc_display = if UnicodeWidthStr::width(breadcrumb.as_str()) > bc_width {
                let target = bc_width.saturating_sub(3);
                let mut width = 0;
                let trimmed: String = breadcrumb
                    .chars()
                    .rev()
                    .take_while(|ch| {
                        let w = UnicodeWidthChar::width(*ch).unwrap_or(1);
                        if width + w > target {
                            return false;
                        }
                        width += w;
                        true
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                format!("...{trimmed}")
            } else {
                breadcrumb
            };
            render_str(
                frame.buffer_mut(),
                inner.x,
                inner.y,
                &bc_display,
                inner.width,
                bc_style,
            );
            Rect {
                x: inner.x,
                y: inner.y + 1,
                width: inner.width,
                height: inner.height - 1,
            }
        } else {
            inner
        }
    } else {
        inner
    };

    let visible_height = inner.height as usize;

    // Build visible line indices (skipping folded interiors)
    let visible_lines = build_visible_lines(state, visible_height);

    // Scroll adjustment using visible lines
    // (The scroll_offset for raw mode with folds is handled by build_visible_lines)

    let gutter_width = if state.raw_lines.is_empty() {
        1
    } else {
        format!("{}", state.raw_lines.len()).len()
    };

    // Reserve the scrollbar column (same overdraw hazard as the tree view).
    let remaining = if state.raw_lines.len() > visible_height {
        inner.x + inner.width.saturating_sub(1)
    } else {
        inner.x + inner.width
    };

    // [Feature 2] Pre-compute matching bracket for selected line
    let match_line = state.matching_bracket(state.selected);

    // Pre-compute enclosing scope for selected line (for scope highlighting)
    let enclosing_scope = find_enclosing_scope(state, state.selected);

    // Compute scope indent level for active scope gutter indicator
    let scope_indent_level: Option<usize> = enclosing_scope.and_then(|(scope_start, _)| {
        state.raw_lines.get(scope_start).map(|line| {
            let leading = line.len() - line.trim_start().len();
            leading / 2 // serde_json indent size = 2
        })
    });

    // Sticky scope header: if enclosing scope's opening line is scrolled off-screen
    let sticky_header_line: Option<usize> = enclosing_scope.and_then(|(scope_start, _)| {
        if !visible_lines.is_empty() && scope_start < visible_lines[0] {
            Some(scope_start)
        } else {
            None
        }
    });

    for (i, &abs_idx) in visible_lines.iter().enumerate() {
        let y = inner.y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }
        let line_num = abs_idx + 1;
        let is_selected = abs_idx == state.selected;
        let is_bracket_match = match_line == Some(abs_idx);

        let line = &state.raw_lines[abs_idx];
        let is_folded_start = state.folded_lines.contains(&abs_idx);

        // [Feature 5] Structural line dimming
        let is_structural = is_structural_line(line);

        // Change gutter indicator (only in diff mode)
        let change_gutter_offset: u16 = if !state.change_annotations.is_empty() {
            let change_status = state
                .raw_line_node_ids
                .get(abs_idx)
                .and_then(|node_id| state.find_annotation(node_id));
            let (ch, color) = match change_status {
                Some(SourceChangeStatus::Added) => ("+", scheme.added),
                Some(SourceChangeStatus::Removed) => ("-", scheme.removed),
                Some(SourceChangeStatus::Modified) => ("~", scheme.modified),
                None => (" ", scheme.muted),
            };
            let span = Span::styled(ch, Style::default().fg(color).bold());
            frame.buffer_mut().set_span(inner.x, y, &span, 1);
            1
        } else {
            0
        };

        // Bookmark indicator
        if state.bookmarks.contains(&abs_idx) {
            render_str(
                frame.buffer_mut(),
                inner.x + change_gutter_offset,
                y,
                "\u{2605}",
                1,
                Style::default().fg(scheme.warning),
            );
        }

        // Line number gutter — highlight matching bracket; diff-aware coloring
        let raw_change_status = state
            .raw_line_node_ids
            .get(abs_idx)
            .and_then(|node_id| state.find_annotation(node_id));
        let gutter_style = if is_bracket_match {
            Style::default().fg(scheme.accent).bold()
        } else if !state.change_annotations.is_empty() {
            // In diff mode: bold + colored for changed lines, dimmed for unchanged
            match raw_change_status {
                Some(SourceChangeStatus::Added) => Style::default().fg(scheme.added).bold(),
                Some(SourceChangeStatus::Removed) => Style::default().fg(scheme.removed).bold(),
                Some(SourceChangeStatus::Modified) => Style::default().fg(scheme.modified).bold(),
                None => Style::default().fg(scheme.muted),
            }
        } else if is_structural {
            Style::default().fg(scheme.muted)
        } else {
            Style::default().fg(scheme.text_muted)
        };

        // [Feature 4] Fold indicator in gutter
        let fold_char = if is_folded_start {
            "\u{25b6}" // ▶ (folded)
        } else if state.bracket_pairs.contains_key(&abs_idx) {
            "\u{25bc}" // ▼ (foldable, expanded)
        } else {
            " "
        };
        let num_str = format!("{fold_char}{line_num:>gutter_width$} \u{2502} ");
        render_str(
            frame.buffer_mut(),
            inner.x + change_gutter_offset,
            y,
            &num_str,
            remaining - inner.x,
            gutter_style,
        );
        // Color the fold indicator separately
        if state.bracket_pairs.contains_key(&abs_idx)
            || state.bracket_pairs_reverse.contains_key(&abs_idx)
        {
            let fold_style = if is_folded_start {
                Style::default().fg(scheme.accent)
            } else {
                Style::default().fg(scheme.muted)
            };
            if let Some(cell) = frame
                .buffer_mut()
                .cell_mut((inner.x + change_gutter_offset, y))
            {
                cell.set_style(fold_style);
            }
        }

        let content_x = inner.x + change_gutter_offset + num_str.len() as u16;
        if content_x < remaining {
            let max_w = remaining - content_x;

            if is_folded_start {
                // [Feature 4] Show fold summary instead of content
                let fold_end = state
                    .bracket_pairs
                    .get(&abs_idx)
                    .copied()
                    .unwrap_or(abs_idx);
                let hidden = fold_end - abs_idx;
                let trimmed = line.trim();
                let summary = format!("{trimmed} \u{2026} ({hidden} lines)");
                render_str(
                    frame.buffer_mut(),
                    content_x,
                    y,
                    &summary,
                    max_w,
                    Style::default().fg(scheme.accent),
                );
            } else {
                // Apply horizontal scroll offset
                let display_line = if state.word_wrap {
                    line.to_string()
                } else if state.h_scroll_offset > 0 {
                    skip_display_chars(line, state.h_scroll_offset)
                } else {
                    line.to_string()
                };

                if has_json_tree {
                    // [Feature 5] Structural lines get dimmed rendering
                    if is_structural {
                        render_str(
                            frame.buffer_mut(),
                            content_x,
                            y,
                            &display_line,
                            max_w,
                            Style::default().fg(scheme.muted),
                        );
                    } else {
                        render_json_line_highlighted(
                            frame.buffer_mut(),
                            content_x,
                            y,
                            &display_line,
                            max_w,
                            &scheme,
                        );
                    }
                } else if has_xml_tree {
                    render_xml_line_highlighted(
                        frame.buffer_mut(),
                        content_x,
                        y,
                        &display_line,
                        max_w,
                        &scheme,
                    );
                } else {
                    render_str(
                        frame.buffer_mut(),
                        content_x,
                        y,
                        &display_line,
                        max_w,
                        Style::default().fg(scheme.text),
                    );
                }

                // Active scope indent guide: single guide at the enclosing
                // scope level, skipping structural-only lines for cleanliness
                if state.show_indent_guides
                    && has_json_tree
                    && state.h_scroll_offset == 0
                    && !is_structural
                    && let Some(scope_level) = scope_indent_level
                {
                    let leading_spaces = line.len() - line.trim_start().len();
                    let indent_size = 2; // serde_json pretty-print indent
                    let line_depth = leading_spaces / indent_size;
                    // Render on lines at or deeper than the scope content
                    if line_depth >= scope_level {
                        let guide_offset = (scope_level * indent_size) as u16;
                        let gx = content_x + guide_offset;
                        if gx < remaining
                            && let Some(cell) = frame.buffer_mut().cell_mut((gx, y))
                        {
                            cell.set_char('\u{2506}') // ┆ thin dashed guide
                                .set_style(Style::default().fg(scheme.accent));
                        }
                    }
                }
            }
        }

        // Link indicator for navigable references in raw mode
        if let Some(label) = state.link_labels.get(&abs_idx)
            && !is_folded_start
            && !is_structural
        {
            // For path-like labels, show the basename (end of path)
            let short_label = shorten_path_label(label, 40);
            let link_text = format!(" \u{2192} {short_label}");
            // Estimate current x position from content
            let line_display_len = if state.word_wrap || state.h_scroll_offset == 0 {
                UnicodeWidthStr::width(line.as_str())
            } else {
                UnicodeWidthStr::width(skip_display_chars(line, state.h_scroll_offset).as_str())
            };
            let link_x = content_x + (line_display_len as u16).min(remaining - content_x);
            if link_x + 4 < remaining {
                let avail = (remaining - link_x) as usize;
                let truncated = crate::tui::widgets::truncate_str(&link_text, avail);
                render_str(
                    frame.buffer_mut(),
                    link_x,
                    y,
                    &truncated,
                    remaining - link_x,
                    Style::default().fg(scheme.primary).italic(),
                );
            }
        }

        // Diff change annotation: bold text on changed lines (difftastic-style)
        if !state.change_annotations.is_empty() {
            let annotation = state
                .raw_line_node_ids
                .get(abs_idx)
                .and_then(|node_id| state.find_annotation(node_id));
            if let Some(status) = annotation {
                let fg = match status {
                    SourceChangeStatus::Added => scheme.added,
                    SourceChangeStatus::Removed => scheme.removed,
                    SourceChangeStatus::Modified => scheme.modified,
                };
                for col in inner.x..remaining {
                    if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                        cell.set_fg(fg);
                        cell.modifier.insert(ratatui::style::Modifier::BOLD);
                    }
                }
            }
            // Unchanged lines: keep original syntax highlighting (don't override)
        }

        // Highlight selected row
        if is_selected {
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                }
            }
        }

        // Search match highlighting (substring-level)
        if !state.search_matches.is_empty()
            && state.search_query.len() >= 2
            && state.search_matches.binary_search(&abs_idx).is_ok()
        {
            let is_current = state.search_matches.get(state.search_current) == Some(&abs_idx);
            highlight_search_in_row(
                frame.buffer_mut(),
                y,
                content_x,
                remaining,
                line,
                &state.search_query,
                is_current,
                &scheme,
            );
        }
    }

    // Sticky scope header: render the opening bracket line at the top when scrolled off
    if let Some(header_line_idx) = sticky_header_line
        && let Some(header_line) = state.raw_lines.get(header_line_idx)
    {
        let header_y = inner.y;
        // Clear the first row with background_alt
        for col in inner.x..remaining {
            if let Some(cell) = frame.buffer_mut().cell_mut((col, header_y)) {
                cell.reset();
                cell.set_bg(scheme.background_alt);
            }
        }
        // Render the line number + content
        let header_num = format!(" {:>gutter_width$} \u{2502} ", header_line_idx + 1,);
        render_str(
            frame.buffer_mut(),
            inner.x,
            header_y,
            &header_num,
            remaining - inner.x,
            Style::default()
                .fg(scheme.text_muted)
                .bg(scheme.background_alt),
        );
        let header_content_x = inner.x + header_num.len() as u16;
        if header_content_x < remaining {
            let display_line = if state.h_scroll_offset > 0 {
                skip_display_chars(header_line, state.h_scroll_offset)
            } else {
                header_line.to_string()
            };
            render_str(
                frame.buffer_mut(),
                header_content_x,
                header_y,
                &display_line,
                remaining - header_content_x,
                Style::default().fg(scheme.text).bg(scheme.background_alt),
            );
        }
    }

    // Search bar
    render_search_bar(frame, inner, state, &scheme);

    // Scrollbar
    if state.raw_lines.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(scheme.accent))
            .track_style(Style::default().fg(scheme.muted));
        let mut sb_state = ScrollbarState::new(state.raw_lines.len()).position(state.selected);
        frame.render_stateful_widget(scrollbar, inner, &mut sb_state);
    }
}

/// Find the innermost bracket scope containing the given line.
/// Returns (opening_line, closing_line) if found.
fn find_enclosing_scope(state: &SourcePanelState, line: usize) -> Option<(usize, usize)> {
    // Check if this line IS an opening bracket
    if let Some(&end) = state.bracket_pairs.get(&line) {
        return Some((line, end));
    }
    // Walk backwards to find the enclosing opening bracket
    for start_line in (0..line).rev() {
        if let Some(&end_line) = state.bracket_pairs.get(&start_line)
            && end_line >= line
        {
            return Some((start_line, end_line));
        }
    }
    None
}

/// Shorten a label for display: if it looks like a file path and exceeds
/// `max_len`, show `…/basename` instead of truncating from the right.
fn shorten_path_label(label: &str, max_len: usize) -> String {
    if label.len() <= max_len {
        return label.to_string();
    }
    // If it contains path separators, show the basename
    if let Some(last_sep) = label.rfind('/') {
        let basename = &label[last_sep + 1..];
        if basename.len() + 2 <= max_len {
            return format!("\u{2026}/{basename}"); // …/filename
        }
    }
    // Fallback: truncate from the right
    let truncated: String = label.chars().take(max_len.saturating_sub(1)).collect();
    format!("{truncated}\u{2026}")
}

/// Build the list of visible raw line indices, skipping folded interiors.
/// Starts from the scroll region around `state.selected` and returns up to
/// `visible_height` line indices.
fn build_visible_lines(state: &mut SourcePanelState, visible_height: usize) -> Vec<usize> {
    if state.folded_lines.is_empty() {
        // Fast path: no folds, use simple range
        if visible_height > 0 {
            if state.selected >= state.scroll_offset + visible_height {
                state.scroll_offset = state.selected.saturating_sub(visible_height - 1);
            } else if state.selected < state.scroll_offset {
                state.scroll_offset = state.selected;
            }
        }
        return (state.scroll_offset..)
            .take(visible_height)
            .take_while(|&i| i < state.raw_lines.len())
            .collect();
    }

    // With folds: build full visible line list, then window around selected
    let total = state.raw_lines.len();
    let mut all_visible = Vec::with_capacity(total / 2);
    let mut i = 0;
    while i < total {
        all_visible.push(i);
        if state.folded_lines.contains(&i) {
            // Skip to after the fold end
            if let Some(&end) = state.bracket_pairs.get(&i) {
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    // Find selected line's position in visible list
    let sel_pos = all_visible
        .iter()
        .position(|&l| l == state.selected)
        .unwrap_or(0);

    // Window around selected
    let start = sel_pos.saturating_sub(visible_height / 3);
    let end = (start + visible_height).min(all_visible.len());
    let start = if end == all_visible.len() {
        end.saturating_sub(visible_height)
    } else {
        start
    };

    all_visible[start..end].to_vec()
}

/// Check if a raw line is purely structural (just braces, brackets, commas).
fn is_structural_line(line: &str) -> bool {
    let trimmed = line.trim();
    matches!(trimmed, "{" | "}" | "}," | "[" | "]" | "]," | "{}" | "[]")
}

/// Render a raw JSON line with syntax highlighting.
fn render_json_line_highlighted(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    line: &str,
    max_width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let mut cx = x;
    let limit = x + max_width;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() && cx < limit {
        let ch = chars[i];
        match ch {
            '{' | '}' | '[' | ']' | ':' | ',' => {
                if let Some(cell) = buf.cell_mut((cx, y)) {
                    cell.set_char(ch)
                        .set_style(Style::default().fg(scheme.text_muted));
                }
                cx += 1;
                i += 1;
            }
            '"' => {
                // Find end of quoted string
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // skip closing quote
                }

                // Look ahead past whitespace for ':' to determine if key or value
                let mut lookahead = i;
                while lookahead < chars.len() && chars[lookahead].is_whitespace() {
                    lookahead += 1;
                }
                let is_key = lookahead < chars.len() && chars[lookahead] == ':';
                let style = if is_key {
                    Style::default().fg(scheme.primary)
                } else {
                    Style::default().fg(scheme.success)
                };

                for ch in &chars[start..i] {
                    if cx >= limit {
                        break;
                    }
                    let w = UnicodeWidthChar::width(*ch).unwrap_or(1) as u16;
                    if cx + w > limit {
                        break;
                    }
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(*ch).set_style(style);
                    }
                    cx += w;
                }
            }
            't' | 'f' if json_looks_like_bool(&chars, i) => {
                let word_len = if ch == 't' { 4 } else { 5 };
                let style = Style::default().fg(scheme.warning);
                for j in 0..word_len {
                    if i + j < chars.len() && cx < limit {
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char(chars[i + j]).set_style(style);
                        }
                        cx += 1;
                    }
                }
                i += word_len;
            }
            'n' if json_looks_like_null(&chars, i) => {
                let style = Style::default().fg(scheme.text_muted);
                for j in 0..4 {
                    if i + j < chars.len() && cx < limit {
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char(chars[i + j]).set_style(style);
                        }
                        cx += 1;
                    }
                }
                i += 4;
            }
            '0'..='9' | '-' => {
                let style = Style::default().fg(scheme.accent);
                while i < chars.len()
                    && (chars[i].is_ascii_digit()
                        || chars[i] == '.'
                        || chars[i] == '-'
                        || chars[i] == 'e'
                        || chars[i] == 'E'
                        || chars[i] == '+')
                {
                    if cx >= limit {
                        break;
                    }
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(chars[i]).set_style(style);
                    }
                    cx += 1;
                    i += 1;
                }
            }
            _ => {
                let w = UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
                if cx + w <= limit {
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(scheme.text));
                    }
                    cx += w;
                }
                i += 1;
            }
        }
    }
}

fn json_looks_like_bool(chars: &[char], i: usize) -> bool {
    let remaining = &chars[i..];
    (remaining.len() >= 4 && remaining[..4] == ['t', 'r', 'u', 'e'])
        || (remaining.len() >= 5 && remaining[..5] == ['f', 'a', 'l', 's', 'e'])
}

fn json_looks_like_null(chars: &[char], i: usize) -> bool {
    let remaining = &chars[i..];
    remaining.len() >= 4 && remaining[..4] == ['n', 'u', 'l', 'l']
}

/// Render a raw XML line with syntax highlighting.
fn render_xml_line_highlighted(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    line: &str,
    max_width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let mut cx = x;
    let limit = x + max_width;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() && cx < limit {
        let ch = chars[i];
        match ch {
            '<' => {
                // Check for comment: <!--
                if i + 3 < chars.len()
                    && chars[i + 1] == '!'
                    && chars[i + 2] == '-'
                    && chars[i + 3] == '-'
                {
                    let comment_style = Style::default().fg(scheme.text_muted);
                    // Render until -->
                    while i < chars.len() && cx < limit {
                        let w = UnicodeWidthChar::width(chars[i]).unwrap_or(1) as u16;
                        if cx + w > limit {
                            break;
                        }
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char(chars[i]).set_style(comment_style);
                        }
                        cx += w;
                        if i >= 2 && chars[i] == '>' && chars[i - 1] == '-' && chars[i - 2] == '-' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }

                // Tag start: render < in muted
                let struct_style = Style::default().fg(scheme.text_muted);
                if let Some(cell) = buf.cell_mut((cx, y)) {
                    cell.set_char('<').set_style(struct_style);
                }
                cx += 1;
                i += 1;

                // Optional / for closing tags
                if i < chars.len() && chars[i] == '/' {
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char('/').set_style(struct_style);
                    }
                    cx += 1;
                    i += 1;
                }

                // Tag name
                let tag_style = Style::default().fg(scheme.primary);
                while i < chars.len()
                    && cx < limit
                    && !chars[i].is_whitespace()
                    && chars[i] != '>'
                    && chars[i] != '/'
                {
                    let w = UnicodeWidthChar::width(chars[i]).unwrap_or(1) as u16;
                    if cx + w > limit {
                        break;
                    }
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(chars[i]).set_style(tag_style);
                    }
                    cx += w;
                    i += 1;
                }

                // Attributes inside tag
                while i < chars.len() && cx < limit && chars[i] != '>' {
                    if chars[i] == '/' {
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char('/').set_style(struct_style);
                        }
                        cx += 1;
                        i += 1;
                    } else if chars[i] == '"' {
                        // Quoted attribute value
                        let val_style = Style::default().fg(scheme.success);
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char('"').set_style(val_style);
                        }
                        cx += 1;
                        i += 1;
                        while i < chars.len() && cx < limit && chars[i] != '"' {
                            let w = UnicodeWidthChar::width(chars[i]).unwrap_or(1) as u16;
                            if cx + w > limit {
                                break;
                            }
                            if let Some(cell) = buf.cell_mut((cx, y)) {
                                cell.set_char(chars[i]).set_style(val_style);
                            }
                            cx += w;
                            i += 1;
                        }
                        if i < chars.len() && cx < limit {
                            if let Some(cell) = buf.cell_mut((cx, y)) {
                                cell.set_char('"').set_style(val_style);
                            }
                            cx += 1;
                            i += 1;
                        }
                    } else if chars[i] == '=' {
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char('=').set_style(struct_style);
                        }
                        cx += 1;
                        i += 1;
                    } else if chars[i].is_whitespace() {
                        if let Some(cell) = buf.cell_mut((cx, y)) {
                            cell.set_char(chars[i])
                                .set_style(Style::default().fg(scheme.text));
                        }
                        cx += 1;
                        i += 1;
                    } else {
                        // Attribute name
                        let attr_style = Style::default().fg(scheme.accent);
                        let w = UnicodeWidthChar::width(chars[i]).unwrap_or(1) as u16;
                        if cx + w <= limit {
                            if let Some(cell) = buf.cell_mut((cx, y)) {
                                cell.set_char(chars[i]).set_style(attr_style);
                            }
                            cx += w;
                        }
                        i += 1;
                    }
                }

                // Closing >
                if i < chars.len() && cx < limit && chars[i] == '>' {
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char('>').set_style(struct_style);
                    }
                    cx += 1;
                    i += 1;
                }
            }
            '&' => {
                // XML entity (e.g., &amp;)
                let entity_style = Style::default().fg(scheme.accent);
                while i < chars.len() && cx < limit {
                    let w = UnicodeWidthChar::width(chars[i]).unwrap_or(1) as u16;
                    if cx + w > limit {
                        break;
                    }
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(chars[i]).set_style(entity_style);
                    }
                    cx += w;
                    let done = chars[i] == ';';
                    i += 1;
                    if done {
                        break;
                    }
                }
            }
            _ => {
                // Text content
                let w = UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
                if cx + w <= limit {
                    if let Some(cell) = buf.cell_mut((cx, y)) {
                        cell.set_char(ch)
                            .set_style(Style::default().fg(scheme.text));
                    }
                    cx += w;
                }
                i += 1;
            }
        }
    }
}

/// Render search bar at the bottom of the panel.
fn render_search_bar(
    frame: &mut Frame,
    inner: Rect,
    state: &SourcePanelState,
    scheme: &crate::tui::theme::ColorScheme,
) {
    if !state.search_active && state.search_query.is_empty() {
        return;
    }

    let search_y = inner.y + inner.height.saturating_sub(1);
    let remaining = inner.x + inner.width;

    // Clear the last row
    for col in inner.x..remaining {
        if let Some(cell) = frame.buffer_mut().cell_mut((col, search_y)) {
            cell.reset();
        }
    }

    let cursor = if state.search_active { "\u{2588}" } else { "" };
    let match_info = if state.search_query.len() >= 2 {
        if state.search_matches.is_empty() {
            " (no matches)".to_string()
        } else {
            format!(
                " ({}/{})",
                state.search_current + 1,
                state.search_matches.len()
            )
        }
    } else {
        String::new()
    };

    let regex_indicator = if state.search_regex_mode { "[R] " } else { "" };
    let search_text = format!(
        "/{regex_indicator}{}{}{}",
        state.search_query, cursor, match_info
    );
    render_str(
        frame.buffer_mut(),
        inner.x,
        search_y,
        &search_text,
        inner.width,
        Style::default().fg(scheme.accent),
    );
}

/// Highlight search query substrings within a rendered row.
///
/// After a row has been rendered, this overlays the search highlight on cells
/// that match the query. Only applies to visible buffer cells.
#[allow(clippy::too_many_arguments)]
fn highlight_search_in_row(
    buf: &mut Buffer,
    y: u16,
    x_start: u16,
    x_end: u16,
    displayed_text: &str,
    query: &str,
    is_current_match: bool,
    scheme: &crate::tui::theme::ColorScheme,
) {
    if query.is_empty() || displayed_text.is_empty() {
        return;
    }

    let bg = if is_current_match {
        scheme.search_highlight_bg
    } else {
        scheme.highlight
    };

    let lower_text = displayed_text.to_lowercase();
    let lower_query = query.to_lowercase();

    // Collect char positions → column offsets
    let char_cols: Vec<(usize, u16)> = {
        let mut cols = Vec::new();
        let mut col: u16 = 0;
        for (byte_idx, ch) in displayed_text.char_indices() {
            cols.push((byte_idx, col));
            col += UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
        }
        cols
    };

    // Find all occurrences of the query in the text (case-insensitive)
    let mut search_start = 0;
    while let Some(pos) = lower_text[search_start..].find(&lower_query) {
        let byte_start = search_start + pos;
        let byte_end = byte_start + lower_query.len();
        search_start = byte_start + 1;

        // Map byte range to column range
        let col_start = char_cols
            .iter()
            .find(|(b, _)| *b >= byte_start)
            .map(|(_, c)| *c);
        let col_end = char_cols
            .iter()
            .find(|(b, _)| *b >= byte_end)
            .map(|(_, c)| *c)
            .unwrap_or_else(|| {
                // End of string
                char_cols
                    .last()
                    .map(|(_, c)| {
                        *c + UnicodeWidthChar::width(displayed_text.chars().last().unwrap_or(' '))
                            .unwrap_or(1) as u16
                    })
                    .unwrap_or(0)
            });

        if let Some(start_col) = col_start {
            for col in start_col..col_end {
                let abs_col = x_start + col;
                if abs_col >= x_end {
                    break;
                }
                if let Some(cell) = buf.cell_mut((abs_col, y)) {
                    cell.set_bg(bg);
                }
            }
        }
    }
}

/// Build a breadcrumb string from a node ID path.
fn breadcrumb_from_node_id(node_id: &str) -> String {
    if node_id.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = node_id.split('.').collect();
    parts.join(" > ")
}

/// Skip a given number of display-width characters from the start of a string.
fn skip_display_chars(s: &str, skip_width: usize) -> String {
    let mut skipped = 0;
    let mut chars = s.chars();
    for ch in chars.by_ref() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(1);
        skipped += w;
        if skipped >= skip_width {
            break;
        }
    }
    chars.collect()
}

/// Render a 1-line summary bar showing change positions within the file.
fn render_change_summary_bar(
    frame: &mut Frame,
    area: Rect,
    state: &SourcePanelState,
    total_items: usize,
    scheme: &crate::tui::theme::ColorScheme,
) {
    if area.width < 12 || total_items == 0 {
        return;
    }

    let change_count = state.change_indices.len();
    // Reserve space for " N changes" label on the right
    let label = format!(" {change_count} changes");
    let bar_width = (area.width as usize).saturating_sub(label.len() + 4);
    if bar_width < 5 {
        return;
    }

    // Build bar characters
    let mut bar: Vec<(char, Color)> = vec![('\u{2591}', scheme.muted); bar_width]; // ░

    for &idx in &state.change_indices {
        let col = (idx * bar_width) / total_items.max(1);
        let col = col.min(bar_width - 1);
        // Determine color
        let color = state
            .change_status_at_index(idx)
            .map_or(scheme.modified, |s| match s {
                SourceChangeStatus::Added => scheme.added,
                SourceChangeStatus::Removed => scheme.removed,
                SourceChangeStatus::Modified => scheme.modified,
            });
        bar[col] = ('\u{2588}', color); // █
    }

    // Cursor position marker
    let cursor_col = if total_items > 0 {
        (state.selected * bar_width) / total_items.max(1)
    } else {
        0
    };
    let cursor_col = cursor_col.min(bar_width.saturating_sub(1));

    // Build spans
    let mut spans: Vec<Span> = Vec::with_capacity(bar_width + 6);
    spans.push(Span::raw("["));
    for (i, (ch, color)) in bar.iter().enumerate() {
        if i == cursor_col {
            spans.push(Span::styled(
                "\u{25b4}",
                Style::default().fg(scheme.accent).bold(),
            )); // ▴ cursor
        } else {
            spans.push(Span::styled(ch.to_string(), Style::default().fg(*color)));
        }
    }
    spans.push(Span::raw("]"));
    spans.push(Span::styled(label, Style::default().fg(scheme.muted)));

    let line = Line::from(spans);
    frame
        .buffer_mut()
        .set_line(area.x, area.y, &line, area.width);
}

/// Write a string into the buffer starting at (x, y), limited to `max_width`.
pub fn render_str(buf: &mut Buffer, x: u16, y: u16, s: &str, max_width: u16, style: Style) {
    let mut cx = x;
    let limit = x + max_width;
    // When the text will not fully fit, reserve the last column for an
    // explicit ellipsis: a silently clipped "4.17.20 → 4.17" reads as a
    // plausible but wrong value, which is worse than visibly truncating.
    let fits = UnicodeWidthStr::width(s) as u16 <= max_width;
    let draw_limit = if fits { limit } else { limit.saturating_sub(1) };
    let mut truncated = false;
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
        if cx + w > draw_limit {
            truncated = true;
            break;
        }
        if let Some(cell) = buf.cell_mut((cx, y)) {
            cell.set_char(ch).set_style(style);
        }
        cx += w;
    }
    if truncated
        && cx < limit
        && let Some(cell) = buf.cell_mut((cx, y))
    {
        cell.set_char('\u{2026}').set_style(style);
    }
}
