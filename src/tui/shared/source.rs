//! Shared source rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! Provides interactive JSON tree rendering and raw text rendering for the Source tab.

use crate::tui::app_states::source::{
    JsonTreeNode, JsonValueType, SourcePanelState, SourceViewMode,
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
    pub is_last_sibling: bool,
    pub ancestors_last: Vec<bool>,
}

/// Flatten the JSON tree into a list respecting expand/collapse state.
pub fn flatten_json_tree(
    node: &JsonTreeNode,
    parent_path: &str,
    depth: usize,
    expanded: &std::collections::HashSet<String>,
    items: &mut Vec<FlatJsonItem>,
    is_last_sibling: bool,
    ancestors_last: &[bool],
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

    items.push(FlatJsonItem {
        node_id: node_id.clone(),
        depth,
        display_key: node.display_key(),
        value_preview,
        value_type,
        is_expandable: node.is_expandable(),
        is_expanded,
        child_count_label: node.child_count_label(),
        is_last_sibling,
        ancestors_last: ancestors_last.to_vec(),
    });

    if is_expanded && let Some(children) = node.children() {
        let mut current_ancestors = ancestors_last.to_vec();
        current_ancestors.push(is_last_sibling);
        for (i, child) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            flatten_json_tree(
                child,
                &node_id,
                depth + 1,
                expanded,
                items,
                child_is_last,
                &current_ancestors,
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
        scheme.accent
    } else {
        scheme.border
    };

    let mode_hint = if state.json_tree.is_some() {
        " 'v':Raw "
    } else {
        ""
    };
    let node_info = if state.total_node_count > 0 {
        format!(" ({} nodes)", state.total_node_count)
    } else {
        String::new()
    };
    let block = Block::default()
        .title(format!(" {title} [Tree]{node_info}{mode_hint}"))
        .title_style(Style::default().fg(border_color).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    if state.json_tree.is_none() {
        let msg = ratatui::widgets::Paragraph::new(
            "Content is not valid JSON. Press 'v' for raw text view.",
        )
        .style(Style::default().fg(scheme.text_muted));
        frame.render_widget(msg, inner);
        return;
    }

    // Use cached flat items (rebuilt only on expand/collapse changes)
    state.ensure_flat_cache();
    let item_count = state.cached_flat_items.len();
    state.visible_count = item_count;

    // Clamp selection
    if state.selected >= item_count && item_count > 0 {
        state.selected = item_count - 1;
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
                let trimmed =
                    &breadcrumb[breadcrumb.len().saturating_sub(bc_width.saturating_sub(3))..];
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

    // Scroll adjustment
    let visible_height = inner.height as usize;
    if visible_height > 0 {
        if state.selected >= state.scroll_offset + visible_height {
            state.scroll_offset = state.selected.saturating_sub(visible_height - 1);
        } else if state.selected < state.scroll_offset {
            state.scroll_offset = state.selected;
        }
    }

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

        let mut x = inner.x;

        // Selection indicator
        let sel_str = if is_selected { "> " } else { "  " };
        render_str(
            frame.buffer_mut(),
            x,
            y,
            sel_str,
            inner.width,
            Style::default().fg(scheme.accent).bold(),
        );
        x += 2;

        // Tree connector lines
        if item.depth > 0 {
            let connector_style = Style::default().fg(scheme.muted);
            // Draw ancestor continuation lines
            for d in 0..item.depth - 1 {
                let is_ancestor_last = item.ancestors_last.get(d + 1).copied().unwrap_or(false);
                let connector = if is_ancestor_last { "   " } else { "│  " };
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    connector,
                    inner.width.saturating_sub(x - inner.x),
                    connector_style,
                );
                x += 3;
            }
            // Draw branch connector for this node
            let branch = if item.is_last_sibling {
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
            x += 3;
        }

        // Expand/collapse indicator
        if item.is_expandable {
            let indicator = if item.is_expanded { "▼ " } else { "▶ " };
            render_str(
                frame.buffer_mut(),
                x,
                y,
                indicator,
                inner.width.saturating_sub(x - inner.x),
                Style::default().fg(scheme.accent),
            );
            x += 2;
        }

        let remaining = inner.x + inner.width;

        // Key name
        if !item.display_key.is_empty() && x < remaining {
            let key_style = Style::default().fg(scheme.primary);
            let max_w = (remaining - x) as usize;
            let key_width = UnicodeWidthStr::width(item.display_key.as_str());
            let display_key = if key_width > max_w {
                &item.display_key[..max_w.min(item.display_key.len())]
            } else {
                &item.display_key
            };
            render_str(
                frame.buffer_mut(),
                x,
                y,
                display_key,
                remaining - x,
                key_style,
            );
            x += UnicodeWidthStr::width(display_key) as u16;

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

        // Value or child count
        if x < remaining {
            let max_w = (remaining - x) as usize;
            if item.is_expandable {
                let label = &item.child_count_label;
                let display = if label.len() > max_w {
                    &label[..max_w]
                } else {
                    label.as_str()
                };
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    display,
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
                let display_val = if item.value_preview.len() > max_w {
                    format!("{}...", &item.value_preview[..max_w.saturating_sub(3)])
                } else {
                    item.value_preview.clone()
                };
                render_str(
                    frame.buffer_mut(),
                    x,
                    y,
                    &display_val,
                    remaining - x,
                    val_style,
                );
            }
        }

        // Highlight selected row background
        if is_selected {
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                }
            }
        }

        // Search match highlighting
        if !state.search_matches.is_empty() && state.search_matches.binary_search(&abs_idx).is_ok()
        {
            let is_current = state.search_matches.get(state.search_current) == Some(&abs_idx);
            let bg = if is_current {
                scheme.search_highlight_bg
            } else {
                scheme.highlight
            };
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(bg);
                }
            }
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

/// Render the raw text view with line numbers.
fn render_source_raw(
    frame: &mut Frame,
    area: Rect,
    state: &mut SourcePanelState,
    title: &str,
    is_focused: bool,
) {
    let scheme = colors();
    let border_color = if is_focused {
        scheme.accent
    } else {
        scheme.border
    };

    let has_tree = state.json_tree.is_some();
    let mode_hint = if has_tree { " 'v':Tree " } else { "" };
    let block = Block::default()
        .title(format!(
            " {} [Raw] ({} lines){} ",
            title,
            state.raw_lines.len(),
            mode_hint
        ))
        .title_style(Style::default().fg(border_color).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    state.visible_count = state.raw_lines.len();

    // Clamp selection
    if state.selected >= state.raw_lines.len() && !state.raw_lines.is_empty() {
        state.selected = state.raw_lines.len() - 1;
    }

    let visible_height = inner.height as usize;

    // Scroll adjustment
    if visible_height > 0 {
        if state.selected >= state.scroll_offset + visible_height {
            state.scroll_offset = state.selected.saturating_sub(visible_height - 1);
        } else if state.selected < state.scroll_offset {
            state.scroll_offset = state.selected;
        }
    }

    let gutter_width = if state.raw_lines.is_empty() {
        1
    } else {
        format!("{}", state.raw_lines.len()).len()
    };

    let remaining = inner.x + inner.width;

    for (i, line) in state
        .raw_lines
        .iter()
        .skip(state.scroll_offset)
        .take(visible_height)
        .enumerate()
    {
        let y = inner.y + i as u16;
        let line_num = state.scroll_offset + i + 1;
        let is_selected = state.scroll_offset + i == state.selected;

        // Line number gutter
        let num_str = format!("{line_num:>gutter_width$} │ ");
        render_str(
            frame.buffer_mut(),
            inner.x,
            y,
            &num_str,
            remaining - inner.x,
            Style::default().fg(scheme.text_muted),
        );

        let content_x = inner.x + num_str.len() as u16;
        if content_x < remaining {
            let max_w = remaining - content_x;
            if has_tree {
                render_json_line_highlighted(
                    frame.buffer_mut(),
                    content_x,
                    y,
                    line,
                    max_w,
                    &scheme,
                );
            } else {
                let display_line = if line.len() > max_w as usize {
                    &line[..max_w as usize]
                } else {
                    line.as_str()
                };
                render_str(
                    frame.buffer_mut(),
                    content_x,
                    y,
                    display_line,
                    max_w,
                    Style::default().fg(scheme.text),
                );
            }
        }

        // Highlight selected row
        if is_selected {
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                }
            }
        }

        // Search match highlighting
        let abs_idx = state.scroll_offset + i;
        if !state.search_matches.is_empty() && state.search_matches.binary_search(&abs_idx).is_ok()
        {
            let is_current = state.search_matches.get(state.search_current) == Some(&abs_idx);
            let bg = if is_current {
                scheme.search_highlight_bg
            } else {
                scheme.highlight
            };
            for col in inner.x..remaining {
                if let Some(cell) = frame.buffer_mut().cell_mut((col, y)) {
                    cell.set_bg(bg);
                }
            }
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

    let search_text = format!("/{}{}{}", state.search_query, cursor, match_info);
    render_str(
        frame.buffer_mut(),
        inner.x,
        search_y,
        &search_text,
        inner.width,
        Style::default().fg(scheme.accent),
    );
}

/// Build a breadcrumb string from a node ID path.
fn breadcrumb_from_node_id(node_id: &str) -> String {
    if node_id.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = node_id.split('.').collect();
    parts.join(" > ")
}

/// Write a string into the buffer starting at (x, y), limited to `max_width`.
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
