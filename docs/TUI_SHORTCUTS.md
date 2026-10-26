# TUI keyboard shortcuts

<!-- markdownlint-disable MD013 -->

Every binding below was read off a handler arm in `src/tui/`. Keys that are
advertised somewhere but have no handler are not listed, and conditional keys
carry their condition. Uppercase and lowercase letters are different bindings
throughout (`k` and `K`, `x` and `X`, `s` and `S`, `p` and `P` all do unrelated
things), and the same letter frequently means different things on different
tabs.

The reason a key can differ per tab is the layered dispatch. In the diff TUI a
key is offered to each layer in order — `Ctrl+C`, then an active text-input
search, then the threshold / view-switcher / deep-dive modals, then the generic
overlay layer (shortcuts, export, legend), then the **active tab's** handler,
then the **active mode's** handler (multi-comparison dashboards), and only then
the global fallback. The first layer that consumes a key ends the dispatch, so a
tab-local binding always wins over a colliding global one: `l` opens the color
legend on most tabs but switches compliance standards on the Compliance tab,
because Compliance consumes it first. The single-SBOM view TUI layers the same
way: `Ctrl+C`, tab-local search input, global search, overlays, focused-panel
handlers, global keys, then per-tab keys.

Press `?` in either app for the in-app overlay. It is context-aware (it knows
the current mode and folds in the active tab's own shortcut list), but treat it
as a convenience rather than an authority: its "Global" rows are not scoped by
tab, and a tab's own `shortcuts()` list is not checked against that tab's
handler — the Graph Changes list still advertises `g/G` "First/Last" even
though only `G` is bound there (see the caveat under "Shortcuts overlay"). This
file is the checked one. Sources of truth, in dispatch order: `src/tui/events/mod.rs`,
`src/tui/events/*.rs` plus `src/tui/view_states/*.rs` (diff tabs),
`src/tui/events/{multi_diff,timeline,matrix}.rs` (multi modes),
`src/tui/view/events.rs` (view app), and `src/tui/views/overlays.rs` (overlays).

## Global keys shared by both apps

| Key | Action | Guard |
| --- | --- | --- |
| `q` | Quit (saves the last active tab) | Any open overlay or modal consumes `q` to close itself instead |
| `?` | Open the shortcuts overlay | Swallowed by the Components quick-filter picker and by full-swallow modals |
| `K` | Open the shortcuts overlay | Diff app only, and not on the Side-by-Side tab, which binds `K` to scrolling |
| `F1` | Open the shortcuts overlay | Diff app only |
| `e` | Export dialog | Every tab, every mode, both apps |
| `l` | Color legend | Diff mode only (never in the multi modes); shadowed on the diff Compliance and Source tabs. View app: all tabs |
| `T` | Cycle theme (dark → light → high-contrast) | No-op and not persisted whenever monochrome was forced at startup — by the `--no-color` flag *or* a non-empty `NO_COLOR`; either one makes monochrome sticky |
| `/` | Search | Opens the global search overlay unless the active tab owns `/` (see per-tab tables) |
| `y` | Copy the selected item to the clipboard | Reports "Nothing selected to copy" only on the tabs that fall through to the global handler. The diff Components and Side-by-Side tabs consume `y` locally and stay **silent** when nothing is selected (Side-by-Side in Grouped mode shows a grouping hint instead); the view app's Source tab answers "Shift+drag to select text, then Cmd/Ctrl+C". `Ctrl+C` always takes the global path, so it always reports |
| `Ctrl+C` | Copy the selected item to the clipboard | Handled before every other layer, so it works with an overlay or search open |
| `b` | Navigate back through breadcrumbs | Requires navigation history. On the diff Dependencies tab `b` toggles the breadcrumb bar instead |
| `Backspace` | Navigate back through breadcrumbs | Requires navigation history |
| `Esc` | Close the topmost overlay / back out one level | See the per-overlay and view-app tables for the exact rung |
| `Tab` | Next tab | Multi modes bind `Tab` to panel switching |
| `Shift-Tab` | Previous tab | Terminals report this as `BackTab`. In the diff app it is gated to diff mode; the multi modes bind it to panel switching |
| `j` / `Down` | Move selection down | Some tabs implement it locally; it is never dead |
| `k` / `Up` | Move selection up | Some tabs implement it locally; it is never dead |
| `PageUp` / `PageDown` | Page the list | |
| `Home` | First item | |
| `End` / `G` | Last item | |
| `g` | First item | Diff app only, and **not on every tab**. Licenses, Vulnerabilities and Compliance bind `g` to grouping and Timeline to jump-to-version; Quality and Side-by-Side bind it to "first item" themselves. The global fallback (`App::select_first`) only has arms for Summary, Components, Vulnerabilities, Licenses and Source, so on **Dependencies and Graph Changes `g` is dead** — those tabs bind `Home` instead (see their per-tab tables). In the view app `g` is always the grouping toggle, never "first item" (use `Home`) |

Two more keys are global in the diff app only. `P` exists in the view app too,
where it means something else entirely (cycle the BOM profile); `D` is not bound
in the view app at all.

| Key | Action | Guard |
| --- | --- | --- |
| `P` | Run the compliance check | Diff mode only; works from any tab |
| `D` | Component deep dive | Resolved from the active tab's selection — see the deep-dive section below |

## Diff TUI

### Tab navigation

Digits always jump tabs, from every tab — no tab shadows them. Tabs `9`/`0`
depend on whether the diff produced graph changes.

| Key | Tab |
| --- | --- |
| `1` | Summary |
| `2` | Components |
| `3` | Dependencies |
| `4` | Licenses |
| `5` | Vulnerabilities |
| `6` | Quality |
| `7` | Compliance |
| `8` | Side-by-Side |
| `9` | Graph Changes when the diff has graph changes, otherwise Source |
| `0` | Source, only when the Graph Changes tab exists |
| `Tab` | Next tab (wraps) |
| `Shift-Tab` | Previous tab (wraps) |

Digit keys are inert in the multi-comparison modes, which have no tab bar.

### Summary tab

Navigation runs through the global list handler; `p` is the only tab-scoped
extra.

| Key | Action |
| --- | --- |
| `j` / `k`, `Up` / `Down` | Scroll the All Changes list |
| `PageUp` / `PageDown` | Page the list |
| `Home` / `g`, `End` / `G` | Jump to start / end |
| `p` | Cycle the policy preset (Summary is the only tab that renders the policy widget) |

### Components tab

| Key | Action | Guard |
| --- | --- | --- |
| `f` | Cycle the change filter | |
| `s` | Cycle the sort order | |
| `v` | Toggle multi-select mode | |
| `Space` | Toggle selection of the current row | Multi-select mode only |
| `A` | Select all | |
| `Ctrl+A` | Select all | |
| `Esc` | Leave multi-select mode | Multi-select mode only; otherwise falls through to the global overlay close |
| `p` | Toggle panel focus | |
| `d` | Jump to the Dependencies tab for the selected component | |
| `Enter` | Open the component deep dive for the selection | Same modal as `D` |
| `Q` | Open the quick-filter picker (below) | |
| `F` | Flag / unflag the selected component for review | |
| `o` | Open the selected component's first CVE in a browser | Reports "No vulnerability to open" when there is none |
| `n` | Cycle the security note on the selected component | Requires the component to be flagged with `F` first |
| `y` | Copy name, id, version and ecosystem of the selection | |
| `j` / `k` | Move the selection (handled by the global list handler) | |

#### Quick-filter picker (`Q`)

A modal that swallows every key that is not listed here — including `q`, which
closes the picker rather than quitting.

| Key | Action |
| --- | --- |
| `1` | Toggle High Risk |
| `2` | Toggle Has Vulns |
| `3` | Toggle Critical |
| `4` | Toggle KEV |
| `5` | Toggle Copyleft |
| `6` | Toggle Flagged |
| `7` | Toggle Stale |
| `8` | Toggle Direct |
| `0` | Clear all quick filters |
| `Esc` / `Q` / `q` | Close the picker |

### Dependencies tab

| Key | Action | Guard |
| --- | --- | --- |
| `/` | Start the tab-local tree search | |
| `n` / `N` | Next / previous search match | Only while a confirmed search query is pinned |
| `Esc` | Clear the pinned search | Only while a query is pinned |
| `t` | Toggle transitive dependencies | This is why `t` does not open the threshold overlay here |
| `h` | Toggle change highlighting | Diff data only |
| `C` | Toggle the cycles display | |
| `f` | Cycle the change filter | |
| `s` | Cycle the sort order | |
| `x` | Expand all nodes | |
| `E` | Collapse all nodes | |
| `b` | Toggle the breadcrumb bar | Shadows the global back-navigation `b`; use `Backspace` to go back |
| `Enter` | Expand / collapse the selected node | |
| `Right` | Expand the selected node | |
| `Left` | Collapse the selected node | |
| `+` / `=` | Increase the depth limit | |
| `-` / `_` | Decrease the depth limit | |
| `>` / `.` | Show more roots | |
| `<` / `,` | Show fewer roots | |
| `c` | Jump to the selected node's component | |
| `Ctrl+D` | Scroll the detail panel down | |
| `Ctrl+U` | Scroll the detail panel up | |
| `j` / `k`, `Up` / `Down` | Move the tree cursor (skips placeholder rows) | |
| `PageUp` / `PageDown`, `Home`, `End` / `G` | Page / jump the tree cursor | |
| `y` | Copy the selected edge (falls through to the global yank) | No copy target on placeholder rows |

While the search input is active: `Esc` cancels, `Enter` confirms, `Backspace`
deletes, `Ctrl+F` toggles filter mode, and every other character is typed into
the query (including `f`, `n` and `N`).

### Licenses tab

| Key | Action | Guard |
| --- | --- | --- |
| `g` | Toggle grouping | |
| `s` | Cycle the sort order | |
| `r` | Cycle the risk filter | |
| `c` | Toggle the compatibility view | |
| `p` | Toggle panel focus | |
| `j` / `k`, `Up` / `Down` | Move the selection | |
| `Enter` | Show the components using the selected license | No-op when the list is empty |

### Vulnerabilities tab

| Key | Action | Guard |
| --- | --- | --- |
| `f` | Cycle the severity filter | |
| `s` | Cycle the sort order | |
| `g` | Toggle grouped-by-component view | |
| `E` | Expand all groups | Grouped view only |
| `C` | Collapse all groups | Grouped view only |
| `Enter` | Flat view: jump to the affected component. Grouped view: toggle the group, or jump from a vulnerability row | |
| `D` | Component deep dive for the selected vulnerability's component | |
| `j` / `k` | Move the selection (handled by the global list handler) | |

### Quality tab

| Key | Action |
| --- | --- |
| `v` | Cycle the view (Summary → Breakdown → Metrics → Recommendations) |
| `j` / `k`, `Up` / `Down` | Move through recommendations |
| `PageUp` / `PageDown` | Scroll five rows |
| `g` / `Home` | First recommendation |
| `G` / `End` | Last recommendation |
| `Enter` | Jump to the tab related to the selected recommendation's category |

### Compliance tab

| Key | Action | Guard |
| --- | --- | --- |
| `h` / `Left` | Previous standard | |
| `l` / `Right` | Next standard | Shadows the global color legend on this tab |
| `j` / `k`, `Up` / `Down` | Move through violations | |
| `Enter` | Flat list: open the violation detail. Grouped: expand / collapse the group | Requires at least one violation |
| `f` | Cycle the severity filter | |
| `g` | Toggle grouping by element | |
| `v` | Cycle the view mode (Overview → New → Resolved → Old SBOM → New SBOM) | |
| `c` | Jump to the component named by the selected violation | Requires a violation; explains itself when the violation has no component |
| `E` | Export the compliance results as JSON | |
| `Home`, `End` / `G`, `PageUp` / `PageDown` | Jump / page through violations | |

The violation detail is a small overlay: `Esc` or `Enter` closes it and every
other key is swallowed while it is open.

### Side-by-Side tab

| Key | Action | Guard |
| --- | --- | --- |
| `a` | Cycle the alignment mode (Aligned / Unified / Grouped) | |
| `p`, `Left`, `Right` | Toggle panel focus | Unified is a single panel and says so instead |
| `j` / `k`, `Up` / `Down` | Scroll / move the row cursor | |
| `J` | Scroll both panels down, or move the cursor down in row-selection modes | |
| `K` | Scroll both panels up, or move the cursor up in row-selection modes. Shadows the global shortcuts overlay on this tab | |
| `PageUp` / `PageDown` | Page | |
| `g` / `Home` | Top | |
| `G` | Bottom | |
| `s` | Cycle the sync mode | |
| `/` | Start the tab-local search | |
| `n` / `N` | Next / previous search match when a search is pinned in Aligned mode, otherwise next / previous change | Grouped mode has no row cursor and shows a hint |
| `]` / `[` | Next / previous change (always change navigation, even with a search pinned) | Grouped mode shows a hint |
| `A` | Toggle added rows | |
| `r` | Toggle removed rows | |
| `m` | Toggle modified rows | |
| `x` | Show all changes again | |
| `Enter` / `Space` | Open the row detail modal | Grouped mode shows a hint |
| `y` | Copy the current row | Grouped mode shows a hint |
| `Esc` | Clear a pinned search, otherwise fall through to the global overlay close | |

Search input: `Esc` cancels, `Enter` confirms, `Backspace` deletes, `Up` / `Down`
and `Ctrl+N` / `Ctrl+P` step through matches, other characters are typed. The
row detail modal closes on `Esc`, `Enter` or `q` and swallows everything else.

### Graph Changes tab

| Key | Action |
| --- | --- |
| `j` / `k`, `Up` / `Down` | Move the selection |
| `PageUp` / `PageDown` | Page |
| `Home`, `End` / `G` | First / last change |
| `Enter` | Confirms that details are already in the right panel (status message) |
| `D` | Component deep dive for the selected change |

### Source tab

Two panels (old / new). Most keys act on the active panel, and mirror to the
other panel when sync is on.

| Key | Action | Guard |
| --- | --- | --- |
| `w` | Switch the active side (old / new) | |
| `s` | Toggle sync between panels | |
| `v` | Toggle tree / raw mode (both panels) | |
| `/` | Start the panel search | |
| `n` / `N` | Next / previous search match, or next / previous change when no query is set | |
| `Enter` / `Space` | Expand / collapse the selected node | Tree mode |
| `Right` / `l` | Expand the node, or scroll right in raw mode. Shadows the global color legend on this tab | |
| `Left` / `h` | Collapse the node, or scroll left in raw mode | |
| `H` | Collapse all | |
| `L` | Expand all | |
| `!` / `@` / `#` | Expand to depth 1 / 2 / 3 | |
| `f` | Cycle the filter type | Tree mode |
| `S` | Cycle the sort order | Tree mode |
| `a` | Toggle panel alignment | Tree mode, and only with change annotations |
| `u` | Toggle collapsing of unchanged regions | Tree mode |
| `C` | Toggle compact mode (both panels) | |
| `I` | Toggle line numbers | |
| `W` | Toggle word wrap | Raw mode |
| `z` | Fold / unfold at the cursor | Raw mode |
| `Z` | Fold all top level, or unfold all | Raw mode |
| `%` | Jump to the matching bracket | Raw mode |
| `\|` | Toggle indent guides | |
| `m` | Toggle a bookmark on the current line | |
| `'` | Next bookmark | |
| `"` | Previous bookmark | |
| `d` | Toggle the detail strip | |
| `]` / `[` | Scroll the detail strip down / up | Only while the detail strip is open |
| `c` | Copy the JSON path of the selection | |
| `E` | Export the active panel's content to a file | |
| `j` / `k` | Move the cursor (handled by the global list handler) | |

## Diff TUI overlays

Overlays run before the tab and mode handlers, so while one is open the keys it
does not bind are simply swallowed — except `Ctrl+C`, which is handled first and
always copies.

### Shortcuts overlay (`?`, `K`, `F1`)

| Key | Action |
| --- | --- |
| `?` / `K` / `F1` | Close (the same keys that opened it) |
| `Esc` / `q` | Close |
| `j` / `Down` | Scroll down |
| `k` / `Up` | Scroll up |

The overlay's content is assembled from the current mode plus the active tab's
own shortcut list, which is the same list that renders the tab's footer. Its
"Global" rows are scoped by mode but not by tab, so on tabs that shadow a global
key (`K` on Side-by-Side, `l` on Compliance and Source) the per-tab tables above
are the accurate ones. The folded-in per-tab list is not validated against the
tab's handler either: `GraphChangesView::shortcuts()` advertises `g/G`
"First/Last" while its `handle_key` binds only `G` and `Home`
(`src/tui/view_states/graph_changes.rs`), so the overlay offers a dead `g` on
that tab. In both cases the per-tab tables above are the accurate ones.

### Export dialog (`e`)

| Key | Action |
| --- | --- |
| `j` | Export JSON |
| `m` | Export Markdown |
| `h` | Export HTML |
| `s` | Export SARIF |
| `c` | Export CSV |
| `e` | Close the dialog |
| `Esc` / `q` | Close the dialog |

On the Compliance tab the export is routed to the compliance exporter. In the
multi-comparison modes only JSON is supported; other picks close the dialog and
report an explanatory "Export failed" status instead of writing a file.

A SARIF export carries no physical location: the TUI does not keep the SBOM
file, so its results name components only logically, and GitHub code scanning
drops them. Produce SARIF for code scanning with the CLI (`sbom-tools validate
… -o sarif`); see [compliance-output.md](compliance-output.md#sarif).

### Color legend (`l`)

Any key closes it, exactly as its footer promises. Diff mode only — it is not
rendered, and cannot be opened, in the multi-comparison modes.

### Threshold tuning (`t`)

Opens on `t` on every diff tab except Dependencies, which binds `t` to the
transitive toggle.

| Key | Action |
| --- | --- |
| `Up` / `k` | Increase the threshold (coarse step) |
| `Down` / `j` | Decrease the threshold (coarse step) |
| `Right` / `l` / `+` / `=` | Increase by a fine step |
| `Left` / `h` / `-` / `_` | Decrease by a fine step |
| `r` | Reset to the original value |
| `Enter` | Apply the threshold and re-diff |
| `Esc` / `q` | Cancel |

### Component deep dive (`D`, or `Enter` on Components)

`D` resolves its target from the active tab's own selection: the Components tab
uses its selected row, Graph Changes and Vulnerabilities use the component of
their selected row, and every other tab reports "Deep dive: select a component
on the Components tab" instead of opening an empty modal.

| Key | Action |
| --- | --- |
| `Tab` / `Right` / `l` | Next section |
| `Shift-Tab` / `Left` / `h` | Previous section |
| `Esc` / `q` | Close |

### View switcher (`V`)

Bound only in the multi-comparison modes; `V` does nothing in diff mode.

| Key | Action |
| --- | --- |
| `j` / `Down` | Next entry |
| `k` / `Up` | Previous entry |
| `Enter` / `Space` | Switch to the highlighted view |
| `1` | Switch to Multi-Diff |
| `2` | Switch to Timeline |
| `3` | Switch to Matrix |
| `Esc` | Close |

### Global search (`/`)

Opened by `/` on tabs that do not own `/` themselves.

| Key | Action |
| --- | --- |
| `Enter` | Jump to the highlighted result |
| `Up` / `Down` | Move through results |
| `Backspace` | Delete a character (search re-runs live) |
| `Ctrl+R` | Toggle substring / regex mode |
| `Esc` | Cancel |
| any character | Append to the query (search re-runs live) |

## Multi-comparison modes (`diff-multi`, `timeline`, `matrix`)

These modes render full-screen dashboards with no tab bar. Consequences for the
global keys: digits are inert, `Tab` and `Shift-Tab` switch panels instead of
tabs, the color legend and the threshold overlay never open (`l` and `t` are
rebound per mode — chart scroll and statistics in Timeline, cell movement and
the similarity threshold in Matrix), and `V` — dead in diff mode — opens the
view switcher here. `q`, `?`/`K`, `e`, `T`, `y`/`Ctrl+C` and `/` behave as
everywhere else.

### Shared across the three modes

| Key | Action |
| --- | --- |
| `Tab` / `Shift-Tab` / `p` | Switch panel |
| `j` / `k`, `Up` / `Down` | Move the selection |
| `/` | Start the search |
| `n` / `N` | Next / previous search match (only once a search has been confirmed with `Enter`) |
| `s` | Cycle the sort field |
| `V` | View switcher |

Search input in all three: `Enter` confirms, `Esc` cancels, `Backspace` deletes,
`Up` / `Down` preview matches live, `Ctrl+R` toggles regex, other characters type.

### Multi-diff

| Key | Action |
| --- | --- |
| `f` | Cycle the filter preset (re-syncs the selection and search matches) |
| `s` | Cycle the sort field |
| `S` | Toggle the sort direction |
| `Enter` / `Space` | Open the comparison detail modal |
| `v` | Open the variable-components drill-down |
| `x` | Toggle cross-target analysis |
| `h` | Toggle heat-map mode |
| `D` | Component deep dive for the selected variable component |

Detail modal: `Esc` / `q` closes, everything else is swallowed. Variable-components
drill-down: `j` / `k` move, `Esc` / `q` closes, everything else is swallowed.

### Timeline

| Key | Action |
| --- | --- |
| `d` | Open the version-diff modal |
| `t` | Toggle the statistics panel |
| `g` | Enter jump-to-version mode |
| `f` | Filter components (re-syncs the selection) |
| `s` | Cycle the sort field |
| `S` | Toggle the sort direction |
| `m` | Cycle the chart metric |
| `+` / `=` | Zoom the chart in |
| `-` / `_` | Zoom the chart out |
| `h` / `Left` | Scroll the chart left |
| `l` / `Right` | Scroll the chart right |
| `Enter` / `Space` | Open the component-history modal |
| `D` | Component deep dive for the selected component |

`Enter` reports "No components match the current filter" rather than opening an
empty modal. Jump mode: type digits, `Enter` jumps (invalid input is rejected
with a status), `Backspace` deletes, `Esc` cancels. Version-diff modal: `h` / `Left`
and `l` / `Right` move the comparison version, `Esc` / `q` closes. Component-history
modal: `Esc` / `q` closes; both modals swallow everything else.

### Matrix

| Key | Action |
| --- | --- |
| `h` / `Left`, `l` / `Right` | Move the cell cursor |
| `t` | Cycle the similarity threshold |
| `z` | Toggle focus mode |
| `r` | Focus the current row |
| `c` | Focus the current column |
| `Esc` | Clear the focus |
| `H` | Toggle row/column highlighting |
| `Enter` / `d` | Open the pair diff for the selected cell |
| `x` | Open the export-options modal |
| `C` | Open the clustering details |
| `S` | Toggle the sort direction |
| `D` | Reports "Deep dive applies to components — press Enter for pair diff" (deliberately not a modal: matrix rows are SBOMs) |

`Enter` on the diagonal reports "Cannot diff same SBOM". Pair-diff modal:
`j` / `k` scroll, `Esc` / `q` closes. Export-options modal: `c` CSV, `j` JSON,
`h` HTML, `Esc` / `q` closes. Clustering details: `j` / `k` move, `Esc` / `q`
closes. All three swallow every other key.

## View TUI (single SBOM / CBOM / AI-BOM)

### Tab sets per profile

`P` cycles the profile (SBOM → CBOM → AI-BOM) and resets to the Overview tab.
Digits select positionally within the active profile's tab set, so the same
digit means a different tab under a different profile.

| Digit | SBOM | CBOM | AI-BOM |
| --- | --- | --- | --- |
| `1` | Overview | Overview | Overview |
| `2` | Tree | Algorithms | Models |
| `3` | Dependencies | Certificates | Datasets |
| `4` | Licenses | Keys | AI Readiness |
| `5` | Vulnerabilities | Protocols | Compliance |
| `6` | Quality | Quality | Source |
| `7` | Compliance | PQC Compliance | — |
| `8` | Source | Source | — |

`Tab` and `Shift-Tab` cycle within the same set.

### View-app global keys

| Key | Action | Guard |
| --- | --- | --- |
| `q` | Quit (saves the last active tab) | |
| `?` | Toggle the help overlay | `K` closes it but does not open it — `K` is a tab binding here |
| `e` | Export dialog | Every tab |
| `l` | Color legend | Every tab; this is why `l` does not expand tree nodes in this app |
| `T` | Cycle theme | |
| `P` | Cycle the BOM profile and re-score | Resets to Overview |
| `/` | Search — tab-local on Source, Tree, Vulnerabilities and Dependencies; global overlay elsewhere | |
| `y`, `Ctrl+C` | Copy the selection | |
| `b` / `Backspace` | Navigate back | Requires history |
| `Esc` | Back out one rung: clear an applied tree search, else clear the Vulnerabilities KEV filter, else clear the severity filter, else return focus to the left panel, else navigate back | |
| `j` / `k`, `Up` / `Down`, `PageUp` / `PageDown`, `Home`, `End` / `G` | List navigation | `j` / `k` are never shadowed by a tab |

### Per-tab keys

| Key | Tab | Action |
| --- | --- | --- |
| `g` | Tree, Vulnerabilities, Licenses, Compliance | Toggle grouping |
| `f` | Tree, Vulnerabilities, Compliance, Source (tree mode) | Cycle the filter |
| `s` | Vulnerabilities, Algorithms | Cycle the sort order |
| `d` | Vulnerabilities | Toggle deduplication |
| `K` | Vulnerabilities | Toggle the KEV-only filter |
| `K` / `J` | Licenses, Dependencies, Compliance, Models, Datasets | Scroll the detail panel up / down |
| `E` | Vulnerabilities | Expand all groups (including sub-groups) |
| `C` | Vulnerabilities | Collapse all groups |
| `}` / `{` | Vulnerabilities | Jump to the next / previous group header |
| `i` | Vulnerabilities | Inspect: jump to the affected component in the Tree tab |
| `n` | Vulnerabilities | Cycle to the next affected component (multi-component vulnerabilities) |
| `p` | Vulnerabilities | Cycle to the previous affected component, or toggle panel focus when the vulnerability has a single component |
| `p` | all other tabs | Toggle panel focus |
| `x` | Dependencies | Expand all nodes |
| `X` | Dependencies | Collapse all nodes |
| `c` | Dependencies | Jump to the selected dependency's component in the Tree tab |
| `S` | Tree, Vulnerabilities, Dependencies | Jump to the selected entity in the Source tab (reports "Reference not found in source" on a miss) |
| `E` | Compliance | Export the compliance results as JSON |
| `Left` / `h` | Compliance | Previous standard |
| `Right` | Compliance | Next standard (`l` is the color legend in this app) |
| `Left` / `h` | Tree, Dependencies | Collapse the selected node |
| `Right` | Tree, Dependencies | Expand the selected node |
| `v` | Quality | Cycle the quality view |
| `m` | Tree, Source | Toggle a bookmark |
| `Enter` | Tree | Expand a group, or select a component and focus the detail panel |
| `Enter` | Vulnerabilities | Toggle a group header, or jump to the affected component |
| `Enter` | Licenses | Jump to the first component using the license |
| `Enter` | Dependencies | Expand the node, or jump to the component for a leaf |
| `Enter` | Compliance | Toggle the violation detail overlay (requires violations) |
| `Enter` | Quality | Jump from the Summary view to Recommendations |
| `Enter` | Source | Follow the reference under the cursor, or expand / collapse the node |

### Source tab (view app)

| Key | Action | Guard |
| --- | --- | --- |
| `v` | Toggle tree / raw mode | |
| `w` | Toggle panel focus (JSON / map) | |
| `Space` | Expand / collapse the node | Tree mode |
| `Left` / `h` | Collapse the node, or scroll left | Raw mode scrolls |
| `Right` | Expand the node, or scroll right | Raw mode scrolls |
| `H` | Collapse all | |
| `L` | Expand all | |
| `!` / `@` / `#` | Expand to depth 1 / 2 / 3 | |
| `n` / `N` | Next / previous search match | |
| `I` | Toggle line numbers | |
| `W` | Toggle word wrap | Raw mode |
| `z` | Fold / unfold at the cursor | Raw mode |
| `Z` | Fold all top level, or unfold all | Raw mode |
| `%` | Jump to the matching bracket | Raw mode |
| `\|` | Toggle indent guides | |
| `'` | Next bookmark | |
| `S` | Cycle the sort order | Tree mode |
| `c` | Copy the JSON path | |
| `E` | Export the source content to a file | |

### Focused detail panels

Some keys change meaning when the right-hand panel has focus (`p`, or `w` on
Source).

| Key | Context | Action |
| --- | --- | --- |
| `1` / `2` / `3` / `4` | Tree, right panel, component selected | Select the Overview / Identifiers / Vulnerabilities / Dependencies detail tab |
| `!` / `@` / `#` / `$` | Tree, right panel, component selected | Same four detail tabs |
| `[` / `]` | Tree, right panel, component selected | Previous / next detail tab |
| `j` / `k` | Tree, right panel, component selected | Scroll the detail panel |
| `j` / `k` | Vulnerabilities, right panel | Scroll the detail panel |
| `p` | Vulnerabilities / Source, right panel | Return focus to the left panel |
| `j` / `k` | Source, map panel | Move through the map |
| `Enter` / `Space` | Source, map panel | Jump to the selected map entry |
| `t` | Source, map panel | Jump to the Tree tab for the component in the context footer |
| `u` | Source, map panel | Jump to the Vulnerabilities tab for the component in the context footer |

### View-app overlays

| Overlay | Open | Keys | Close |
| --- | --- | --- | --- |
| Help | `?` | `j` / `k` or `Up` / `Down` scroll | `?`, `K`, `Esc`, `q` |
| Export | `e` | `j` JSON, `s` SARIF, `m` Markdown, `h` HTML, `c` CSV | `e`, `Esc`, `q` |
| Legend | `l` | — | any key |
| Search | `/` | `Enter` jump, `Up` / `Down` move, `Backspace`, `Ctrl+R` regex toggle, characters type | `Esc` |
| Compliance detail | `Enter` on Compliance | swallows every other key | `Esc`, `q` |

Tab-local searches (Source, Tree, Vulnerabilities, Dependencies) take `Enter` to
confirm, `Esc` to cancel, `Backspace` to delete and characters to type; the
Source search additionally toggles regex with `Ctrl+R`.

## Recently changed bindings

If you have muscle memory from an older build, these moved:

| Was | Now | Where |
| --- | --- | --- |
| Digits toggled Components security quick filters | Digits always jump tabs; the quick filters live behind the `Q` picker modal | Diff, Components |
| Digits toggled Side-by-Side change filters | `A` added, `r` removed, `m` modified, `x` show all | Diff, Side-by-Side |
| `k` toggled the KEV filter | `K` (uppercase); lowercase `k` stays pure navigation | View, Vulnerabilities |
| `Tab` / `Shift-Tab` jumped vulnerability groups | `}` / `{`; `Tab` always switches app tabs | View, Vulnerabilities |
| `e` folded all dependency nodes | `x` / `X` expand / collapse all in the view app, `x` / `E` in the diff app; `e` is the export dialog everywhere | Both apps, Dependencies |
| `y` toggled the cycles display | `C`; `y` is the copy key everywhere | Diff, Dependencies |
| The threshold overlay had no key | `t` on every diff tab except Dependencies | Diff |
| `D` opened a hollow deep-dive modal in Matrix | `D` is disabled there and explains why; use `Enter` for the pair diff | Matrix |
