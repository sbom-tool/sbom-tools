//! Graph Changes state types.

pub struct GraphChangesState {
    pub selected: usize,
    pub total: usize,
    pub scroll_offset: usize,
}

impl GraphChangesState {
    pub fn new() -> Self {
        Self {
            selected: 0,
            total: 0,
            scroll_offset: 0,
        }
    }

    pub fn select_next(&mut self) {
        if self.total > 0 && self.selected < self.total - 1 {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn page_down(&mut self) {
        let page_size = 10;
        self.selected = (self.selected + page_size).min(self.total.saturating_sub(1));
    }

    pub fn page_up(&mut self) {
        let page_size = 10;
        self.selected = self.selected.saturating_sub(page_size);
    }

    pub fn set_total(&mut self, total: usize) {
        self.total = total;
        // Clamp selection if out of bounds
        if self.total > 0 && self.selected >= self.total {
            self.selected = self.total - 1;
        }
    }
}

impl Default for GraphChangesState {
    fn default() -> Self {
        Self::new()
    }
}

