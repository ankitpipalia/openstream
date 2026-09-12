#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    OpenUi,
    QuitUi,
    StopHosting,
    Disconnect,
    CheckForUpdates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrayModel {
    ui_visible: bool,
    hosting_enabled: bool,
    hosting_ready: bool,
    active_guest: bool,
}

impl TrayModel {
    pub const fn hosting_ready() -> Self {
        Self {
            ui_visible: true,
            hosting_enabled: true,
            hosting_ready: true,
            active_guest: false,
        }
    }

    pub const fn ui_visible(self) -> bool {
        self.ui_visible
    }

    pub const fn hosting_continues(self) -> bool {
        self.hosting_enabled && self.hosting_ready
    }

    pub const fn has_active_guest(self) -> bool {
        self.active_guest
    }

    pub const fn set_active_guest(&mut self, active: bool) {
        self.active_guest = active;
    }

    /// Dispatch a user action and return whether it produced a state change.
    /// UI lifetime and host lifetime are intentionally separate: the tray is
    /// allowed to outlive the window and the host agent is never stopped by
    /// `QuitUi`.
    pub const fn dispatch(&mut self, command: TrayCommand) -> bool {
        match command {
            TrayCommand::OpenUi => {
                let changed = !self.ui_visible;
                self.ui_visible = true;
                changed
            }
            TrayCommand::QuitUi => {
                let changed = self.ui_visible;
                self.ui_visible = false;
                changed
            }
            TrayCommand::StopHosting => {
                let changed = self.hosting_enabled || self.hosting_ready;
                self.hosting_enabled = false;
                self.hosting_ready = false;
                changed
            }
            TrayCommand::Disconnect => {
                let changed = self.active_guest;
                self.active_guest = false;
                changed
            }
            TrayCommand::CheckForUpdates => false,
        }
    }
}

fn main() {
    // The native menu adapters are platform work; this binary keeps the
    // lifecycle contract usable by them without making the tray load-bearing.
    println!("lowlat-tray: lifecycle model ready");
}

#[cfg(test)]
mod tests {
    use super::{TrayCommand, TrayModel};

    #[test]
    fn quitting_ui_does_not_stop_background_hosting() {
        let mut model = TrayModel::hosting_ready();
        model.dispatch(TrayCommand::QuitUi);
        assert!(model.hosting_continues());
        assert!(!model.ui_visible());
    }

    #[test]
    fn stop_hosting_is_distinct_from_quitting_ui() {
        let mut model = TrayModel::hosting_ready();
        model.dispatch(TrayCommand::StopHosting);
        assert!(!model.hosting_continues());
        assert!(model.ui_visible());
    }

    #[test]
    fn disconnect_requires_an_active_guest() {
        let mut model = TrayModel::hosting_ready();
        assert!(!model.dispatch(TrayCommand::Disconnect));
        model.set_active_guest(true);
        assert!(model.dispatch(TrayCommand::Disconnect));
        assert!(!model.has_active_guest());
    }
}
