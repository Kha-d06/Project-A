//! What this desktop can do for an overlay, decided before any window opens.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    Other,
}

impl Os {
    pub fn current() -> Self {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPlan {
    /// Run under XWayland (by hiding WAYLAND_DISPLAY from winit).
    pub use_xwayland: bool,
    /// The window can float above others.
    pub always_on_top: bool,
    /// Clicks can pass through transparent parts.
    pub click_through: bool,
    /// Shown in the pet's settings when something doesn't work here; never hidden.
    pub note: Option<&'static str>,
}

/// Decides how to open the overlay from the OS and the session's environment.
///
/// Wayland's standard window protocol has no "always on top" and no way to
/// position a window, and only some compositors (KDE, wlroots) offer
/// layer-shell. The pet therefore runs through XWayland when it is there,
/// where always-on-top and input shapes work on GNOME, KDE and wlroots alike.
/// Without XWayland it opens as a normal window and says so.
pub fn plan(os: Os, env: &dyn Fn(&str) -> Option<String>) -> OverlayPlan {
    match os {
        Os::Windows | Os::MacOs => OverlayPlan {
            use_xwayland: false,
            always_on_top: true,
            click_through: true,
            note: None,
        },
        Os::Linux => {
            let wayland = env("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
                || env("XDG_SESSION_TYPE").is_some_and(|v| v.eq_ignore_ascii_case("wayland"));
            let x11 = env("DISPLAY").is_some_and(|v| !v.is_empty());
            match (wayland, x11) {
                (true, true) => OverlayPlan { use_xwayland: true, always_on_top: true, click_through: true, note: None },
                (true, false) => OverlayPlan {
                    use_xwayland: false,
                    always_on_top: false,
                    click_through: true,
                    note: Some("This Wayland session has no XWayland, so the Guardian opens as a normal window: it can't stay above other windows or sit at the screen edge."),
                },
                _ => OverlayPlan { use_xwayland: false, always_on_top: true, click_through: true, note: None },
            }
        }
        Os::Other => OverlayPlan {
            use_xwayland: false,
            always_on_top: false,
            click_through: false,
            note: Some("The Guardian isn't supported on this system."),
        },
    }
}
