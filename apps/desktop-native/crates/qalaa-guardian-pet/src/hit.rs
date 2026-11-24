//! Click-through control. The window covers the sprite (and the popover when
//! open). Over our own pixels it catches the mouse; over the transparent
//! margin it turns hit-testing off so clicks reach the window underneath:
//! `WS_EX_TRANSPARENT` on Windows, `ignoresMouseEvents` on macOS, an empty
//! X11 input shape or Wayland input region on Linux (all via winit).
//!
//! With hit-testing off the window gets no more mouse events, so it is turned
//! back on after a short pause; if the pointer is still over a transparent
//! spot, the next move turns it off again. Only that short timer ever runs.

use crate::geometry::{hit_test, Hit, Rect};
use crate::mood::Millis;

pub const RECHECK_MS: Millis = 250;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitAction {
    /// Leave things as they are.
    None,
    /// Stop catching the mouse, and re-enable at the given time.
    PassThroughUntil(Millis),
    /// Catch the mouse again.
    Catch,
}

#[derive(Debug, Default)]
pub struct HitController {
    passing_through: bool,
}

impl HitController {
    pub fn passing_through(&self) -> bool {
        self.passing_through
    }

    /// The pointer moved to (px, py) in window coordinates.
    pub fn pointer_moved(&mut self, sprite: &Rect, popover: Option<&Rect>, px: f32, py: f32, now: Millis) -> HitAction {
        match hit_test(sprite, popover, px, py) {
            Hit::PassThrough if !self.passing_through => {
                self.passing_through = true;
                HitAction::PassThroughUntil(now + RECHECK_MS)
            }
            Hit::Sprite | Hit::Popover if self.passing_through => {
                self.passing_through = false;
                HitAction::Catch
            }
            _ => HitAction::None,
        }
    }

    /// The re-check timer fired.
    pub fn recheck(&mut self) -> HitAction {
        if self.passing_through {
            self.passing_through = false;
            HitAction::Catch
        } else {
            HitAction::None
        }
    }
}
