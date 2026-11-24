//! Window geometry in logical pixels: where clicks land, where the popover
//! goes, and where the pet rests on screen. Pure functions, tested headless.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Rect {
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w, h }
    }

    pub fn contains(&self, px: f32, py: f32) -> bool {
        px >= self.x && py >= self.y && px < self.x + self.w && py < self.y + self.h
    }

    pub fn right(&self) -> f32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> f32 {
        self.y + self.h
    }

    /// The smallest rectangle holding both.
    pub fn union(&self, other: &Rect) -> Rect {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        Rect::new(x, y, self.right().max(other.right()) - x, self.bottom().max(other.bottom()) - y)
    }
}

/// The sprite's clickable body: an ellipse inside its square, so the
/// transparent corners pass clicks through to whatever is underneath.
pub fn in_sprite(sprite: &Rect, px: f32, py: f32) -> bool {
    if !sprite.contains(px, py) {
        return false;
    }
    let (rx, ry) = (sprite.w / 2.0, sprite.h / 2.0);
    let (dx, dy) = (px - (sprite.x + rx), py - (sprite.y + ry));
    (dx * dx) / (rx * rx) + (dy * dy) / (ry * ry) <= 1.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Sprite,
    Popover,
    /// Nothing of ours here: the click belongs to the window underneath.
    PassThrough,
}

pub fn hit_test(sprite: &Rect, popover: Option<&Rect>, px: f32, py: f32) -> Hit {
    if popover.is_some_and(|p| p.contains(px, py)) {
        Hit::Popover
    } else if in_sprite(sprite, px, py) {
        Hit::Sprite
    } else {
        Hit::PassThrough
    }
}

const GAP: f32 = 8.0;

/// Places the popover next to the sprite, fully inside `screen`: above it when
/// there is room, otherwise below, otherwise beside; then nudged inside.
pub fn place_popover(sprite: &Rect, size: (f32, f32), screen: &Rect) -> Rect {
    let (w, h) = (size.0.min(screen.w), size.1.min(screen.h));
    let centred_x = sprite.x + sprite.w / 2.0 - w / 2.0;
    let above = Rect::new(centred_x, sprite.y - GAP - h, w, h);
    let below = Rect::new(centred_x, sprite.bottom() + GAP, w, h);
    let left = Rect::new(sprite.x - GAP - w, sprite.y + sprite.h / 2.0 - h / 2.0, w, h);
    let right = Rect::new(sprite.right() + GAP, sprite.y + sprite.h / 2.0 - h / 2.0, w, h);
    let fits_v = |r: &Rect| r.y >= screen.y && r.bottom() <= screen.bottom();
    let fits_h = |r: &Rect| r.x >= screen.x && r.right() <= screen.right();
    let chosen = if fits_v(&above) {
        above
    } else if fits_v(&below) {
        below
    } else if fits_h(&left) {
        left
    } else {
        right
    };
    clamp_into(&chosen, screen)
}

pub fn clamp_into(r: &Rect, screen: &Rect) -> Rect {
    let x = r.x.clamp(screen.x, (screen.right() - r.w).max(screen.x));
    let y = r.y.clamp(screen.y, (screen.bottom() - r.h).max(screen.y));
    Rect::new(x, y, r.w, r.h)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corner {
    BottomRight,
    BottomLeft,
}

/// The resting place: a corner of the monitor's work area, just above the
/// taskbar or dock. Without a reported work area, a 48 px band is left at the
/// bottom for one.
pub fn rest_position(sprite_size: (f32, f32), work_area: &Rect, corner: Corner) -> (f32, f32) {
    let margin = 16.0;
    let y = work_area.bottom() - sprite_size.1 - margin;
    let x = match corner {
        Corner::BottomRight => work_area.right() - sprite_size.0 - margin,
        Corner::BottomLeft => work_area.x + margin,
    };
    (x.max(work_area.x), y.max(work_area.y))
}

/// A monitor's area minus a band for the taskbar, when the OS doesn't say.
pub fn assumed_work_area(monitor: &Rect) -> Rect {
    Rect::new(monitor.x, monitor.y, monitor.w, (monitor.h - 48.0).max(0.0))
}

/// Snaps a dragged pet to the nearest horizontal edge of the work area when it
/// is dropped within `reach` pixels of it.
pub fn snap_x(x: f32, width: f32, work_area: &Rect, reach: f32) -> f32 {
    if x - work_area.x <= reach {
        work_area.x
    } else if work_area.right() - (x + width) <= reach {
        work_area.right() - width
    } else {
        x
    }
}

/// Which monitor holds a point; the first one when none does.
pub fn monitor_for(monitors: &[Rect], px: f32, py: f32) -> Option<usize> {
    if monitors.is_empty() {
        return None;
    }
    Some(monitors.iter().position(|m| m.contains(px, py)).unwrap_or(0))
}
