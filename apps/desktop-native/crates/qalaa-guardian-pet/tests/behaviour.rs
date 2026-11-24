//! Headless tests of everything that decides the Guardian's behaviour.

use qalaa_guardian_pet::geometry::{
    assumed_work_area, clamp_into, hit_test, in_sprite, monitor_for, place_popover, rest_position, snap_x, Corner, Hit, Rect,
};
use qalaa_guardian_pet::hit::{HitAction, HitController, RECHECK_MS};
use qalaa_guardian_pet::mood::{Input, Mood, Pet, Timing};
use qalaa_guardian_pet::platform::{plan, Os};

const T: Timing = Timing {
    defend_ms: 6_000,
    happy_ms: 3_000,
    patrol_every_ms: 120_000,
    patrol_ms: 6_000,
    sleep_after_ms: 300_000,
};

#[test]
fn idle_patrols_then_sleeps_and_wakes_on_activity() {
    let mut pet = Pet::new(0, T);
    assert_eq!(pet.mood(), Mood::Idle);
    assert_eq!(pet.next_deadline(), Some(120_000));
    pet.handle(Input::Tick, 120_000);
    assert_eq!(pet.mood(), Mood::Patrol);
    assert_eq!(pet.next_deadline(), Some(126_000));
    pet.handle(Input::Tick, 126_000);
    assert_eq!(pet.mood(), Mood::Idle);
    // Next patrol would be at 246 s, but five idle minutes come first.
    assert_eq!(pet.next_deadline(), Some(246_000).min(Some(300_000)));
    pet.handle(Input::Tick, 246_000);
    assert_eq!(pet.mood(), Mood::Patrol);
    pet.handle(Input::Tick, 252_000);
    pet.handle(Input::Tick, 300_000);
    assert_eq!(pet.mood(), Mood::Sleep);
    // Asleep, nothing is scheduled: the window uses no timer at all.
    assert_eq!(pet.next_deadline(), None);
    pet.handle(Input::Activity, 400_000);
    assert_eq!(pet.mood(), Mood::Idle);
}

#[test]
fn scan_then_happy_then_back_to_idle() {
    let mut pet = Pet::new(0, T);
    pet.handle(Input::ScanStarted, 1_000);
    assert_eq!(pet.mood(), Mood::Scan);
    assert_eq!(pet.next_deadline(), None);
    pet.handle(Input::ScanFinished { threats: 0 }, 9_000);
    assert_eq!(pet.mood(), Mood::Happy);
    pet.handle(Input::Tick, 12_000);
    assert_eq!(pet.mood(), Mood::Idle);
}

#[test]
fn threats_alert_until_clicked_and_outrank_everything() {
    let mut pet = Pet::new(0, T);
    pet.handle(Input::ScanStarted, 0);
    pet.handle(Input::ScanFinished { threats: 2 }, 5_000);
    assert_eq!(pet.mood(), Mood::Alert);
    // A blocked threat or a new scan doesn't hide an unanswered alert.
    pet.handle(Input::ThreatBlocked, 6_000);
    pet.handle(Input::ScanStarted, 7_000);
    assert_eq!(pet.mood(), Mood::Alert);
    pet.handle(Input::Tick, 60_000);
    assert_eq!(pet.mood(), Mood::Alert, "alerts don't time out");
    pet.handle(Input::Clicked, 61_000);
    assert_eq!(pet.mood(), Mood::Scan, "acknowledged: back to the scan still running");
}

#[test]
fn defend_shows_then_turns_happy() {
    let mut pet = Pet::new(0, T);
    pet.handle(Input::ThreatBlocked, 1_000);
    assert_eq!(pet.mood(), Mood::Defend);
    pet.handle(Input::ScanFinished { threats: 0 }, 2_000);
    assert_eq!(pet.mood(), Mood::Defend, "a quiet scan result doesn't cut the defend pose short");
    pet.handle(Input::Tick, 7_000);
    assert_eq!(pet.mood(), Mood::Happy);
}

#[test]
fn snooze_hides_but_alerts_still_show() {
    let mut pet = Pet::new(0, T);
    pet.handle(Input::Snooze { minutes: 120 }, 0);
    assert!(!pet.visible(1_000));
    assert!(pet.next_deadline().is_some_and(|d| d <= 7_200_000));
    pet.handle(Input::Alert, 2_000);
    assert!(pet.visible(2_000), "an alert is never snoozed away");
    pet.handle(Input::Clicked, 3_000);
    assert!(!pet.visible(3_000));
    pet.handle(Input::Tick, 7_200_000);
    assert!(pet.visible(7_200_000));
}

#[test]
fn sprite_hit_area_is_the_body_not_the_corners() {
    let sprite = Rect::new(0.0, 0.0, 96.0, 96.0);
    assert!(in_sprite(&sprite, 48.0, 48.0));
    assert!(!in_sprite(&sprite, 2.0, 2.0), "transparent corner passes through");
    assert!(!in_sprite(&sprite, 120.0, 48.0));
    let popover = Rect::new(0.0, -308.0, 280.0, 300.0);
    assert_eq!(hit_test(&sprite, Some(&popover), 10.0, -100.0), Hit::Popover);
    assert_eq!(hit_test(&sprite, Some(&popover), 48.0, 48.0), Hit::Sprite);
    assert_eq!(hit_test(&sprite, Some(&popover), 200.0, 50.0), Hit::PassThrough);
    assert_eq!(hit_test(&sprite, None, 10.0, -100.0), Hit::PassThrough);
}

#[test]
fn popover_stays_on_screen_at_every_edge() {
    let screen = Rect::new(0.0, 0.0, 1280.0, 720.0);
    let size = (280.0, 300.0);
    for (x, y) in [
        (1170.0, 600.0),
        (0.0, 600.0),
        (0.0, 0.0),
        (1184.0, 0.0),
        (600.0, 300.0),
        (1184.0, 312.0),
    ] {
        let sprite = Rect::new(x, y, 96.0, 96.0);
        let p = place_popover(&sprite, size, &screen);
        assert!(
            p.x >= 0.0 && p.y >= 0.0 && p.right() <= 1280.0 && p.bottom() <= 720.0,
            "inside at {x},{y}: {p:?}"
        );
        let overlaps = p.x < sprite.right() && sprite.x < p.right() && p.y < sprite.bottom() && sprite.y < p.bottom();
        assert!(!overlaps, "doesn't cover the pet at {x},{y}: {p:?}");
    }
    // Bottom-right corner: goes above.
    let p = place_popover(&Rect::new(1170.0, 600.0, 96.0, 96.0), size, &screen);
    assert!(p.bottom() <= 600.0);
    // Top edge: goes below.
    let p = place_popover(&Rect::new(600.0, 0.0, 96.0, 96.0), size, &screen);
    assert!(p.y >= 96.0);
    // A screen smaller than the popover still keeps it inside.
    let tiny = Rect::new(0.0, 0.0, 200.0, 200.0);
    let p = place_popover(&Rect::new(50.0, 50.0, 96.0, 96.0), size, &tiny);
    assert_eq!((p.x, p.y, p.w, p.h), (0.0, 0.0, 200.0, 200.0));
    assert_eq!(
        clamp_into(&Rect::new(-50.0, 900.0, 100.0, 100.0), &screen),
        Rect::new(0.0, 620.0, 100.0, 100.0)
    );
}

#[test]
fn rests_above_the_taskbar_snaps_to_edges_and_finds_its_monitor() {
    let work = assumed_work_area(&Rect::new(1920.0, 0.0, 1920.0, 1080.0));
    assert_eq!(work, Rect::new(1920.0, 0.0, 1920.0, 1032.0));
    assert_eq!(rest_position((96.0, 96.0), &work, Corner::BottomRight), (3728.0, 920.0));
    assert_eq!(rest_position((96.0, 96.0), &work, Corner::BottomLeft), (1936.0, 920.0));
    assert_eq!(snap_x(1930.0, 96.0, &work, 24.0), 1920.0);
    assert_eq!(snap_x(3730.0, 96.0, &work, 24.0), 3744.0);
    assert_eq!(snap_x(2500.0, 96.0, &work, 24.0), 2500.0);
    let monitors = [Rect::new(0.0, 0.0, 1920.0, 1080.0), Rect::new(1920.0, 0.0, 1920.0, 1080.0)];
    assert_eq!(monitor_for(&monitors, 2000.0, 10.0), Some(1));
    assert_eq!(monitor_for(&monitors, -5.0, -5.0), Some(0));
    assert_eq!(monitor_for(&[], 0.0, 0.0), None);
}

#[test]
fn click_through_toggles_over_transparent_margins() {
    let sprite = Rect::new(0.0, 0.0, 96.0, 96.0);
    let mut hit = HitController::default();
    assert_eq!(hit.pointer_moved(&sprite, None, 48.0, 48.0, 0), HitAction::None);
    assert_eq!(
        hit.pointer_moved(&sprite, None, 2.0, 2.0, 100),
        HitAction::PassThroughUntil(100 + RECHECK_MS)
    );
    assert!(hit.passing_through());
    // Already passing through: no repeated system calls.
    assert_eq!(hit.pointer_moved(&sprite, None, 3.0, 3.0, 120), HitAction::None);
    assert_eq!(hit.recheck(), HitAction::Catch);
    assert_eq!(hit.recheck(), HitAction::None);
    hit.pointer_moved(&sprite, None, 2.0, 2.0, 400);
    assert_eq!(hit.pointer_moved(&sprite, None, 48.0, 48.0, 410), HitAction::Catch);
}

#[test]
fn overlay_plan_per_desktop() {
    let env =
        |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned());
    assert_eq!(plan(Os::Windows, &env(&[])).note, None);
    assert!(plan(Os::MacOs, &env(&[])).always_on_top);
    let x11 = plan(Os::Linux, &env(&[("DISPLAY", ":0")]));
    assert!(!x11.use_xwayland && x11.always_on_top && x11.note.is_none());
    let gnome = plan(
        Os::Linux,
        &env(&[
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("DISPLAY", ":0"),
            ("XDG_CURRENT_DESKTOP", "GNOME"),
        ]),
    );
    assert!(gnome.use_xwayland && gnome.always_on_top, "XWayland keeps it on top even on GNOME");
    let pure = plan(Os::Linux, &env(&[("WAYLAND_DISPLAY", "wayland-0")]));
    assert!(!pure.always_on_top);
    assert!(
        pure.note.is_some_and(|n| n.contains("normal window")),
        "says so instead of pretending"
    );
}
