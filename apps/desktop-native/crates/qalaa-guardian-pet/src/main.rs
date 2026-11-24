//! Qalaa Guardian window. Start it after the background service (or the classic
//! app): `qalaa-guardian-pet [--skin cyber-owl|shield-fox|mini-sentinel] [--lang ar]`.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use qalaa_guardian_pet::geometry::{assumed_work_area, rest_position, Corner, Rect};
use qalaa_guardian_pet::hit::{HitAction, HitController};
use qalaa_guardian_pet::mood::{Input, Mood, Pet, Timing};
use qalaa_guardian_pet::platform::{plan, Os};
use qalaa_guardian_pet::{
    actions, actions_with, clipboard_text, input_for, layout, mood_text, skin_from, text, Lang, Layout, PetWindow, SPRITE,
};
use qalaa_ipc::{Client, Message, Stream};
use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, LogicalPosition, LogicalSize, ModelRc, Timer, TimerMode, VecModel};

struct App {
    window: PetWindow,
    pet: Pet,
    hit: HitController,
    lang: Lang,
    start: Instant,
    rest: (f32, f32),
    position: (f32, f32),
    work_area: Rect,
    popover_open: bool,
    layout: Layout,
    connected: bool,
    deadline: Timer,
    recheck: Timer,
    patrol: Timer,
}

type Shared = Rc<RefCell<App>>;

fn arg(name: &str) -> Option<String> {
    std::env::args().skip_while(|a| a != name).nth(1)
}

fn now(app: &App) -> u64 {
    u64::try_from(app.start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Moves and resizes the window to the current layout.
fn place(app: &mut App) {
    app.layout = layout(app.position, app.popover_open, &app.work_area);
    let (w, l) = (&app.window, &app.layout);
    w.set_sprite_x(l.sprite.x);
    w.set_sprite_y(l.sprite.y);
    if let Some(p) = l.popover {
        w.set_popover_x(p.x);
        w.set_popover_y(p.y);
        w.set_popover_width(p.w);
        w.set_popover_height(p.h);
    }
    w.set_popover_open(app.popover_open);
    w.window().set_size(LogicalSize::new(l.window.w, l.window.h));
    w.window().set_position(LogicalPosition::new(l.window.x, l.window.y));
}

fn show_mood(app: &App) {
    let mood = app.pet.mood();
    app.window.set_mood(mood.as_str().into());
    app.window.set_mood_text(mood_text(mood, app.lang).into());
}

/// Feeds one input, updates the window, and sets the single wake-up timer.
fn feed(shared: &Shared, input: Input) {
    let mut app = shared.borrow_mut();
    let t = now(&app);
    let before = app.pet.mood();
    app.pet.handle(input, t);
    show_mood(&app);
    let visible = app.pet.visible(t);
    if visible != app.window.window().is_visible() {
        let _ = if visible { app.window.show() } else { app.window.hide() };
    }
    if app.pet.mood() == Mood::Patrol && before != Mood::Patrol {
        start_patrol(shared, &mut app);
    }
    if before == Mood::Patrol && app.pet.mood() != Mood::Patrol {
        app.patrol.stop();
        app.position = app.rest;
        place(&mut app);
    }
    schedule(shared, &app);
}

fn schedule(shared: &Shared, app: &App) {
    let t = now(app);
    match app.pet.next_deadline() {
        Some(at) => {
            let weak = Rc::downgrade(shared);
            app.deadline.start(
                TimerMode::SingleShot,
                Duration::from_millis(at.saturating_sub(t).max(1)),
                move || {
                    if let Some(shared) = weak.upgrade() {
                        feed(&shared, Input::Tick);
                    }
                },
            );
        }
        None => app.deadline.stop(),
    }
}

/// A short walk along the bottom edge; the only animation timer, and only while patrolling.
fn start_patrol(shared: &Shared, app: &mut App) {
    let weak = Rc::downgrade(shared);
    let started = Instant::now();
    app.patrol.start(TimerMode::Repeated, Duration::from_millis(50), move || {
        let Some(shared) = weak.upgrade() else { return };
        let mut app = shared.borrow_mut();
        let phase = started.elapsed().as_secs_f32() / 6.0 * std::f32::consts::TAU;
        let x = app.rest.0 - 60.0 * phase.sin().abs();
        app.position = (x, app.rest.1);
        let l = layout(app.position, false, &app.work_area);
        app.window.window().set_position(LogicalPosition::new(l.window.x, l.window.y));
    });
}

fn call_service(method: &'static str) {
    thread::spawn(move || {
        if let Ok(mut client) = Client::connect(&qalaa_ipc::endpoint(), &qalaa_ipc::token_file(), "qalaa-guardian-pet") {
            let _ = client.call_raw(method, None);
        }
    });
}

/// Listens for service events on its own connection; reconnects every 10 s.
fn listen(window: slint::Weak<PetWindow>, sink: Arc<Mutex<Vec<Input>>>) {
    thread::spawn(move || loop {
        let connected = Client::<Stream>::connect(&qalaa_ipc::endpoint(), &qalaa_ipc::token_file(), "qalaa-guardian-pet");
        let online = connected.is_ok();
        let _ = window.upgrade_in_event_loop(move |w| w.invoke_connection_changed(online));
        if let Ok(mut client) = connected {
            while let Ok(message) = client.read_message() {
                if let Message::Event(event) = message {
                    if event.name == "clipboard.armed" || event.name == "clipboard.cleared" {
                        let ms = if event.name == "clipboard.armed" {
                            event.payload.get("ttlMs").and_then(serde_json::Value::as_i64).unwrap_or(0)
                        } else {
                            0
                        };
                        let _ = window.upgrade_in_event_loop(move |w| w.invoke_clipboard_changed(i32::try_from(ms).unwrap_or(0)));
                        continue;
                    }
                    if let Some(input) = input_for(&event) {
                        if let Ok(mut queue) = sink.lock() {
                            queue.push(input);
                        }
                        let _ = window.upgrade_in_event_loop(|w| w.invoke_drain_events());
                    }
                }
            }
            let _ = window.upgrade_in_event_loop(|w| w.invoke_connection_changed(false));
        }
        thread::sleep(Duration::from_secs(10));
    });
}

fn main() -> Result<(), slint::PlatformError> {
    let overlay = plan(Os::current(), &|k| std::env::var(k).ok());
    if overlay.use_xwayland {
        // XWayland gives always-on-top and input shapes on every compositor.
        std::env::remove_var("WAYLAND_DISPLAY");
    }
    let lang = Lang::detect(arg("--lang").as_deref());
    let window = PetWindow::new()?;
    window.set_skin(skin_from(arg("--skin").as_deref()).into());
    window.set_rtl(lang == Lang::Ar);
    window.set_sprite_label(text("sprite", lang).into());
    window.set_note(overlay.note.unwrap_or("").into());
    window.set_status_text(text("offline", lang).into());
    window.set_actions(ModelRc::from(Rc::new(VecModel::from(actions(lang, false)))));

    let start = Instant::now();
    let shared: Shared = Rc::new(RefCell::new(App {
        window: window.clone_strong(),
        pet: Pet::new(0, Timing::default()),
        hit: HitController::default(),
        lang,
        start,
        rest: (0.0, 0.0),
        position: (0.0, 0.0),
        work_area: Rect::new(0.0, 0.0, 1280.0, 720.0),
        popover_open: false,
        layout: layout((0.0, 0.0), false, &Rect::new(0.0, 0.0, 1280.0, 720.0)),
        connected: false,
        deadline: Timer::default(),
        recheck: Timer::default(),
        patrol: Timer::default(),
    }));

    let queue: Arc<Mutex<Vec<Input>>> = Arc::default();
    {
        let (weak, queue) = (Rc::downgrade(&shared), Arc::clone(&queue));
        window.on_drain_events(move || {
            let Some(shared) = weak.upgrade() else { return };
            let inputs: Vec<Input> = queue.lock().map(|mut q| q.drain(..).collect()).unwrap_or_default();
            for input in inputs {
                feed(&shared, input);
            }
        });
    }
    {
        let weak = Rc::downgrade(&shared);
        window.on_connection_changed(move |online| {
            let Some(shared) = weak.upgrade() else { return };
            let mut app = shared.borrow_mut();
            app.connected = online;
            app.window
                .set_status_text(text(if online { "connected" } else { "offline" }, app.lang).into());
            app.window
                .set_actions(ModelRc::from(Rc::new(VecModel::from(actions(app.lang, online)))));
        });
    }
    {
        let weak = Rc::downgrade(&shared);
        window.on_sprite_clicked(move || {
            let Some(shared) = weak.upgrade() else { return };
            feed(&shared, Input::Clicked);
            let mut app = shared.borrow_mut();
            app.popover_open = !app.popover_open;
            place(&mut app);
        });
    }
    {
        let weak = Rc::downgrade(&shared);
        window.on_close_popover(move || {
            let Some(shared) = weak.upgrade() else { return };
            let mut app = shared.borrow_mut();
            app.popover_open = false;
            place(&mut app);
        });
    }
    {
        let weak = Rc::downgrade(&shared);
        window.on_action(move |id| {
            let Some(shared) = weak.upgrade() else { return };
            match id.as_str() {
                "scan.quick" => call_service("scan.quick"),
                "clipboard.clear_now" => call_service("clipboard.clear_now"),
                "signatures.update" => call_service("signatures.update"),
                "open" => {
                    let exe = std::env::current_exe().ok().and_then(|p| {
                        p.parent()
                            .map(|d| d.join(if cfg!(windows) { "qalaa-command.exe" } else { "qalaa-command" }))
                    });
                    if let Some(exe) = exe {
                        let _ = std::process::Command::new(exe).spawn();
                    }
                }
                "snooze" => {
                    {
                        let mut app = shared.borrow_mut();
                        app.popover_open = false;
                        place(&mut app);
                    }
                    feed(&shared, Input::Snooze { minutes: 120 });
                }
                _ => {}
            }
        });
    }

    // Window-system setup once the window exists: position, click-through, taskbar.
    {
        let weak = Rc::downgrade(&shared);
        let setup = Timer::default();
        setup.start(TimerMode::SingleShot, Duration::from_millis(1), move || {
            let Some(shared) = weak.upgrade() else { return };
            let mut app = shared.borrow_mut();
            let monitor = app
                .window
                .window()
                .with_winit_window(|w| {
                    let m = w.current_monitor().or_else(|| w.primary_monitor())?;
                    let scale = m.scale_factor() as f32;
                    let (pos, size) = (m.position(), m.size());
                    #[cfg(windows)]
                    {
                        use winit::platform::windows::WindowExtWindows;
                        w.set_skip_taskbar(true);
                    }
                    w.set_window_level(winit::window::WindowLevel::AlwaysOnTop);
                    Some(Rect::new(
                        pos.x as f32 / scale,
                        pos.y as f32 / scale,
                        size.width as f32 / scale,
                        size.height as f32 / scale,
                    ))
                })
                .flatten();
            if let Some(monitor) = monitor {
                app.work_area = assumed_work_area(&monitor);
            }
            app.rest = rest_position((SPRITE, SPRITE), &app.work_area, Corner::BottomRight);
            app.position = app.rest;
            place(&mut app);
            schedule(&shared, &app);
        });
        std::mem::forget(setup);
    }
    if overlay.click_through {
        let weak = Rc::downgrade(&shared);
        window.window().on_winit_window_event(move |w, event| {
            if let winit::event::WindowEvent::CursorMoved { position, .. } = event {
                let Some(shared) = weak.upgrade() else {
                    return EventResult::Propagate;
                };
                let scale = w.scale_factor();
                let mut app = shared.borrow_mut();
                let t = now(&app);
                let (px, py) = (position.x as f32 / scale, position.y as f32 / scale);
                let popover = app.layout.popover;
                let sprite = app.layout.sprite;
                let action = app.hit.pointer_moved(&sprite, popover.as_ref(), px, py, t);
                drop(app);
                apply_hit(&shared, action);
                if qalaa_guardian_pet::geometry::in_sprite(&sprite, px, py) {
                    feed(&shared, Input::Activity);
                }
            }
            EventResult::Propagate
        });
    }

    // Clipboard countdown in the card; the timer runs only while a secret is armed.
    {
        let weak = Rc::downgrade(&shared);
        let countdown = Rc::new(Timer::default());
        window.on_clipboard_changed(move |remaining_ms| {
            let Some(shared) = weak.upgrade() else { return };
            countdown.stop();
            let (lang, connected) = {
                let app = shared.borrow();
                (app.lang, app.connected)
            };
            let restore = {
                let shared = Rc::clone(&shared);
                move || {
                    let app = shared.borrow();
                    app.window
                        .set_status_text(text(if app.connected { "connected" } else { "offline" }, app.lang).into());
                    app.window
                        .set_actions(ModelRc::from(Rc::new(VecModel::from(actions(app.lang, app.connected)))));
                }
            };
            if remaining_ms <= 0 {
                restore();
                return;
            }
            let deadline = Instant::now() + Duration::from_millis(u64::try_from(remaining_ms).unwrap_or(0));
            {
                let app = shared.borrow();
                app.window
                    .set_status_text(clipboard_text(u64::try_from(remaining_ms).unwrap_or(0), lang).into());
                app.window
                    .set_actions(ModelRc::from(Rc::new(VecModel::from(actions_with(lang, connected, true)))));
            }
            let inner = Rc::downgrade(&shared);
            let stop = Rc::downgrade(&countdown);
            countdown.start(TimerMode::Repeated, Duration::from_secs(1), move || {
                let Some(shared) = inner.upgrade() else { return };
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    if let Some(timer) = stop.upgrade() {
                        timer.stop();
                    }
                    let app = shared.borrow();
                    app.window
                        .set_status_text(text(if app.connected { "connected" } else { "offline" }, app.lang).into());
                    app.window
                        .set_actions(ModelRc::from(Rc::new(VecModel::from(actions(app.lang, app.connected)))));
                } else {
                    let app = shared.borrow();
                    app.window
                        .set_status_text(clipboard_text(u64::try_from(left.as_millis()).unwrap_or(0), app.lang).into());
                }
            });
        });
    }

    listen(window.as_weak(), Arc::clone(&queue));
    window.run()
}

fn apply_hit(shared: &Shared, action: HitAction) {
    let app = shared.borrow();
    match action {
        HitAction::None => {}
        HitAction::Catch => {
            app.window.window().with_winit_window(|w| w.set_cursor_hittest(true));
        }
        HitAction::PassThroughUntil(at) => {
            app.window.window().with_winit_window(|w| w.set_cursor_hittest(false));
            let weak = Rc::downgrade(shared);
            let delay = at.saturating_sub(now(&app));
            app.recheck.start(TimerMode::SingleShot, Duration::from_millis(delay), move || {
                let Some(shared) = weak.upgrade() else { return };
                let action = shared.borrow_mut().hit.recheck();
                apply_hit(&shared, action);
            });
        }
    }
}
