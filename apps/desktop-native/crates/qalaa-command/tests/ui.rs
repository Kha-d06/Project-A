//! Headless interface tests with Slint's testing backend: elements are found by
//! their accessible labels, as a screen reader would.

use std::cell::RefCell;
use std::rc::Rc;

use i_slint_backend_testing::ElementHandle;
use qalaa_command::strings::Lang;
use qalaa_command::view::{home_view, palette_entries, parse_iso};
use qalaa_command::{apply_home, set_language, set_offline, set_palette, App};
use qalaa_ipc::HomeModel;
use slint::platform::{Key, WindowEvent};
use slint::{ComponentHandle, Model};

fn fixture() -> HomeModel {
    serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/home.json")).expect("fixture")
}

fn labelled(app: &App, label: &str) -> Vec<ElementHandle> {
    ElementHandle::find_by_accessible_label(app, label).collect()
}

// One test function: the testing backend is set up once per process.
#[test]
fn command_centre_interface() {
    i_slint_backend_testing::init_no_event_loop();
    let now = parse_iso("2026-11-24T12:00:00Z").expect("now");

    // --- Offline: says what's wrong and offers a retry.
    let app = App::new().expect("window");
    // Tall enough that nothing is scrolled out of view (the search skips clipped items).
    app.window().set_size(slint::LogicalSize::new(1100.0, 2400.0));
    set_language(&app, Lang::En);
    set_offline(&app);
    let retried = Rc::new(RefCell::new(0));
    {
        let retried = Rc::clone(&retried);
        app.on_retry(move || *retried.borrow_mut() += 1);
    }
    let retry = labelled(&app, "Try again");
    assert_eq!(retry.len(), 1, "one retry button");
    retry[0].invoke_accessible_default_action();
    assert_eq!(*retried.borrow(), 1);

    // --- Home from the shared fixture.
    let view = home_view(&fixture(), now, Lang::En);
    apply_home(&app, &view);
    set_palette(&app, &palette_entries(Some(&view), Lang::En));
    assert!(labelled(&app, "Try again").is_empty(), "offline card hidden once connected");

    let ring = labelled(&app, "Protection score");
    assert_eq!(ring.len(), 1);
    assert_eq!(ring[0].accessible_value().as_deref(), Some("36%"));
    assert_eq!(
        labelled(&app, "Malware fingerprints: Needs a look, 3 days ago").len(),
        1,
        "check row with freshness"
    );
    assert_eq!(labelled(&app, "Real-time file checks: Off, never").len(), 1);

    // Action queue: the button carries the action's name and calls back with its id.
    let ran = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let ran = Rc::clone(&ran);
        app.on_run_action(move |id| ran.borrow_mut().push(id.to_string()));
    }
    let review: Vec<_> = labelled(&app, "Review recent threats")
        .into_iter()
        .filter(|e| e.accessible_role() == Some(i_slint_core::items::AccessibleRole::Button))
        .collect();
    assert_eq!(review.len(), 1);
    review[0].invoke_accessible_default_action();
    assert_eq!(*ran.borrow(), vec!["review_threats".to_owned()]);

    // Quick toggles: switching calls back with the key and new value; unavailable ones are disabled.
    let toggled = Rc::new(RefCell::new(Vec::<(String, bool)>::new()));
    {
        let toggled = Rc::clone(&toggled);
        app.on_set_toggle(move |key, on| toggled.borrow_mut().push((key.to_string(), on)));
    }
    let downloads = labelled(&app, "Check new downloads");
    assert_eq!(downloads.len(), 1);
    assert_eq!(downloads[0].accessible_checked(), Some(false));
    downloads[0].invoke_accessible_default_action();
    assert_eq!(*toggled.borrow(), vec![("watchEnabled".to_owned(), true)]);

    // --- Command palette: Ctrl+K opens it, typing filters it, Escape closes it.
    let filtered = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let (filtered, weak) = (Rc::clone(&filtered), app.as_weak());
        app.on_palette_filter(move |query| {
            filtered.borrow_mut().push(query.to_string());
            if let Some(app) = weak.upgrade() {
                let entries = palette_entries(None, Lang::En);
                set_palette(&app, &qalaa_command::view::filter_palette(&entries, query.as_str()));
            }
        });
    }
    let window = app.window();
    assert!(!app.get_palette_open());
    window.dispatch_event(WindowEvent::KeyPressed { text: Key::Control.into() });
    window.dispatch_event(WindowEvent::KeyPressed { text: "k".into() });
    window.dispatch_event(WindowEvent::KeyReleased { text: "k".into() });
    window.dispatch_event(WindowEvent::KeyReleased { text: Key::Control.into() });
    assert!(app.get_palette_open(), "Ctrl+K opens the palette");
    assert_eq!(filtered.borrow().first().map(String::as_str), Some(""));
    for ch in ["s", "c", "a", "n"] {
        window.dispatch_event(WindowEvent::KeyPressed { text: ch.into() });
        window.dispatch_event(WindowEvent::KeyReleased { text: ch.into() });
    }
    assert_eq!(filtered.borrow().last().map(String::as_str), Some("scan"));
    let items: Vec<String> = app.get_palette_items().iter().map(|i| i.id.to_string()).collect();
    assert_eq!(items, vec!["scan.quick".to_owned()]);
    let ran_palette = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let ran_palette = Rc::clone(&ran_palette);
        app.on_palette_run(move |id| ran_palette.borrow_mut().push(id.to_string()));
    }
    window.dispatch_event(WindowEvent::KeyPressed { text: Key::Return.into() });
    window.dispatch_event(WindowEvent::KeyReleased { text: Key::Return.into() });
    assert_eq!(*ran_palette.borrow(), vec!["scan.quick".to_owned()]);
    assert!(!app.get_palette_open(), "running a command closes the palette");

    // --- About carries the Slint credit the royalty-free licence requires.
    app.set_page("about".into());
    assert!(ElementHandle::find_by_element_type_name(&app, "AboutSlint").count() >= 1);

    // --- Arabic: labels and right-to-left.
    let arabic = App::new().expect("window");
    arabic.window().set_size(slint::LogicalSize::new(1100.0, 2400.0));
    set_language(&arabic, Lang::Ar);
    apply_home(&arabic, &home_view(&fixture(), now, Lang::Ar));
    assert!(arabic.get_rtl());
    assert_eq!(labelled(&arabic, "درجة الحماية").len(), 1);
    assert_eq!(labelled(&arabic, "افحص التنزيلات الجديدة").len(), 1);
}
