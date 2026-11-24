//! Qalaa command centre: a native window (no browser engine) over the
//! background service. Run the service first (`node dist/daemon.js`, or the
//! classic app, which serves the same protocol).

use std::sync::{Arc, Mutex};
use std::thread;

use qalaa_command::strings::{t, Lang};
use qalaa_command::view::{filter_palette, home_view, palette_entries, PaletteEntry};
use qalaa_command::{apply_home, now_secs, set_language, set_offline, set_palette, App};
use qalaa_ipc::{Client, HomeModel, IpcError, Message, Stream};
use serde_json::json;
use slint::ComponentHandle;

type Shared<T> = Arc<Mutex<T>>;

struct State {
    lang: Lang,
    client: Shared<Option<Client<Stream>>>,
    home: Shared<Option<HomeModel>>,
    palette: Shared<Vec<PaletteEntry>>,
}

fn connect() -> Result<Client<Stream>, IpcError> {
    Client::connect(&qalaa_ipc::endpoint(), &qalaa_ipc::token_file(), "qalaa-command")
}

fn show(app: &App, lang: Lang, model: &HomeModel, palette: &Shared<Vec<PaletteEntry>>) {
    let view = home_view(model, now_secs(), lang);
    apply_home(app, &view);
    let entries = palette_entries(Some(&view), lang);
    set_palette(app, &entries);
    if let Ok(mut p) = palette.lock() {
        *p = entries;
    }
}

/// Runs a service call off the interface thread, then refreshes Home.
fn call(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            client.call_raw(method, params).map_err(|e| e.to_string())?;
            client.call::<HomeModel>("home.get", None).map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(model) => {
                    show(&app, lang, &model, &state.palette);
                    app.set_notice("".into());
                    if let Ok(mut home) = state.home.lock() {
                        *home = Some(model);
                    }
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// A second connection that only listens for `home.changed`.
fn listen(app: &App, state: &Arc<State>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    thread::spawn(move || {
        let Ok(mut events) = connect() else { return };
        while let Ok(message) = events.read_message() {
            if let Message::Event(event) = message {
                if event.name != "home.changed" {
                    continue;
                }
                let Ok(model) = serde_json::from_value::<HomeModel>(event.payload) else {
                    continue;
                };
                let state = Arc::clone(&state);
                let _ = weak.upgrade_in_event_loop(move |app| {
                    show(&app, state.lang, &model, &state.palette);
                    if let Ok(mut home) = state.home.lock() {
                        *home = Some(model);
                    }
                });
            }
        }
        let _ = weak.upgrade_in_event_loop(|app| set_offline(&app));
    });
}

fn start(app: &App, state: &Arc<State>) {
    match connect().and_then(|mut client| client.call::<HomeModel>("home.get", None).map(|home| (client, home))) {
        Ok((client, model)) => {
            show(app, state.lang, &model, &state.palette);
            if let Ok(mut c) = state.client.lock() {
                *c = Some(client);
            }
            if let Ok(mut h) = state.home.lock() {
                *h = Some(model);
            }
            listen(app, state);
        }
        Err(error) => {
            eprintln!("{error}");
            set_offline(app);
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let arg_lang = std::env::args().skip_while(|a| a != "--lang").nth(1);
    let lang = Lang::detect(arg_lang.as_deref());
    let app = App::new()?;
    set_language(&app, lang);
    let state = Arc::new(State {
        lang,
        client: Arc::default(),
        home: Arc::default(),
        palette: Arc::default(),
    });

    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_retry(move || {
            if let Some(app) = weak.upgrade() {
                start(&app, &state);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_set_toggle(move |key, on| {
            if let Some(app) = weak.upgrade() {
                call(&app, &state, "settings.set", Some(json!({ key.as_str(): on })));
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_run_action(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let command = state.home.lock().ok().and_then(|h| {
                h.as_ref()
                    .and_then(|h| h.actions.iter().find(|a| a.id == id.as_str()).map(|a| a.command.clone()))
            });
            let Some(command) = command else { return };
            match command.method.as_str() {
                "settings.set" => call(&app, &state, "settings.set", command.params),
                "scan.quick" => call(&app, &state, "scan.quick", None),
                "signatures.update" => call(&app, &state, "signatures.update", None),
                // Views not yet rebuilt natively live in the classic app.
                _ => app.set_notice(t(state.lang, "classic").into()),
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_palette_filter(move |query| {
            if let (Some(app), Ok(entries)) = (weak.upgrade(), state.palette.lock()) {
                let base = if entries.is_empty() {
                    palette_entries(None, state.lang)
                } else {
                    entries.clone()
                };
                set_palette(&app, &filter_palette(&base, query.as_str()));
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_palette_run(move |id| {
            let Some(app) = weak.upgrade() else { return };
            match id.as_str() {
                "scan.quick" => call(&app, &state, "scan.quick", None),
                "signatures.update" => call(&app, &state, "signatures.update", None),
                "page.home" => app.set_page("home".into()),
                "page.about" => app.set_page("about".into()),
                other => {
                    if let Some(key) = other.strip_prefix("toggle.") {
                        let on = state
                            .home
                            .lock()
                            .ok()
                            .and_then(|h| h.as_ref().and_then(|h| h.toggles.iter().find(|t| t.key == key).map(|t| t.on)));
                        if let Some(on) = on {
                            call(&app, &state, "settings.set", Some(json!({ key: !on })));
                        }
                    }
                }
            }
        });
    }

    start(&app, &state);
    app.run()
}
