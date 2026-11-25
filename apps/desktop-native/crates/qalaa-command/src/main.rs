//! Qalaa command centre: a native window (no browser engine) over the
//! background service. Run the service first (`node dist/daemon.js`, or the
//! classic app, which serves the same protocol).

use std::sync::{Arc, Mutex};
use std::thread;

use qalaa_command::strings::{t, Lang};
use qalaa_command::view::{
    alias_notice, brokers_view, clipboard_text, content_protected, credential_text, credentials_view, deep_view, filter_palette, home_view,
    inspector_text, network_progress_text, network_view, palette_entries, ports_view, posture_view, progress_text, protection_view,
    quarantine_view, scan_view, system_view, vpn_view, PaletteEntry,
};
use qalaa_command::{
    apply_home, now_secs, set_behaviour, set_brokers, set_credentials, set_deep, set_language, set_network, set_offline, set_palette,
    set_ports, set_posture, set_protection, set_protection_system, set_quarantine, set_sandbox, set_scan, set_vpn, App,
};
use qalaa_ipc::{
    BehaviourStatus, BrokerStatus, Client, CredentialChecks, CredentialStatus, DeepCheck, HomeModel, IpcError, ListenerStatus, Message,
    NetworkStatus, PostureStatus, ProtectionStatus, QuarantineItem, QuarantineList, SandboxList, SandboxRun, ScanDetails, ScanStatus,
    Stream, SystemChecks, VpnStatus,
};
use serde_json::json;
use slint::winit_030::WinitWindowAccessor;
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

/// Runs a shared-client call off the interface thread and hands the result to `done` on it.
fn on_client<T: Send + 'static>(
    app: &App,
    state: &Arc<State>,
    work: impl FnOnce(&mut Client<Stream>) -> Result<T, IpcError> + Send + 'static,
    done: impl FnOnce(&App, Lang, T) + Send + 'static,
) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            work(client).map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(value) => {
                    app.set_notice("".into());
                    done(&app, lang, value);
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Shows the Scan page from a fresh `scan.get`.
fn scan_page(app: &App, state: &Arc<State>) {
    on_client(
        app,
        state,
        |c| c.call::<ScanStatus>("scan.get", None),
        |app, lang, status| {
            set_scan(app, &scan_view(&status, now_secs(), lang));
        },
    );
}

/// A scan can take minutes, so it gets its own connection: the rest of the window keeps working,
/// and progress arrives as scan.progress events on the listening connection.
fn run_scan(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_scanning(true);
    app.set_scan_summary(progress_text(0, 0, state.lang).into());
    thread::spawn(move || {
        let result = connect().and_then(|mut c| c.call_raw(method, params)).map_err(|e| e.to_string());
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_scanning(false);
            if let Err(message) = result {
                app.set_notice(message.into());
            }
            scan_page(&app, &state);
        });
    });
}

/// Calls a protection.* method (or just protection.get) and shows the Protection page.
fn protection(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    on_client(
        app,
        state,
        move |c| {
            if method != "protection.get" {
                c.call_raw(method, params)?;
            }
            c.call::<ProtectionStatus>("protection.get", None)
        },
        |app, lang, status| set_protection(app, &protection_view(&status, now_secs(), lang)),
    );
}

fn protection_system(app: &App, state: &Arc<State>) {
    on_client(
        app,
        state,
        |c| c.call::<SystemChecks>("protection.system", None),
        |app, lang, checks| {
            set_protection_system(app, &system_view(&checks, lang));
        },
    );
}

fn network_page(app: &App, state: &Arc<State>) {
    on_client(
        app,
        state,
        |c| c.call::<NetworkStatus>("network.get", None),
        |app, lang, status| {
            set_network(app, &network_view(&status, now_secs(), lang));
        },
    );
}

/// A network scan or a default-password check takes a while: its own connection, like a file scan.
fn network_long<T: Send + 'static>(
    app: &App,
    state: &Arc<State>,
    work: impl FnOnce(&mut Client<Stream>) -> Result<T, IpcError> + Send + 'static,
    done: impl FnOnce(&App, Lang, T) + Send + 'static,
) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_net_scanning(true);
    thread::spawn(move || {
        let result = connect().and_then(|mut c| work(&mut c)).map_err(|e| e.to_string());
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_net_scanning(false);
            match result {
                Ok(value) => done(&app, lang, value),
                Err(message) => app.set_notice(message.into()),
            }
            network_page(&app, &state);
        });
    });
}

/// Calls a vpn.* method (or just vpn.get) and shows the VPN page.
fn vpn(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    on_client(
        app,
        state,
        move |c| c.call::<VpnStatus>(method, params),
        |app, lang, status| {
            set_vpn(app, &vpn_view(&status, lang));
        },
    );
}

/// The page's list with one item added or removed, for the vpn.guard call.
fn edited(model: slint::ModelRc<slint::SharedString>, item: &str, add: bool) -> Vec<String> {
    use slint::Model;
    let mut items: Vec<String> = model.iter().map(|s| s.to_string()).filter(|s| s != item).collect();
    if add {
        items.push(item.to_owned());
    }
    items
}

/// Calls a posture.* method and shows the Security posture page. A full check takes a few
/// seconds, so it runs on its own connection.
fn posture(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    if method == "posture.check" {
        let weak = app.as_weak();
        let lang = state.lang;
        app.set_pos_checking(true);
        thread::spawn(move || {
            let result = connect()
                .and_then(|mut c| c.call::<PostureStatus>("posture.check", None))
                .map_err(|e| e.to_string());
            let _ = weak.upgrade_in_event_loop(move |app| {
                app.set_pos_checking(false);
                match result {
                    Ok(status) => set_posture(&app, &posture_view(&status, now_secs(), lang)),
                    Err(message) => app.set_notice(message.into()),
                }
            });
        });
        return;
    }
    on_client(
        app,
        state,
        move |c| c.call::<PostureStatus>(method, params),
        |app, lang, status| {
            set_posture(app, &posture_view(&status, now_secs(), lang));
        },
    );
}

fn quarantine_page(app: &App, state: &Arc<State>) {
    on_client(
        app,
        state,
        |c| c.call::<QuarantineList>("quarantine.list", None),
        |app, lang, list| {
            set_quarantine(app, &quarantine_view(&list.items, now_secs(), lang));
        },
    );
}

/// Calls a listeners.* method off the interface thread and shows the result on the Ports page.
fn ports(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            let status: ListenerStatus = client.call(method, params).map_err(|e| e.to_string())?;
            let home = client.call::<HomeModel>("home.get", None).ok();
            Ok::<_, String>((status, home))
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok((status, home)) => {
                    set_ports(&app, &ports_view(&status, lang), status.can_block);
                    app.set_notice(status.change.unwrap_or_default().into());
                    if let Some(model) = home {
                        show(&app, lang, &model, &state.palette);
                        if let Ok(mut h) = state.home.lock() {
                            *h = Some(model);
                        }
                    }
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Calls a behaviour.* method off the interface thread and shows the result on the Behaviour page.
fn behaviour(app: &App, state: &Arc<State>, method: String, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            client.call::<BehaviourStatus>(&method, params).map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(status) => {
                    let (rows, note) = qalaa_command::view::behaviour_view(&status, now_secs(), lang);
                    set_behaviour(&app, &rows, &note, qalaa_command::view::behaviour_can_install_helper(&status));
                    app.set_notice("".into());
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Sends a file to the server's sandbox, or refreshes the runs, off the interface thread.
fn sandbox(app: &App, state: &Arc<State>, path: Option<String>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            if let Some(path) = path {
                client
                    .call::<SandboxRun>("sandbox.submit", Some(json!({ "path": path })))
                    .map_err(|e| e.to_string())?;
            }
            client.call::<SandboxList>("sandbox.list", None).map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(list) => {
                    set_sandbox(&app, &qalaa_command::view::sandbox_view(&list.runs, lang));
                    app.set_notice("".into());
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Calls a credentials.* method off the interface thread and shows the result on the Credentials page.
fn credentials(app: &App, state: &Arc<State>, method: String, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            let status: CredentialStatus = client.call(&method, params).map_err(|e| e.to_string())?;
            let home = client.call::<HomeModel>("home.get", None).ok();
            Ok::<_, String>((status, home))
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok((status, home)) => {
                    let (rows, mode) = credentials_view(&status, now_secs(), lang);
                    set_credentials(&app, &rows, &mode);
                    app.set_notice("".into());
                    if let Some(model) = home {
                        show(&app, lang, &model, &state.palette);
                        if let Ok(mut h) = state.home.lock() {
                            *h = Some(model);
                        }
                    }
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Calls a brokers.* method and shows the checklist.
fn brokers(app: &App, state: &Arc<State>, method: &'static str, params: Option<serde_json::Value>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            client.call::<BrokerStatus>(method, params).map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(status) => {
                    let (rows, summary) = brokers_view(&status, lang);
                    set_brokers(&app, &rows, &summary);
                }
                Err(message) => app.set_notice(message.into()),
            }
        });
    });
}

/// Hands an https opt-out page to the system's browser.
fn open_in_browser(url: &str) {
    if !qalaa_command::view::safe_to_open(url) {
        return;
    }
    let mut command = if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = command.spawn();
}

/// Asks the service for a new email alias, copied to the clipboard; says so in the notice bar.
fn new_alias(app: &App, state: &Arc<State>) {
    let weak = app.as_weak();
    let state = Arc::clone(state);
    app.set_busy(true);
    thread::spawn(move || {
        let result = (|| {
            let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
            let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
            client
                .call_raw("aliases.create", Some(json!({ "copy": true })))
                .map_err(|e| e.to_string())
        })();
        let lang = state.lang;
        let _ = weak.upgrade_in_event_loop(move |app| {
            app.set_busy(false);
            match result {
                Ok(alias) => {
                    let address = alias.get("address").and_then(serde_json::Value::as_str).unwrap_or_default();
                    let copied = alias.get("copied").and_then(serde_json::Value::as_bool).unwrap_or(false);
                    app.set_notice(alias_notice(address, copied, lang).into());
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
                if event.name == "clipboard.armed" || event.name == "clipboard.cleared" {
                    let kind = if event.name == "clipboard.armed" {
                        event
                            .payload
                            .get("kind")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("high_entropy")
                            .to_owned()
                    } else {
                        String::new()
                    };
                    let ms = event.payload.get("ttlMs").and_then(serde_json::Value::as_i64).unwrap_or(0);
                    let _ = weak.upgrade_in_event_loop(move |app| app.invoke_clip_event(kind.into(), i32::try_from(ms).unwrap_or(0)));
                    continue;
                }
                if event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("behaviour") {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "behaviour" {
                            app.invoke_page_changed("behaviour".into());
                        }
                    });
                    continue;
                }
                if event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("credential") {
                    // Refresh the Credentials page if it's open; Home follows with home.changed.
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "credentials" {
                            app.invoke_page_changed("credentials".into());
                        }
                    });
                    continue;
                }
                if event.name == "scan.progress" {
                    let scanned = event.payload.get("scanned").and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let found = event.payload.get("found").and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let lang = state.lang;
                    let _ = weak.upgrade_in_event_loop(move |app| {
                        app.set_scanning(true);
                        let n = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
                        app.set_scan_summary(progress_text(n(scanned), n(found), lang).into());
                    });
                    continue;
                }
                if event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("ransomware") {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "protection" {
                            app.invoke_page_changed("protection".into());
                        }
                    });
                    continue;
                }
                if event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("vpn") {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "vpn" {
                            app.invoke_page_changed("vpn".into());
                        }
                    });
                    continue;
                }
                if event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("integrity") {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "posture" {
                            app.invoke_page_changed("posture".into());
                        }
                    });
                    continue;
                }
                if event.name == "network.progress" {
                    let n = |key: &str| {
                        u32::try_from(event.payload.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0)).unwrap_or(u32::MAX)
                    };
                    let (done, total) = (n("done"), n("total"));
                    let phase = event
                        .payload
                        .get("phase")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("sweep")
                        .to_owned();
                    let lang = state.lang;
                    let _ = weak.upgrade_in_event_loop(move |app| {
                        app.set_net_scanning(true);
                        app.set_net_summary(network_progress_text(done, total, &phase, lang).into());
                    });
                    continue;
                }
                if event.name == "network.scanned"
                    || (event.name == "alert" && event.payload.get("kind").and_then(serde_json::Value::as_str) == Some("network"))
                {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        if app.get_page() == "network" {
                            app.invoke_page_changed("network".into());
                        }
                    });
                    continue;
                }
                if event.name == "scan.finished" || event.name == "threat.blocked" {
                    let _ = weak.upgrade_in_event_loop(|app| {
                        let page = app.get_page();
                        if page == "scan" || page == "quarantine" {
                            app.invoke_page_changed(page);
                        }
                    });
                    continue;
                }
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
                "scan.quick" => run_scan(&app, &state, "scan.quick", None),
                "signatures.update" => call(&app, &state, "signatures.update", None),
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("network") =>
                {
                    app.set_page("network".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("quarantine") =>
                {
                    app.set_page("quarantine".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        // "Review threats" lands on the scan results, where detections are listed first.
                        .is_some_and(|v| v == "scan" || v == "timeline") =>
                {
                    app.set_page("scan".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("listeners") =>
                {
                    app.set_page("ports".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("credentials") =>
                {
                    app.set_page("credentials".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("behaviour") =>
                {
                    app.set_page("behaviour".into());
                }
                "view.open"
                    if command
                        .params
                        .as_ref()
                        .and_then(|p| p.get("view"))
                        .and_then(serde_json::Value::as_str)
                        == Some("brokers") =>
                {
                    app.set_page("brokers".into());
                }
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
                "scan.quick" => run_scan(&app, &state, "scan.quick", None),
                "signatures.update" => call(&app, &state, "signatures.update", None),
                "page.home" => app.set_page("home".into()),
                "page.scan" => app.set_page("scan".into()),
                "page.quarantine" => app.set_page("quarantine".into()),
                "page.protection" => app.set_page("protection".into()),
                "page.network" => app.set_page("network".into()),
                "page.vpn" => app.set_page("vpn".into()),
                "page.posture" => app.set_page("posture".into()),
                "page.about" => app.set_page("about".into()),
                "page.ports" => app.set_page("ports".into()),
                "page.credentials" => app.set_page("credentials".into()),
                "page.brokers" => app.set_page("brokers".into()),
                "safepay" => call(&app, &state, "safepay.launch", None),
                "alias.new" => new_alias(&app, &state),
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

    // Clipboard countdown: a one-second timer that runs only while a secret is armed.
    {
        let countdown = std::rc::Rc::new(slint::Timer::default());
        let (weak, lang) = (app.as_weak(), state.lang);
        app.on_clip_event(move |kind, remaining_ms| {
            let Some(app) = weak.upgrade() else { return };
            countdown.stop();
            if kind.is_empty() || remaining_ms <= 0 {
                app.set_clip_text("".into());
                return;
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(u64::try_from(remaining_ms).unwrap_or(0));
            let kind = kind.to_string();
            app.set_clip_text(clipboard_text(&kind, u64::try_from(remaining_ms).unwrap_or(0), lang).into());
            let inner = weak.clone();
            countdown.start(slint::TimerMode::Repeated, std::time::Duration::from_secs(1), move || {
                let Some(app) = inner.upgrade() else { return };
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    app.set_clip_text("".into());
                } else {
                    app.set_clip_text(clipboard_text(&kind, u64::try_from(left.as_millis()).unwrap_or(0), lang).into());
                }
            });
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_clip_clear(move || {
            if let Some(app) = weak.upgrade() {
                call(&app, &state, "clipboard.clear_now", None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_page_changed(move |page| {
            let Some(app) = weak.upgrade() else { return };
            // Hidden from screenshots and screen sharing where the system allows it.
            let protect = content_protected(page.as_str());
            app.window().with_winit_window(|w| w.set_content_protected(protect));
            match page.as_str() {
                "ports" => ports(&app, &state, "listeners.check", None),
                "credentials" => credentials(&app, &state, "credentials.get".into(), None),
                "behaviour" => {
                    behaviour(&app, &state, "behaviour.get".into(), None);
                    sandbox(&app, &state, None);
                }
                "brokers" => brokers(&app, &state, "brokers.get", None),
                "scan" => scan_page(&app, &state),
                "quarantine" => quarantine_page(&app, &state),
                "network" => network_page(&app, &state),
                "vpn" => vpn(&app, &state, "vpn.get", None),
                // Shows what's known at once, then runs a fresh check.
                "posture" => {
                    posture(&app, &state, "posture.get", None);
                    posture(&app, &state, "posture.check", None);
                }
                "protection" => {
                    protection(&app, &state, "protection.get", None);
                    protection_system(&app, &state);
                }
                _ => {}
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_port_trust(move |key| {
            if let Some(app) = weak.upgrade() {
                ports(&app, &state, "listeners.trust", Some(json!({ "key": key.as_str() })));
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_port_block(move |port, block| {
            if let Some(app) = weak.upgrade() {
                ports(&app, &state, "listeners.block", Some(json!({ "port": port, "block": block })));
            }
        });
    }

    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_cred_action(move |id, action| {
            let Some(app) = weak.upgrade() else { return };
            if matches!(action.as_str(), "suspend" | "resume" | "terminate" | "allow" | "dismiss") {
                credentials(&app, &state, format!("credentials.{action}"), Some(json!({ "id": id.as_str() })));
            }
        });
    }

    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_beh_helper({
            let (weak, state) = (weak.clone(), Arc::clone(&state));
            move || {
                if let Some(app) = weak.upgrade() {
                    behaviour(&app, &state, "behaviour.helper".into(), Some(json!({ "install": true })));
                }
            }
        });
        app.on_beh_action(move |id, action| {
            let Some(app) = weak.upgrade() else { return };
            if matches!(action.as_str(), "stop" | "dismiss") {
                behaviour(&app, &state, format!("behaviour.{action}"), Some(json!({ "id": id.as_str() })));
            }
        });
    }

    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_safepay(move || {
            if let Some(app) = weak.upgrade() {
                call(&app, &state, "safepay.launch", None);
            }
        });
    }

    app.on_broker_open(|url| open_in_browser(url.as_str()));
    app.on_sandbox_open(|url| open_in_browser(url.as_str()));
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_sandbox_send(move |path| {
            if let Some(app) = weak.upgrade() {
                sandbox(&app, &state, Some(path.trim().to_owned()));
                app.set_sandbox_path("".into());
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_sandbox_refresh(move || {
            if let Some(app) = weak.upgrade() {
                sandbox(&app, &state, None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_broker_mark(move |id, broker_state| {
            if let Some(app) = weak.upgrade() {
                brokers(
                    &app,
                    &state,
                    "brokers.mark",
                    Some(json!({ "id": id.as_str(), "state": broker_state.as_str() })),
                );
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_broker_letter(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "id": id.as_str(), "name": app.get_letter_name().as_str(), "email": app.get_letter_email().as_str(), "copy": true });
            let (weak, state) = (app.as_weak(), Arc::clone(&state));
            thread::spawn(move || {
                let result = (|| {
                    let mut guard = state.client.lock().map_err(|_| "lock".to_owned())?;
                    let client = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
                    client.call_raw("brokers.template", Some(params)).map_err(|e| e.to_string())
                })();
                let lang = state.lang;
                let _ = weak.upgrade_in_event_loop(move |app| match result {
                    Ok(_) => app.set_notice(t(lang, "brokers.letter_copied").into()),
                    Err(message) => app.set_notice(message.into()),
                });
            });
        });
    }

    // --- Scan and Quarantine ---------------------------------------------------------
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_quick(move || {
            if let Some(app) = weak.upgrade() {
                run_scan(&app, &state, "scan.quick", None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_custom(move |path| {
            if let Some(app) = weak.upgrade() {
                run_scan(&app, &state, "scan.custom", Some(json!({ "paths": [path.trim()] })));
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_exclude(move |path| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "path": path.trim() });
            on_client(
                &app,
                &state,
                move |c| c.call::<ScanStatus>("scan.exclude", Some(params)),
                |app, lang, status| {
                    app.set_scan_path("".into());
                    set_scan(app, &scan_view(&status, now_secs(), lang));
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_include(move |path| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "path": path.as_str() });
            on_client(
                &app,
                &state,
                move |c| c.call::<ScanStatus>("scan.include", Some(params)),
                |app, lang, status| {
                    set_scan(app, &scan_view(&status, now_secs(), lang));
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_inspect(move |path| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "path": path.as_str() });
            on_client(
                &app,
                &state,
                move |c| c.call::<ScanDetails>("scan.details", Some(params)),
                |app, lang, details| {
                    app.set_inspector_text(inspector_text(&details, now_secs(), lang).into());
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_deep(move || {
            let Some(app) = weak.upgrade() else { return };
            on_client(
                &app,
                &state,
                |c| c.call::<DeepCheck>("scan.deep", None),
                |app, lang, deep| {
                    set_deep(app, &deep_view(&deep, lang));
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_quarantine(move |path| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "path": path.as_str() });
            let after = Arc::clone(&state);
            on_client(
                &app,
                &state,
                move |c| {
                    c.call::<QuarantineItem>("quarantine.add", Some(params))?;
                    c.call::<ScanStatus>("scan.get", None)
                },
                move |app, lang, status| {
                    set_scan(app, &scan_view(&status, now_secs(), lang));
                    app.set_notice(t(after.lang, "quar.added").into());
                },
            );
        });
    }
    {
        // The full server analysis is the sandbox upload; its report opens in the browser.
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_scan_server(move |path| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "path": path.as_str() });
            on_client(
                &app,
                &state,
                move |c| c.call::<SandboxRun>("sandbox.submit", Some(params)),
                |_app, _lang, run| {
                    open_in_browser(&run.report_url);
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_quar_restore(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "id": id.as_str() });
            on_client(
                &app,
                &state,
                move |c| {
                    let restored = c.call_raw("quarantine.restore", Some(params))?;
                    let list = c.call::<QuarantineList>("quarantine.list", None)?;
                    Ok((restored, list))
                },
                |app, lang, (restored, list)| {
                    set_quarantine(app, &quarantine_view(&list.items, now_secs(), lang));
                    let path = restored.get("path").and_then(serde_json::Value::as_str).unwrap_or_default();
                    app.set_notice(t(lang, "quar.restored").replace("{path}", path).into());
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_quar_delete(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "id": id.as_str() });
            on_client(
                &app,
                &state,
                move |c| {
                    c.call_raw("quarantine.delete", Some(params))?;
                    c.call::<QuarantineList>("quarantine.list", None)
                },
                |app, lang, list| {
                    set_quarantine(app, &quarantine_view(&list.items, now_secs(), lang));
                    app.set_notice(t(lang, "quar.deleted").into());
                },
            );
        });
    }

    // --- Protection -------------------------------------------------------------------
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_toggle(move |key, on| {
            let Some(app) = weak.upgrade() else { return };
            let method = match key.as_str() {
                "realtime" => "protection.realtime",
                "onaccess" => "protection.onaccess",
                "ransomware" => "protection.ransomware",
                "decoys" => "protection.decoys",
                "terminal" => "protection.terminal",
                _ => return,
            };
            protection(&app, &state, method, Some(json!({ "on": on })));
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_folder_add(move |path| {
            if let Some(app) = weak.upgrade() {
                protection(&app, &state, "protection.folder_add", Some(json!({ "path": path.trim() })));
                app.set_prot_path("".into());
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_folder_remove(move |path| {
            if let Some(app) = weak.upgrade() {
                protection(&app, &state, "protection.folder_remove", Some(json!({ "path": path.as_str() })));
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_halted_action(move |pid, action| {
            let Some(app) = weak.upgrade() else { return };
            let (Ok(pid), true) = (pid.parse::<u32>(), matches!(action.as_str(), "resume" | "kill")) else {
                return;
            };
            protection(
                &app,
                &state,
                "protection.halted",
                Some(json!({ "pid": pid, "action": action.as_str() })),
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_cfa(move |action, path| {
            let Some(app) = weak.upgrade() else { return };
            let params = if path.is_empty() {
                json!({ "action": action.as_str() })
            } else {
                json!({ "action": action.as_str(), "path": path.trim() })
            };
            protection(&app, &state, "protection.cfa", Some(params));
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_prot_system(move || {
            if let Some(app) = weak.upgrade() {
                protection_system(&app, &state);
            }
        });
    }

    // --- Home network ---------------------------------------------------------------
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_net_scan(move || {
            if let Some(app) = weak.upgrade() {
                app.set_net_cred_text("".into());
                network_long(
                    &app,
                    &state,
                    |c| c.call::<NetworkStatus>("network.scan", None),
                    |_app, _lang, _status| {},
                );
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_net_trust(move |key, trusted| {
            let Some(app) = weak.upgrade() else { return };
            let params = json!({ "key": key.as_str(), "trusted": trusted });
            on_client(
                &app,
                &state,
                move |c| c.call::<NetworkStatus>("network.trust", Some(params)),
                |app, lang, status| {
                    set_network(app, &network_view(&status, now_secs(), lang));
                },
            );
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_net_check(move |ip| {
            let Some(app) = weak.upgrade() else { return };
            // The checkbox is the consent; the service refuses without it.
            let params = json!({ "ip": ip.as_str(), "consent": app.get_net_consent() });
            network_long(
                &app,
                &state,
                move |c| c.call::<CredentialChecks>("network.credentials", Some(params)),
                |app, lang, checks| {
                    app.set_net_cred_text(credential_text(&checks, lang).into());
                },
            );
        });
    }

    // --- VPN ---------------------------------------------------------------------------
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_setup(move || {
            if let Some(app) = weak.upgrade() {
                vpn(&app, &state, "vpn.setup", None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_connect(move |connect| {
            if let Some(app) = weak.upgrade() {
                vpn(&app, &state, if connect { "vpn.connect" } else { "vpn.disconnect" }, None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_toggle(move |key, on| {
            let Some(app) = weak.upgrade() else { return };
            match key.as_str() {
                "killswitch" => vpn(&app, &state, "vpn.killswitch", Some(json!({ "on": on }))),
                "allowlan" => vpn(&app, &state, "vpn.guard", Some(json!({ "allowLan": on }))),
                "autoconnect" => vpn(&app, &state, "vpn.guard", Some(json!({ "autoConnect": on }))),
                _ => {}
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_split(move |mode| {
            if let Some(app) = weak.upgrade() {
                if matches!(mode.as_str(), "full" | "exclude" | "only") {
                    vpn(&app, &state, "vpn.guard", Some(json!({ "splitMode": mode.as_str() })));
                }
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_range(move |range, add| {
            let Some(app) = weak.upgrade() else { return };
            let ranges = edited(app.get_vpn_ranges(), range.trim(), add);
            app.set_vpn_range_input("".into());
            vpn(&app, &state, "vpn.guard", Some(json!({ "splitCidrs": ranges })));
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_vpn_trust(move |name, add| {
            let Some(app) = weak.upgrade() else { return };
            let names = edited(app.get_vpn_trusted_names(), name.trim(), add);
            app.set_vpn_trusted_input("".into());
            vpn(&app, &state, "vpn.guard", Some(json!({ "trusted": names })));
        });
    }

    // --- Security posture ---------------------------------------------------------------
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_pos_check(move || {
            if let Some(app) = weak.upgrade() {
                posture(&app, &state, "posture.check", None);
            }
        });
    }
    {
        let (weak, state) = (app.as_weak(), Arc::clone(&state));
        app.on_pos_action(move |action, value| {
            let Some(app) = weak.upgrade() else { return };
            let value = value.trim().to_owned();
            let (method, params) = match action.as_str() {
                "startup_ack" => ("posture.startup_ack", None),
                "startup_off" => ("posture.startup_off", Some(json!({ "id": value }))),
                "startup_on" => ("posture.startup_on", Some(json!({ "id": value }))),
                "integrity_accept" => ("posture.integrity_accept", Some(json!({ "path": value }))),
                "integrity_remove" => ("posture.integrity_remove", Some(json!({ "path": value }))),
                "integrity_add" => {
                    app.set_pos_path_input("".into());
                    ("posture.integrity_add", Some(json!({ "path": value })))
                }
                "integrity_reset" => ("posture.integrity_reset", None),
                _ => return,
            };
            posture(&app, &state, method, params);
        });
    }

    start(&app, &state);
    app.run()
}
