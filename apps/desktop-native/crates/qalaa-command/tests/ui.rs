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
    // The quick scan, then the Scan page.
    assert_eq!(items, vec!["scan.quick".to_owned(), "page.scan".to_owned()]);
    let ran_palette = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let ran_palette = Rc::clone(&ran_palette);
        app.on_palette_run(move |id| ran_palette.borrow_mut().push(id.to_string()));
    }
    window.dispatch_event(WindowEvent::KeyPressed { text: Key::Return.into() });
    window.dispatch_event(WindowEvent::KeyReleased { text: Key::Return.into() });
    assert_eq!(*ran_palette.borrow(), vec!["scan.quick".to_owned()]);
    assert!(!app.get_palette_open(), "running a command closes the palette");

    // --- Ports: new listeners first, with Expected and Block buttons that call back.
    let status: qalaa_ipc::ListenerStatus = serde_json::from_value(serde_json::json!({
        "listeners": [
            {"key": "sshd|22|net", "port": 22, "address": "0.0.0.0", "process": "sshd", "pid": 2, "exposed": true, "risk": null, "fresh": false},
            {"key": "nc|4444|net", "port": 4444, "address": "0.0.0.0", "process": "nc", "pid": 3, "exposed": true, "risk": null, "fresh": true}
        ],
        "blockedPorts": [22], "canBlock": true, "checkedAt": null
    }))
    .expect("status");
    qalaa_command::set_ports(&app, &qalaa_command::view::ports_view(&status, Lang::En), true);
    app.set_page("ports".into());
    let decisions = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let decisions = Rc::clone(&decisions);
        app.on_port_trust(move |key| decisions.borrow_mut().push(format!("trust {key}")));
    }
    {
        let decisions = Rc::clone(&decisions);
        app.on_port_block(move |port, block| decisions.borrow_mut().push(format!("block {port} {block}")));
    }
    labelled(&app, "Expected: nc on port 4444")[0].invoke_accessible_default_action();
    labelled(&app, "Block port: nc on port 4444")[0].invoke_accessible_default_action();
    labelled(&app, "Allow again: sshd on port 22")[0].invoke_accessible_default_action();
    assert_eq!(
        *decisions.borrow(),
        vec![
            "trust nc|4444|net".to_owned(),
            "block 4444 true".to_owned(),
            "block 22 false".to_owned()
        ]
    );
    assert!(
        labelled(&app, "Expected: sshd on port 22").is_empty(),
        "only new listeners ask for a decision"
    );

    // --- SafePay from the Quick-Toggle Dock.
    app.set_page("home".into());
    let safepay = Rc::new(RefCell::new(0));
    {
        let safepay = Rc::clone(&safepay);
        app.on_safepay(move || *safepay.borrow_mut() += 1);
    }
    labelled(&app, "Open SafePay")[0].invoke_accessible_default_action();
    assert_eq!(*safepay.borrow(), 1);

    // --- Clipboard countdown banner with Clear now.
    app.set_page("home".into());
    app.set_clip_text(qalaa_command::view::clipboard_text("api_token", 12_000, Lang::En).into());
    let cleared = Rc::new(RefCell::new(0));
    {
        let cleared = Rc::clone(&cleared);
        app.on_clip_clear(move || *cleared.borrow_mut() += 1);
    }
    assert!(labelled(&app, "An API token is on the clipboard: clearing in 12 s")
        .iter()
        .any(|e| e.accessible_role() == Some(i_slint_core::items::AccessibleRole::Groupbox)));
    labelled(&app, "Clear now")[0].invoke_accessible_default_action();
    assert_eq!(*cleared.borrow(), 1);
    app.set_clip_text("".into());
    assert!(labelled(&app, "Clear now").is_empty());

    // --- Credentials: who opened what, with Pause / Stop / Allow / Dismiss.
    let status: qalaa_ipc::CredentialStatus = serde_json::from_value(serde_json::json!({
        "supported": true, "enabled": true, "mode": "polling", "trusted": [],
        "incidents": [
            {"id": "c1", "pid": 900, "program": "python3", "exe": "/usr/bin/python3", "credential": "ssh_key", "file": "~/.ssh/id_rsa", "at": "2026-11-24T09:59:00Z", "state": "open"},
            {"id": "c2", "pid": 901, "program": "node", "exe": "/usr/bin/node", "credential": "env_file", "file": "~/app/.env", "at": "2026-11-24T09:58:00Z", "state": "suspended"}
        ]
    }))
    .expect("status");
    let (rows, mode) = qalaa_command::view::credentials_view(&status, now, Lang::En);
    qalaa_command::set_credentials(&app, &rows, &mode);
    app.set_page("credentials".into());
    let answers = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let answers = Rc::clone(&answers);
        app.on_cred_action(move |id, action| answers.borrow_mut().push(format!("{action} {id}")));
    }
    labelled(&app, "Pause: python3 opened ~/.ssh/id_rsa")[0].invoke_accessible_default_action();
    labelled(&app, "Resume: node opened ~/app/.env  · Paused")[0].invoke_accessible_default_action();
    labelled(&app, "Stop: python3 opened ~/.ssh/id_rsa")[0].invoke_accessible_default_action();
    labelled(&app, "Allow program: node opened ~/app/.env  · Paused")[0].invoke_accessible_default_action();
    assert_eq!(
        *answers.borrow(),
        vec![
            "suspend c1".to_owned(),
            "resume c2".to_owned(),
            "terminate c1".to_owned(),
            "allow c2".to_owned()
        ]
    );
    assert!(
        labelled(&app, "Pause: node opened ~/app/.env  · Paused").is_empty(),
        "a paused program offers Resume"
    );
    assert_eq!(labelled(&app, &mode).len(), 1, "the page says how complete the watching is");
    qalaa_command::set_credentials(&app, &[], &mode);
    assert_eq!(labelled(&app, "No unexpected program has opened your credentials.").len(), 1);

    // --- Behaviour: a rule match with Stop / Dismiss; finished ones offer no buttons.
    let status: qalaa_ipc::BehaviourStatus = serde_json::from_value(serde_json::json!({
        "enabled": true, "rules": 8, "rulesVersion": "2026.11.25.1",
        "capability": {"source": "proc_poll", "intervalMs": 1000, "seesShortLived": false, "note": ""},
        "incidents": [
            {"id": "b1", "rule": "download_piped_to_shell", "title": "A download is run straight in a shell", "description": "", "technique": "T1059.004", "level": "medium", "pid": 30, "program": "sh", "parent": "bash", "commandLine": "sh -c curl x | sh", "at": "2026-11-24T09:59:00Z", "state": "open"},
            {"id": "b2", "rule": "firewall_disabled", "title": "The firewall is being switched off or emptied", "description": "", "technique": "T1562.004", "level": "high", "pid": 31, "program": "sh", "parent": "bash", "commandLine": "ufw disable", "at": "2026-11-24T09:58:00Z", "state": "stopped"}
        ]
    }))
    .expect("status");
    let (rows, note) = qalaa_command::view::behaviour_view(&status, now, Lang::En);
    qalaa_command::set_behaviour(&app, &rows, &note, true);
    app.set_page("behaviour".into());
    let helper = Rc::new(RefCell::new(0));
    {
        let helper = Rc::clone(&helper);
        app.on_beh_helper(move || *helper.borrow_mut() += 1);
    }
    labelled(
        &app,
        "See every program start (installs a small system helper; asks for your password)",
    )[0]
    .invoke_accessible_default_action();
    assert_eq!(*helper.borrow(), 1);
    let beh = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let beh = Rc::clone(&beh);
        app.on_beh_action(move |id, action| beh.borrow_mut().push(format!("{action} {id}")));
    }
    labelled(&app, "Stop program: A download is run straight in a shell: sh")[0].invoke_accessible_default_action();
    labelled(&app, "Dismiss: A download is run straight in a shell: sh")[0].invoke_accessible_default_action();
    assert_eq!(*beh.borrow(), vec!["stop b1".to_owned(), "dismiss b1".to_owned()]);
    assert!(
        labelled(
            &app,
            "Stop program: The firewall is being switched off or emptied: sh  · High risk  · Stopped"
        )
        .is_empty(),
        "a stopped program offers no actions"
    );
    assert_eq!(labelled(&app, &note).len(), 1, "the page says what polling can miss");
    qalaa_command::set_behaviour(&app, &[], &note, false);
    assert!(labelled(
        &app,
        "See every program start (installs a small system helper; asks for your password)"
    )
    .is_empty());
    assert_eq!(labelled(&app, "No new program has matched a behaviour rule.").len(), 1);

    // --- Sandbox runs on the Behaviour page: send a path, open a report.
    app.set_page("behaviour".into());
    let runs: Vec<qalaa_ipc::SandboxRun> = serde_json::from_value(serde_json::json!([
        {"id": "a", "file": "install.sh", "reportUrl": "https://q.example/scans/a", "status": "completed", "risk": "suspicious", "note": null, "timedOut": false, "seconds": 2.5, "dnsLookups": ["c2.bad.test"], "webRequests": [], "directConnections": [], "programs": [], "submittedAt": "2026-11-25T10:00:00Z"}
    ]))
    .expect("runs");
    qalaa_command::set_sandbox(&app, &qalaa_command::view::sandbox_view(&runs, Lang::En));
    let sent = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let sent = Rc::clone(&sent);
        app.on_sandbox_send(move |p| sent.borrow_mut().push(format!("send {p}")));
    }
    {
        let sent = Rc::clone(&sent);
        app.on_sandbox_open(move |u| sent.borrow_mut().push(format!("open {u}")));
    }
    app.set_sandbox_path("/home/a/install.sh".into());
    labelled(&app, "Send to the sandbox")[0].invoke_accessible_default_action();
    labelled(&app, "Open report: install.sh  · Done")[0].invoke_accessible_default_action();
    assert_eq!(
        *sent.borrow(),
        vec!["send /home/a/install.sh".to_owned(), "open https://q.example/scans/a".to_owned()]
    );

    // --- Data brokers: open, mark, and the request letter needs a name and email first.
    let status: qalaa_ipc::BrokerStatus = serde_json::from_value(serde_json::json!({
        "catalogVersion": "2026-11-25", "reviewed": null, "note": "", "done": 0, "recheckDue": 0,
        "brokers": [{"id": "spokeo", "name": "Spokeo", "site": "spokeo.com", "optOutUrl": "https://www.spokeo.com/optout", "verification": "email_link", "removalDays": 3, "steps": [], "state": "todo", "at": null, "recheckDue": false, "expectedBy": null}]
    }))
    .expect("status");
    let (rows, summary) = qalaa_command::view::brokers_view(&status, Lang::En);
    qalaa_command::set_brokers(&app, &rows, &summary);
    app.set_page("brokers".into());
    let broker_calls = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let calls = Rc::clone(&broker_calls);
        app.on_broker_open(move |url| calls.borrow_mut().push(format!("open {url}")));
    }
    {
        let calls = Rc::clone(&broker_calls);
        app.on_broker_mark(move |id, state| calls.borrow_mut().push(format!("{state} {id}")));
    }
    {
        let calls = Rc::clone(&broker_calls);
        app.on_broker_letter(move |id| calls.borrow_mut().push(format!("letter {id}")));
    }
    labelled(&app, "Open opt-out page: Spokeo")[0].invoke_accessible_default_action();
    labelled(&app, "I asked: Spokeo")[0].invoke_accessible_default_action();
    assert_eq!(labelled(&app, "Copy request letter: Spokeo")[0].accessible_enabled(), Some(false));
    app.set_letter_name("Amira K".into());
    app.set_letter_email("amira@example.com".into());
    labelled(&app, "Copy request letter: Spokeo")[0].invoke_accessible_default_action();
    assert_eq!(
        *broker_calls.borrow(),
        vec![
            "open https://www.spokeo.com/optout".to_owned(),
            "requested spokeo".to_owned(),
            "letter spokeo".to_owned()
        ]
    );
    assert_eq!(labelled(&app, "Remove yourself from data brokers  ·  0 / 1 done").len(), 1);

    // --- Scan: results from the shared fixture, inspector, quarantine, exclusions, progress.
    let scan_json: serde_json::Value =
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/scan.json")).expect("scan fixture");
    let scan_status: qalaa_ipc::ScanStatus = serde_json::from_value(scan_json["status"].clone()).expect("scan status");
    let scan_now = qalaa_command::view::parse_iso("2026-11-25T13:00:00Z").expect("time");
    qalaa_command::set_scan(&app, &qalaa_command::view::scan_view(&scan_status, scan_now, Lang::En));
    app.set_page("scan".into());
    let scan_calls = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_quick(move || calls.borrow_mut().push("quick".to_owned()));
    }
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_custom(move |p| calls.borrow_mut().push(format!("custom {p}")));
    }
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_inspect(move |p| calls.borrow_mut().push(format!("inspect {p}")));
    }
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_quarantine(move |p| calls.borrow_mut().push(format!("quarantine {p}")));
    }
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_include(move |p| calls.borrow_mut().push(format!("include {p}")));
    }
    {
        let calls = Rc::clone(&scan_calls);
        app.on_scan_deep(move || calls.borrow_mut().push("deep".to_owned()));
    }
    assert_eq!(labelled(&app, "Last scan: 3 files, 2 found, 59 minutes ago").len(), 1);
    // Suspicious and not yet in quarantine: can be moved. Already quarantined: no button.
    assert_eq!(labelled(&app, "Move to quarantine: setup.js").len(), 1);
    assert!(labelled(&app, "Move to quarantine: invoice.pdf.exe").is_empty());
    assert!(labelled(&app, "Move to quarantine: notes.txt").is_empty());
    labelled(&app, "Quick scan")[0].invoke_accessible_default_action();
    labelled(&app, "Details: setup.js")[0].invoke_accessible_default_action();
    labelled(&app, "Move to quarantine: setup.js")[0].invoke_accessible_default_action();
    labelled(&app, "Scan it again: /home/me/Downloads/builds")[0].invoke_accessible_default_action();
    labelled(&app, "Deep check")[0].invoke_accessible_default_action();
    assert_eq!(labelled(&app, "Scan this path")[0].accessible_enabled(), Some(false));
    app.set_scan_path("/home/me/Desktop".into());
    labelled(&app, "Scan this path")[0].invoke_accessible_default_action();
    assert_eq!(
        *scan_calls.borrow(),
        vec![
            "quick".to_owned(),
            "inspect /home/me/Downloads/setup.js".to_owned(),
            "quarantine /home/me/Downloads/setup.js".to_owned(),
            "include /home/me/Downloads/builds".to_owned(),
            "deep".to_owned(),
            "custom /home/me/Desktop".to_owned(),
        ]
    );
    // While a scan runs, another can't be started from here.
    app.set_scanning(true);
    assert_eq!(labelled(&app, "Quick scan")[0].accessible_enabled(), Some(false));
    app.set_scanning(false);
    // The inspector opens with every finding and closes again.
    let details: qalaa_ipc::ScanDetails = serde_json::from_value(scan_json["details"].clone()).expect("details");
    assert!(labelled(&app, "Details").is_empty());
    app.set_inspector_text(qalaa_command::view::inspector_text(&details, scan_now, Lang::En).into());
    assert!(!labelled(&app, "Details").is_empty());
    labelled(&app, "Close")[0].invoke_accessible_default_action();
    assert_eq!(app.get_inspector_text(), "");

    // --- Quarantine: restore or delete.
    let list: qalaa_ipc::QuarantineList = serde_json::from_value(scan_json["quarantine"].clone()).expect("quarantine");
    qalaa_command::set_quarantine(&app, &qalaa_command::view::quarantine_view(&list.items, scan_now, Lang::En));
    app.set_page("quarantine".into());
    let quar_calls = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let calls = Rc::clone(&quar_calls);
        app.on_quar_restore(move |id| calls.borrow_mut().push(format!("restore {id}")));
    }
    {
        let calls = Rc::clone(&quar_calls);
        app.on_quar_delete(move |id| calls.borrow_mut().push(format!("delete {id}")));
    }
    labelled(&app, "Restore: invoice.pdf.exe · Threat")[0].invoke_accessible_default_action();
    labelled(&app, "Delete for good: invoice.pdf.exe · Threat")[0].invoke_accessible_default_action();
    assert_eq!(*quar_calls.borrow(), vec!["restore q-1".to_owned(), "delete q-1".to_owned()]);
    qalaa_command::set_quarantine(&app, &[]);
    assert_eq!(labelled(&app, "Nothing in quarantine.").len(), 1);

    // --- Protection: switches, a frozen program, folders, Wi-Fi and updates.
    let prot_json: serde_json::Value =
        serde_json::from_str(include_str!("../../qalaa-ipc/tests/fixtures/protection.json")).expect("protection fixture");
    let linux: qalaa_ipc::ProtectionStatus = serde_json::from_value(prot_json["linux"].clone()).expect("linux");
    let prot_now = qalaa_command::view::parse_iso("2026-11-25T12:30:00Z").expect("time");
    qalaa_command::set_protection(&app, &qalaa_command::view::protection_view(&linux, prot_now, Lang::En));
    let checks: qalaa_ipc::SystemChecks = serde_json::from_value(prot_json["system"].clone()).expect("system");
    qalaa_command::set_protection_system(&app, &qalaa_command::view::system_view(&checks, Lang::En));
    app.set_page("protection".into());
    let prot_calls = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let calls = Rc::clone(&prot_calls);
        app.on_prot_toggle(move |key, on| calls.borrow_mut().push(format!("{key} {on}")));
    }
    {
        let calls = Rc::clone(&prot_calls);
        app.on_prot_halted_action(move |pid, action| calls.borrow_mut().push(format!("{action} {pid}")));
    }
    {
        let calls = Rc::clone(&prot_calls);
        app.on_prot_folder_add(move |p| calls.borrow_mut().push(format!("add {p}")));
    }
    {
        let calls = Rc::clone(&prot_calls);
        app.on_prot_folder_remove(move |p| calls.borrow_mut().push(format!("remove {p}")));
    }
    {
        let calls = Rc::clone(&prot_calls);
        app.on_prot_system(move || calls.borrow_mut().push("system".to_owned()));
    }
    labelled(&app, "Scan new files")[0].invoke_accessible_default_action();
    labelled(&app, "Remove: Program 4242 was frozen")[0].invoke_accessible_default_action();
    labelled(&app, "Stop protecting: /home/me/Documents")[0].invoke_accessible_default_action();
    app.set_prot_path("/home/me/Pictures".into());
    labelled(&app, "Protect this folder")[0].invoke_accessible_default_action();
    labelled(&app, "Check now")[0].invoke_accessible_default_action();
    assert_eq!(
        *prot_calls.borrow(),
        vec![
            "realtime false".to_owned(),
            "kill 4242".to_owned(),
            "remove /home/me/Documents".to_owned(),
            "add /home/me/Pictures".to_owned(),
            "system".to_owned(),
        ]
    );
    assert!(!labelled(
        &app,
        "Wi-Fi \"Cafe\" is open: others nearby can see unencrypted traffic. Use the VPN here."
    )
    .is_empty());
    // Windows-only Controlled Folder Access buttons don't appear on Linux.
    assert!(labelled(&app, "Audit only").is_empty());
    let windows: qalaa_ipc::ProtectionStatus = serde_json::from_value(prot_json["windows"].clone()).expect("windows");
    qalaa_command::set_protection(&app, &qalaa_command::view::protection_view(&windows, prot_now, Lang::En));
    assert_eq!(labelled(&app, "Audit only").len(), 1);
    assert!(labelled(&app, "Check terminal commands").is_empty());

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
    // The new pages are in the Arabic rail too.
    assert!(!labelled(&arabic, "فحص").is_empty());
    assert!(!labelled(&arabic, "الحجر").is_empty());
}
