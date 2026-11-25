//! The Rust side of the contract with apps/desktop/src/core.

use qalaa_ipc::{parse_message, CheckStatus, HomeModel, Message, PostureState};

#[test]
fn decodes_the_home_fixture_written_by_the_typescript_tests() {
    let json = include_str!("fixtures/home.json");
    let home: HomeModel = serde_json::from_str(json).expect("fixture decodes");
    assert_eq!(home.state, PostureState::AtRisk);
    assert_eq!(home.checks.len(), 6);
    assert_eq!(home.checks[1].id, "realtime");
    assert_eq!(home.checks[1].status, CheckStatus::Off);
    assert_eq!(home.checks[0].checked_at.as_deref(), Some("2026-11-21T08:00:00Z"));
    assert_eq!(home.actions[0].id, "review_threats");
    assert_eq!(home.actions[0].command.method, "view.open");
    assert!(home.toggles.iter().any(|t| t.key == "onAccessScan" && t.available));
    // Round-trips without losing anything the service sent.
    let again: serde_json::Value = serde_json::to_value(&home).expect("encodes");
    let original: serde_json::Value = serde_json::from_str(json).expect("json");
    assert_eq!(again, original);
}

#[test]
fn parses_replies_errors_and_events() {
    assert_eq!(
        parse_message(r#"{"id":3,"result":{"ok":true}}"#).expect("reply"),
        Message::Reply {
            id: 3,
            result: Ok(serde_json::json!({"ok": true}))
        }
    );
    match parse_message(r#"{"id":4,"error":{"code":"not_allowed","message":"No."}}"#).expect("error") {
        Message::Reply {
            id: 4,
            result: Err((code, message)),
        } => {
            assert_eq!(code, "not_allowed");
            assert_eq!(message, "No.");
        }
        other => panic!("unexpected {other:?}"),
    }
    match parse_message(r#"{"event":"home.changed","payload":{"score":1}}"#).expect("event") {
        Message::Event(event) => assert_eq!(event.name, "home.changed"),
        other => panic!("unexpected {other:?}"),
    }
    assert!(parse_message("not json").is_err());
    assert!(parse_message(r#"{"result":1}"#).is_err());
}

#[cfg(unix)]
#[test]
fn talks_to_a_service_over_a_socket() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let (client_side, service_side) = UnixStream::pair().expect("pair");
    let service = std::thread::spawn(move || {
        let mut writer = service_side.try_clone().expect("clone");
        let mut lines = BufReader::new(service_side).lines();
        let hello: serde_json::Value = serde_json::from_str(&lines.next().expect("hello").expect("line")).expect("json");
        assert_eq!(hello["method"], "hello");
        assert_eq!(hello["params"]["token"], "t0ken");
        writeln!(writer, r#"{{"id":{},"result":{{"protocol":1,"version":"0.2.0"}}}}"#, hello["id"]).expect("write");
        let call: serde_json::Value = serde_json::from_str(&lines.next().expect("call").expect("line")).expect("json");
        assert_eq!(call["method"], "settings.set");
        assert_eq!(call["params"]["watchEnabled"], true);
        // An event arrives before the reply; the client keeps it.
        writeln!(writer, r#"{{"event":"home.changed","payload":{{}}}}"#).expect("write");
        writeln!(
            writer,
            r#"{{"id":{},"error":{{"code":"unavailable","message":"Not here."}}}}"#,
            call["id"]
        )
        .expect("write");
    });

    let mut client = qalaa_ipc::Client::from_parts(client_side.try_clone().expect("clone"), client_side);
    let hello = client.say_hello("t0ken", "test").expect("hello");
    assert_eq!(hello.version, "0.2.0");
    let error = client
        .call_raw("settings.set", Some(serde_json::json!({"watchEnabled": true})))
        .expect_err("refused");
    assert_eq!(error.to_string(), "Not here.");
    assert_eq!(client.take_events().len(), 1);
    service.join().expect("service");
}

#[test]
fn decodes_the_scan_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::{QuarantineItem, QuarantineList, ScanDetails, ScanStatus};
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/scan.json")).expect("json");
    let status: ScanStatus = serde_json::from_value(json["status"].clone()).expect("status decodes");
    assert!(!status.scanning);
    assert_eq!(status.results.len(), 3);
    assert_eq!(status.results[2].quarantined.as_deref(), Some("q-1"));
    assert_eq!(status.last.as_ref().map(|l| l.malicious), Some(1));
    assert!(status.engines.clamav && !status.engines.native);
    let details: ScanDetails = serde_json::from_value(json["details"].clone()).expect("details decode");
    assert_eq!(details.findings[0].rule, "heur.script");
    let list: QuarantineList = serde_json::from_value(json["quarantine"].clone()).expect("list decodes");
    assert_eq!(list.items[0].id, "q-1");
    let added: QuarantineItem = serde_json::from_value(json["added"].clone()).expect("item decodes");
    assert_eq!(added.reason, "Known test threat");
    // Nothing the service sent is lost.
    for (key, value) in [
        ("status", serde_json::to_value(&status)),
        ("details", serde_json::to_value(&details)),
        ("quarantine", serde_json::to_value(&list)),
        ("added", serde_json::to_value(&added)),
    ] {
        assert_eq!(value.expect("encodes"), json[key], "{key} round-trips");
    }
}

#[test]
fn decodes_the_protection_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::{ProtectionStatus, SystemChecks};
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/protection.json")).expect("json");
    let linux: ProtectionStatus = serde_json::from_value(json["linux"].clone()).expect("linux decodes");
    assert!(linux.on_access.supported && linux.on_access.responder);
    assert_eq!(linux.ransomware.halted[0].pid, 4242);
    assert!(linux.cfa.is_none());
    assert!(linux.ransomware.last_alert.is_some());
    let windows: ProtectionStatus = serde_json::from_value(json["windows"].clone()).expect("windows decodes");
    assert_eq!(windows.cfa.as_ref().map(|c| c.state.as_str()), Some("audit"));
    assert!(!windows.terminal.supported);
    let system: SystemChecks = serde_json::from_value(json["system"].clone()).expect("system decodes");
    assert_eq!(system.wifi.as_ref().map(|w| w.risk.as_str()), Some("open"));
    for (key, value) in [
        ("linux", serde_json::to_value(&linux)),
        ("windows", serde_json::to_value(&windows)),
        ("system", serde_json::to_value(&system)),
    ] {
        assert_eq!(value.expect("encodes"), json[key], "{key} round-trips");
    }
}

#[test]
fn decodes_the_network_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::{CredentialChecks, NetworkStatus};
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/network.json")).expect("json");
    let status: NetworkStatus = serde_json::from_value(json["status"].clone()).expect("status decodes");
    let scan = status.scan.as_ref().expect("scan");
    assert_eq!(scan.devices.len(), 3);
    assert_eq!(scan.devices[0].role, "router");
    assert_eq!(scan.router.as_ref().map(|r| r.port_forwards.len()), Some(1));
    let changes = status.changes.as_ref().expect("changes");
    assert_eq!(changes.gone[0].ip, "192.168.1.30");
    assert_eq!(changes.new_risks[0].severity, "critical");
    let checks: CredentialChecks = serde_json::from_value(json["credentials"].clone()).expect("credentials decode");
    assert!(!checks.results[0].default_accepted);
    for (key, value) in [
        ("status", serde_json::to_value(&status)),
        ("credentials", serde_json::to_value(&checks)),
    ] {
        assert_eq!(value.expect("encodes"), json[key], "{key} round-trips");
    }
}

#[test]
fn decodes_the_vpn_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::VpnStatus;
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/vpn.json")).expect("json");
    let status: VpnStatus = serde_json::from_value(json["status"].clone()).expect("status decodes");
    assert_eq!(status.state, "connected");
    assert_eq!(status.split_mode, "exclude");
    assert_eq!(status.auto_connected_on.as_deref(), Some("Cafe"));
    assert_eq!(serde_json::to_value(&status).expect("encodes"), json["status"]);
}

#[test]
fn decodes_the_posture_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::PostureStatus;
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/posture.json")).expect("json");
    let status: PostureStatus = serde_json::from_value(json["status"].clone()).expect("status decodes");
    assert_eq!(status.posture.as_ref().and_then(|p| p.score), Some(100));
    assert_eq!(status.encryption.as_ref().map(|e| e.state.as_str()), Some("on"));
    assert!(status.startup.iter().any(|s| s.is_new));
    assert_eq!(status.integrity.changes[0].kind, "modified");
    assert_eq!(status.usb.new_keyboards, 1);
    assert_eq!(serde_json::to_value(&status).expect("encodes"), json["status"]);
}

#[test]
fn decodes_the_privacy_fixture_written_by_the_typescript_tests() {
    use qalaa_ipc::PrivacyStatus;
    let json: serde_json::Value = serde_json::from_str(include_str!("fixtures/privacy.json")).expect("json");
    let status: PrivacyStatus = serde_json::from_value(json["status"].clone()).expect("status decodes");
    assert_eq!(status.locks.microphone, "blocked");
    assert_eq!(status.log[0].app, "zoom");
    assert!(status.web.as_ref().is_some_and(|w| w.vault.ends_with("/dashboard/passwords")));
    assert_eq!(serde_json::to_value(&status).expect("encodes"), json["status"]);
}
