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
