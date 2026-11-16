from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import PASSWORD, sign_up

AUTH = "/api/v1/auth"


def test_register_starts_a_session_and_hides_the_password(client: TestClient) -> None:
    response = client.post(
        f"{AUTH}/register", json={"email": "Amira@Example.com", "password": PASSWORD}
    )
    assert response.status_code == 201
    assert response.json()["user"]["email"] == "amira@example.com"
    assert "password" not in response.text
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie

    assert client.get(f"{AUTH}/session").json()["user"]["email"] == "amira@example.com"


def test_weak_passwords_are_rejected(client: TestClient) -> None:
    for password in ("short", "aaaaaaaaaaaa"):
        response = client.post(
            f"{AUTH}/register", json={"email": "a@example.com", "password": password}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"


def test_duplicate_email_is_reported(client: TestClient) -> None:
    sign_up(client)
    response = TestClient(app).post(
        f"{AUTH}/register", json={"email": "AMIRA@example.com", "password": PASSWORD}
    )
    assert response.status_code == 409


def test_login_failure_does_not_reveal_whether_the_account_exists(client: TestClient) -> None:
    sign_up(client)
    fresh = TestClient(app)
    wrong_password = fresh.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": "not the password"}
    )
    unknown_account = fresh.post(
        f"{AUTH}/login", json={"email": "nobody@example.com", "password": "not the password"}
    )
    assert wrong_password.status_code == unknown_account.status_code == 401
    assert wrong_password.json() == unknown_account.json()


def test_login_and_logout(client: TestClient) -> None:
    sign_up(client)
    other = TestClient(app)
    login = other.post(f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD})
    assert login.status_code == 200

    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert other.post(f"{AUTH}/logout", headers=headers).status_code == 204
    assert other.get(f"{AUTH}/session").status_code == 401


def test_state_changing_requests_need_the_csrf_token(client: TestClient) -> None:
    sign_up(client)
    without_token = client.patch("/api/v1/user/settings", json={"display_name": "Amira"})
    assert without_token.status_code == 403
    assert without_token.json()["error"]["code"] == "csrf_failed"

    forged = client.patch(
        "/api/v1/user/settings", json={"display_name": "x"}, headers={"X-CSRF-Token": "guess"}
    )
    assert forged.status_code == 403


def test_invalid_session_cookie_is_treated_as_signed_out(client: TestClient) -> None:
    client.cookies.set("sentinel_session", "forged-token")
    assert client.get(f"{AUTH}/session").status_code == 401
    assert client.get("/api/v1/scans/history").status_code == 401


def test_repeated_login_attempts_are_rate_limited(client: TestClient) -> None:
    sign_up(client)
    attempts = [
        TestClient(app).post(
            f"{AUTH}/login", json={"email": "amira@example.com", "password": "wrong password"}
        )
        for _ in range(9)
    ]
    assert [r.status_code for r in attempts[:8]] == [401] * 8
    assert attempts[8].status_code == 429
    assert int(attempts[8].headers["retry-after"]) > 0


def test_sql_injection_in_login_is_just_a_wrong_email(client: TestClient) -> None:
    sign_up(client)
    response = client.post(
        f"{AUTH}/login", json={"email": "' OR 1=1 --@example.com", "password": PASSWORD}
    )
    assert response.status_code in (401, 422)


def test_changing_password_signs_out_other_devices(client: TestClient) -> None:
    headers = sign_up(client)
    other = TestClient(app)
    other.post(f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD})

    changed = client.post(
        "/api/v1/user/password",
        json={"current_password": PASSWORD, "new_password": "a brand new passphrase"},
        headers=headers,
    )
    assert changed.status_code == 204
    assert other.get(f"{AUTH}/session").status_code == 401
    assert client.get(f"{AUTH}/session").status_code == 200
