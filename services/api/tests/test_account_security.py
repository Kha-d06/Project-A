import re
import time

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.main import app
from app.models import OutboxEmail, User
from tests.conftest import PASSWORD, sign_up

AUTH = "/api/v1/auth"


@pytest.fixture
def outbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "email_backend", "outbox")


def last_link(db: Session, recipient: str) -> str:
    email = (
        db.query(OutboxEmail)
        .filter_by(recipient=recipient)
        .order_by(OutboxEmail.created_at.desc())
        .first()
    )
    assert email is not None
    match = re.search(r"token=([\w-]+)", email.body)
    assert match
    return match.group(1)


def test_email_features_are_off_without_a_mail_backend(client: TestClient) -> None:
    response = client.post(f"{AUTH}/password-reset", json={"email": "a@example.com"})
    assert response.json()["error"]["code"] == "email_unavailable"


def test_registration_sends_a_verification_link(
    client: TestClient, db: Session, outbox: None
) -> None:
    sign_up(client)
    token = last_link(db, "amira@example.com")
    assert client.post(f"{AUTH}/verify-email", json={"token": token}).status_code == 204
    assert client.get(f"{AUTH}/session").json()["user"]["email_verified_at"] is not None
    assert (
        client.post(f"{AUTH}/verify-email", json={"token": token}).status_code == 400
    )  # single use


def test_password_reset_flow(client: TestClient, db: Session, outbox: None) -> None:
    sign_up(client)
    stranger = TestClient(app)
    unknown = stranger.post(f"{AUTH}/password-reset", json={"email": "nobody@example.com"})
    known = stranger.post(f"{AUTH}/password-reset", json={"email": "amira@example.com"})
    assert unknown.json() == known.json()  # no account enumeration

    token = last_link(db, "amira@example.com")
    weak = stranger.post(
        f"{AUTH}/password-reset/confirm", json={"token": token, "new_password": "short"}
    )
    assert weak.status_code == 422
    done = stranger.post(
        f"{AUTH}/password-reset/confirm",
        json={"token": token, "new_password": "a new long passphrase"},
    )
    assert done.status_code == 204
    assert client.get(f"{AUTH}/session").json()["user"] is None  # old sessions revoked
    login = stranger.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": "a new long passphrase"}
    )
    assert login.status_code == 200
    reuse = stranger.post(
        f"{AUTH}/password-reset/confirm",
        json={"token": token, "new_password": "another long phrase"},
    )
    assert reuse.status_code == 400


def enable_two_factor(client: TestClient, headers: dict[str, str]) -> tuple[pyotp.TOTP, list[str]]:
    setup = client.post("/api/v1/user/2fa/setup", headers=headers).json()
    assert setup["qr_code"].startswith("data:image/png;base64,")
    assert "otpauth://totp/Qalaa" in setup["otpauth_uri"]
    totp = pyotp.TOTP(setup["secret"])
    wrong = client.post("/api/v1/user/2fa/enable", json={"code": "000000"}, headers=headers)
    assert wrong.status_code == 400
    enabled = client.post("/api/v1/user/2fa/enable", json={"code": totp.now()}, headers=headers)
    assert enabled.status_code == 200
    return totp, enabled.json()["backup_codes"]


def test_two_factor_sign_in(client: TestClient, db: Session) -> None:
    headers = sign_up(client)
    totp, backup_codes = enable_two_factor(client, headers)
    assert len(backup_codes) == 10
    stored = db.query(User).one().totp_secret_encrypted
    assert stored and totp.secret not in stored  # encrypted at rest

    other = TestClient(app)
    first = other.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD}
    ).json()
    assert first["two_factor_required"] is True
    assert other.get(f"{AUTH}/session").json()["user"] is None  # no session after password alone

    bad = other.post(
        f"{AUTH}/login/two-factor", json={"challenge": first["challenge"], "code": "123456"}
    )
    assert bad.status_code == 401
    # The code that turned 2FA on has been used (see test_authenticator_codes_work_once).
    next_code = totp.at(time.time() + 30)
    good = other.post(
        f"{AUTH}/login/two-factor", json={"challenge": first["challenge"], "code": next_code}
    )
    assert good.status_code == 200
    assert other.get(f"{AUTH}/session").json()["user"]["email"] == "amira@example.com"

    # A backup code works once.
    third = TestClient(app)
    challenge = third.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD}
    ).json()["challenge"]
    assert (
        third.post(
            f"{AUTH}/login/two-factor", json={"challenge": challenge, "code": backup_codes[0]}
        ).status_code
        == 200
    )
    fourth = TestClient(app)
    challenge = fourth.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD}
    ).json()["challenge"]
    assert (
        fourth.post(
            f"{AUTH}/login/two-factor", json={"challenge": challenge, "code": backup_codes[0]}
        ).status_code
        == 401
    )


def test_forged_or_expired_challenges_are_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = sign_up(client)
    enable_two_factor(client, headers)
    challenge = (
        TestClient(app)
        .post(f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD})
        .json()["challenge"]
    )
    user_id, expires, nonce, signature = challenge.split(".")
    extended = f"{user_id}.{int(expires) + 9999}.{nonce}.{signature}"
    assert (
        client.post(
            f"{AUTH}/login/two-factor", json={"challenge": extended, "code": "123456"}
        ).json()["error"]["code"]
        == "challenge_expired"
    )
    monkeypatch.setattr("app.api.account.time.time", lambda: int(expires) + 1)
    assert (
        client.post(
            f"{AUTH}/login/two-factor", json={"challenge": challenge, "code": "123456"}
        ).status_code
        == 401
    )


def test_two_factor_codes_are_rate_limited(client: TestClient) -> None:
    headers = sign_up(client)
    enable_two_factor(client, headers)  # one failed attempt during setup counts too
    attacker = TestClient(app)
    challenge = attacker.post(
        f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD}
    ).json()["challenge"]
    statuses = [
        attacker.post(
            f"{AUTH}/login/two-factor", json={"challenge": challenge, "code": f"{n:06d}"}
        ).status_code
        for n in range(6)
    ]
    assert 429 in statuses


def test_disabling_two_factor_needs_password_and_code(client: TestClient) -> None:
    headers = sign_up(client)
    totp, _ = enable_two_factor(client, headers)
    wrong = client.post(
        "/api/v1/user/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )
    assert wrong.status_code == 403
    ok = client.post(
        "/api/v1/user/2fa/disable",
        json={"password": PASSWORD, "code": totp.at(time.time() + 30)},
        headers=headers,
    )
    assert ok.status_code == 204
    assert client.get("/api/v1/user/security").json()["two_factor_enabled"] is False
    # Turning it straight back on with a new secret works: the old step is forgotten.
    enable_two_factor(client, headers)


def test_authenticator_codes_work_once(client: TestClient) -> None:
    """OWASP MFA: a code (time step) is accepted once, even by racing sign-ins,
    and never an older step after a newer one."""
    headers = sign_up(client)
    totp, _ = enable_two_factor(client, headers)  # uses the current step

    def attempt(code: str) -> int:
        session = TestClient(app)
        challenge = session.post(
            f"{AUTH}/login", json={"email": "amira@example.com", "password": PASSWORD}
        ).json()["challenge"]
        return session.post(
            f"{AUTH}/login/two-factor", json={"challenge": challenge, "code": code}
        ).status_code

    upcoming = totp.at(time.time() + 30)
    assert attempt(upcoming) == 200
    assert attempt(upcoming) == 401  # the same code again
    assert attempt(totp.now()) == 401  # an older step after a newer one


def test_totp_step_is_claimed_atomically(db: Session) -> None:
    """Two sign-ins checking the same code: only one UPDATE can claim the step."""
    from app.api.account import _use_totp

    user = User(email="race@example.com", password_hash="x")
    db.add(user)
    db.commit()
    totp = pyotp.TOTP(pyotp.random_base32())
    code = totp.now()
    assert _use_totp(db, user, totp, code) is True
    assert _use_totp(db, user, totp, code) is False
    assert _use_totp(db, user, totp, "000000" if code != "000000" else "111111") is False
