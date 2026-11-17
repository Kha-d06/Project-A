from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cli import create_admin
from app.main import app
from app.models import User

API = "/api/v1"


def test_create_admin_creates_promotes_and_can_sign_in(db: Session) -> None:
    assert create_admin(db, "Boss@Example.com", "short") == 1  # weak password refused
    assert create_admin(db, "Boss@Example.com", "first-admin-pass-1") == 0
    user = db.scalar(select(User).where(User.email == "boss@example.com"))
    assert user is not None
    assert user.role == "admin"
    assert user.assessment_enabled_at is not None
    assert user.email_verified_at is not None

    # Running it again resets the password and keeps the account.
    assert create_admin(db, "boss@example.com", "second-admin-pass-2") == 0
    assert db.scalars(select(User).where(User.email == "boss@example.com")).all().__len__() == 1

    client = TestClient(app)
    signed_in = client.post(
        f"{API}/auth/login", json={"email": "boss@example.com", "password": "second-admin-pass-2"}
    )
    assert signed_in.status_code == 200, signed_in.text
    assert signed_in.json()["user"]["role"] == "admin"
    assert signed_in.json()["user"]["assessment_enabled"] is True
