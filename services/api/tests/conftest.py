import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

_WORKDIR = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))

# Settings are read at import time, so the environment must be prepared first.
os.environ.update(
    {
        "SENTINEL_ENVIRONMENT": "test",
        "SENTINEL_DATABASE_URL": f"sqlite:///{_WORKDIR / 'test.db'}",
        "SENTINEL_RATE_LIMIT_BACKEND": "memory",
        "SENTINEL_RUN_SCANS_INLINE": "true",
        "SENTINEL_UPLOAD_DIR": str(_WORKDIR / "uploads"),
        "SENTINEL_SESSION_COOKIE_SECURE": "false",
        "SENTINEL_FEED_SYNC_ENABLED": "false",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.analyzers.safe_fetch import RedirectTrace  # noqa: E402
from app.core.db import get_engine, get_session_factory  # noqa: E402
from app.core.rate_limit import MemoryCounterStore, get_counter_store  # noqa: E402
from app.intel import providers  # noqa: E402
from app.intel.feeds import FeedIndicator, get_or_create_source, store_indicators  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from app.models.base import utcnow  # noqa: E402

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def clean_state() -> Iterator[None]:
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    store = get_counter_store()
    assert isinstance(store, MemoryCounterStore)
    store.reset()
    yield


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Analyzers must never touch the network in tests unless a test opts in."""

    def unreachable(url: str, read_final_body: bool = False) -> RedirectTrace:
        return RedirectTrace(stopped="connection_error", stopped_detail="network disabled in tests")

    def no_rdap(domain: str) -> None:
        raise providers.ProviderUnavailableError("network disabled in tests")

    monkeypatch.setattr("app.analyzers.url_scan.trace_redirects", unreachable)
    monkeypatch.setattr(providers, "domain_registration_date", no_rdap)


@pytest.fixture
def db() -> Iterator[Session]:
    with get_session_factory()() as session:
        yield session


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def upload_dir() -> Path:
    return _WORKDIR / "uploads"


def sign_up(client: TestClient, email: str = "amira@example.com") -> dict[str, str]:
    """Register an account on this client and return the headers mutating requests need."""
    response = client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD})
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def seed_feed(db: Session, key: str, indicators: list[FeedIndicator]) -> None:
    """Install a feed as though it had just synchronised successfully."""
    source = get_or_create_source(db, key, f"{key} test feed")
    source.indicator_count = store_indicators(db, source, indicators)
    source.last_success_at = utcnow()
    db.commit()
