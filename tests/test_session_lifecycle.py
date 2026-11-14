"""Session lifecycle: idle expiry, the absolute deadline, and revocation.

A signed cookie cannot be un-signed, so these tests are about the two deadlines
carried inside it and about the epoch that makes a copied cookie useless the
moment the account signs out.
"""

import time

import pytest
from fastapi.testclient import TestClient

from sentriq import auth, models
from sentriq.auth import (
    LEGACY_PASSWORD_ITERATIONS,
    hash_password,
    session_stamp,
    signer,
    verify_password,
)
from sentriq.config import PASSWORD_ITERATIONS
from sentriq.models import User
from tests.support import make_session_factory


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add_all([
        User(username="admin_l3", password_hash=hash_password("AdminPass123!"), role="L3", is_admin=True),
        User(username="l1", password_hash=hash_password("Password123!"), role="L1"),
    ])
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def csrf(client, path="/login/"):
    client.get(path)
    return client.cookies.get("csrf_token")


def sign_in(client, username, password):
    return client.post("/login/", data={
        "username": username, "password": password, "csrf_token": csrf(client),
    })


def user_id(sessions, username):
    db = sessions()
    try:
        return db.query(User).filter_by(username=username).one().id
    finally:
        db.close()


def cookie_for(sessions, username, *, revocation_offset=0, seen_offset=0, iat_offset=0):
    """A session cookie for that account, with the timestamps under control."""
    db = sessions()
    try:
        user = db.query(User).filter_by(username=username).one()
        now = int(time.time())
        payload = {
            "user_id": user.id,
            "session_stamp": session_stamp(user),
            "epoch": int(user.session_epoch or 0) + revocation_offset,
            "iat": now + iat_offset,
            "seen": now + seen_offset,
        }
    finally:
        db.close()
    return signer.dumps(payload)


def test_a_live_session_is_accepted(client, sessions):
    client.cookies.set("session", cookie_for(sessions, "l1"))
    assert client.get("/alerts/").status_code == 200


def test_an_idle_session_is_refused(client, sessions):
    """Thirty minutes without a request ends the session, cookie or not."""
    client.cookies.set("session", cookie_for(sessions, "l1", seen_offset=-3600))
    assert client.get("/alerts/").status_code == 303


def test_an_active_session_still_ends_at_the_absolute_deadline(client, sessions):
    """Activity slides the idle window; it must not slide the absolute one."""
    client.cookies.set("session", cookie_for(sessions, "l1", iat_offset=-9 * 3600))
    assert client.get("/alerts/").status_code == 303


def test_a_cookie_from_before_a_revocation_is_refused(client, sessions):
    client.cookies.set("session", cookie_for(sessions, "l1"))
    assert client.get("/alerts/").status_code == 200
    db = sessions()
    try:
        user = db.query(User).filter_by(username="l1").one()
        user.session_epoch = int(user.session_epoch or 0) + 1
        db.commit()
    finally:
        db.close()
    assert client.get("/alerts/").status_code == 303


def test_signing_out_revokes_the_cookie_it_just_used(client, sessions):
    """A copied cookie must stop working when the analyst signs out."""
    assert sign_in(client, "l1", "Password123!").status_code == 303
    stolen = client.cookies.get("session")
    client.post("/logout/", data={"csrf_token": csrf(client, "/alerts/")})

    replay = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    replay.cookies.set("session", stolen)
    assert replay.get("/alerts/").status_code == 303


def test_an_administrator_can_sign_an_account_out_everywhere(client, sessions):
    victim = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50001))
    assert sign_in(victim, "l1", "Password123!").status_code == 303
    assert victim.get("/alerts/").status_code == 200

    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50002))
    assert sign_in(admin, "admin_l3", "AdminPass123!").status_code == 303
    revoked = admin.post(
        f"/admin/users/{user_id(sessions, 'l1')}/sessions/",
        data={"csrf_token": csrf(admin, "/admin/users/")},
    )
    assert revoked.status_code == 303
    # The victim's cookie is intact in the jar and still refused.
    assert victim.get("/alerts/").status_code == 303
    # The administrator's own session is untouched.
    assert admin.get("/admin/users/").status_code == 200


def test_a_role_change_ends_the_account_sessions(client, sessions):
    victim = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50003))
    assert sign_in(victim, "l1", "Password123!").status_code == 303

    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50004))
    assert sign_in(admin, "admin_l3", "AdminPass123!").status_code == 303
    admin.post(
        f"/admin/users/{user_id(sessions, 'l1')}/role/",
        data={"role": "L2", "csrf_token": csrf(admin, "/admin/users/")},
    )
    assert victim.get("/alerts/").status_code == 303


# ---------------------------------------------------------------------------
# Sign-in behaviour that shares the session code path
# ---------------------------------------------------------------------------

def test_a_legacy_password_hash_is_upgraded_on_sign_in(client, sessions):
    db = sessions()
    try:
        user = db.query(User).filter_by(username="l1").one()
        user.password_hash = hash_password("Password123!", iterations=LEGACY_PASSWORD_ITERATIONS)
        db.commit()
    finally:
        db.close()

    assert sign_in(client, "l1", "Password123!").status_code == 303

    db = sessions()
    try:
        stored = db.query(User).filter_by(username="l1").one().password_hash
    finally:
        db.close()
    assert stored.startswith(f"pbkdf2_sha256${PASSWORD_ITERATIONS}$")
    assert verify_password("Password123!", stored) is True


def test_an_unknown_username_still_costs_a_password_hash(client, sessions, monkeypatch):
    """Otherwise response time alone tells an attacker which accounts exist."""
    calls = []
    real = auth.dummy_password_hash

    def spy():
        calls.append(1)
        return real()

    monkeypatch.setattr(auth, "dummy_password_hash", spy)
    from sentriq.routes import auth_routes
    monkeypatch.setattr(auth_routes, "dummy_password_hash", spy)

    assert sign_in(client, "no-such-analyst", "whatever").status_code == 200
    assert calls, "an unknown username skipped the dummy hash and returned early"


def test_a_deactivated_account_gets_the_same_answer_as_an_unknown_one(client, sessions):
    """No "this account is disabled" hint, and no lockout counter burned on it."""
    db = sessions()
    try:
        user = db.query(User).filter_by(username="l1").one()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    response = sign_in(client, "l1", "Password123!")
    assert response.status_code == 200
    assert "Invalid username or password" in response.text
