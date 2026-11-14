"""Routes apply the permission matrix.

The matrix tests prove the policy; these prove the routes ask it. The specific
regression: an L1 could open, rewrite and close a ticket assigned to an L2,
because the edit and close routes only checked "is it not closed?".
"""

import pytest
from fastapi.testclient import TestClient

from sentriq import models
from sentriq.auth import hash_password
from sentriq.models import Alert, AuditLog, User
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
        User(username="l2", password_hash=hash_password("Password123!"), role="L2"),
    ])
    db.commit()

    l1 = db.query(User).filter_by(username="l1").one()
    l2 = db.query(User).filter_by(username="l2").one()
    db.add_all([
        Alert(alert_id="#1", title="L1's own ticket", status="WIP", analyst="l1", assigned_to=l1),
        Alert(alert_id="#2", title="L2's ticket", status="WIP", analyst="l2", assigned_to=l2),
        Alert(alert_id="#3", title="Nobody's ticket", status="Open", analyst="Unassigned"),
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


def sign_in(client, username, password="Password123!"):
    return client.post("/login/", data={
        "username": username, "password": password, "csrf_token": csrf(client),
    })


def alert_id(sessions, ref):
    db = sessions()
    try:
        return db.query(Alert).filter_by(alert_id=ref).one().id
    finally:
        db.close()


def audit_actions(sessions):
    db = sessions()
    try:
        return [row.action for row in db.query(AuditLog).all()]
    finally:
        db.close()


# --------------------------------------------------------------- L1 boundaries

def test_l1_cannot_edit_another_analysts_ticket(client, sessions):
    sign_in(client, "l1")
    response = client.post(
        f"/alerts/{alert_id(sessions, '#2')}/edit/",
        data={"csrf_token": csrf(client, "/alerts/"), "title": "rewritten", "severity": "Critical", "sla_hours": "8"},
    )
    assert response.status_code == 403


def test_l1_cannot_open_the_edit_form_for_another_analysts_ticket(client, sessions):
    sign_in(client, "l1")
    assert client.get(f"/alerts/{alert_id(sessions, '#2')}/edit/").status_code == 403


def test_l1_cannot_close_another_analysts_ticket(client, sessions):
    sign_in(client, "l1")
    response = client.post(
        f"/alerts/{alert_id(sessions, '#2')}/close/",
        data={"csrf_token": csrf(client, "/alerts/"), "resolution_summary": "closed by the wrong tier"},
    )
    assert response.status_code == 403


def test_l1_cannot_change_the_status_of_another_analysts_ticket(client, sessions):
    sign_in(client, "l1")
    response = client.post(
        f"/alerts/{alert_id(sessions, '#2')}/status/",
        data={"csrf_token": csrf(client, "/alerts/"), "status": "Pending"},
    )
    assert response.status_code == 403


def test_l1_can_still_work_their_own_ticket(client, sessions):
    sign_in(client, "l1")
    token = csrf(client, "/alerts/")
    own = alert_id(sessions, "#1")
    assert client.post(f"/alerts/{own}/edit/", data={
        "csrf_token": token, "title": "L1 refined it", "severity": "High", "sla_hours": "8",
    }).status_code == 303
    assert client.post(f"/alerts/{own}/close/", data={
        "csrf_token": token, "resolution_summary": "False positive, closed by the owner",
    }).status_code == 303


def test_l1_takes_an_unassigned_ticket_before_working_it(client, sessions):
    """An unassigned ticket is nobody's until someone takes it, and taking it
    is what puts a name in the timeline."""
    sign_in(client, "l1")
    token = csrf(client, "/alerts/")
    unassigned = alert_id(sessions, "#3")
    assert client.get(f"/alerts/{unassigned}/edit/").status_code == 403
    assert client.post(f"/alerts/{unassigned}/take/", data={"csrf_token": token}).status_code == 303
    assert client.get(f"/alerts/{unassigned}/edit/").status_code == 200


# ------------------------------------------------------------ higher tiers

def test_l2_can_close_an_l1_ticket(client, sessions):
    sign_in(client, "l2")
    response = client.post(
        f"/alerts/{alert_id(sessions, '#1')}/close/",
        data={"csrf_token": csrf(client, "/alerts/"), "resolution_summary": "Handled by L2"},
    )
    assert response.status_code == 303


def test_l1_cannot_assign_or_merge(client, sessions):
    sign_in(client, "l1")
    token = csrf(client, "/alerts/")
    own = alert_id(sessions, "#1")
    assert client.post(f"/alerts/{own}/assign/", data={"csrf_token": token, "assigned_to": "2"}).status_code == 403
    assert client.post(f"/alerts/{own}/merge/", data={"csrf_token": token, "target_alert_id": "#2"}).status_code == 403


# ------------------------------------------------------------ audited export

def test_csv_export_is_written_to_the_audit_trail(client, sessions):
    """A CSV leaves with every matching row; the trail has to say who pulled it."""
    sign_in(client, "l1")
    response = client.get("/alerts/export.csv")
    assert response.status_code == 200
    assert response.text.count("\n") >= 3

    db = sessions()
    try:
        row = db.query(AuditLog).filter(AuditLog.action == "alert.exported").one()
        assert "exported 3 ticket" in row.message
        assert "no filters" in row.message
        assert row.target_id == "3"
        assert row.actor.username == "l1"
        assert row.source_ip == "127.0.0.1"
    finally:
        db.close()


def test_the_export_audit_row_records_the_filter(client, sessions):
    sign_in(client, "l1")
    assert client.get("/alerts/export.csv?status=WIP&severity=High").status_code == 200
    db = sessions()
    try:
        row = db.query(AuditLog).filter(AuditLog.action == "alert.exported").one()
        assert "status=WIP" in row.message
        assert "severity=High" in row.message
    finally:
        db.close()
