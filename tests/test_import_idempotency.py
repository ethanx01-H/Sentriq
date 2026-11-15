"""Re-importing the same external document must not double the tickets.

Nothing in the UI ingests Elastic exports any more, but create_or_get_alert
still deduplicates on external_id, and the unique index on that column is what
makes two workers importing at once safe. These tests keep that behaviour
honest, because the next thing to feed this app (a SIEM API, a playbook) will
lean on it.
"""

import pytest

from sentriq.models import Alert
from sentriq.services.alert_service import create_or_get_alert
from tests.support import make_session_factory


@pytest.fixture
def db(engine):
    session = make_session_factory(engine)()
    yield session
    session.close()


def record(external_id, title="Suspicious PowerShell", asset="WS-042"):
    values = {
        "title": title,
        "description": "",
        "severity": "High",
        "asset": asset,
        "tactic": "Execution",
        "iocs": [],
        "sla_hours": 8,
        "source": "logs-endpoint",
    }
    if external_id is not None:
        values["external_id"] = external_id
    return values


def import_records(db, records):
    """One loop, one commit, duplicates counted — the shape an ingest path has."""
    created = skipped = 0
    for item in records:
        _, is_new = create_or_get_alert(db, dict(item))
        if is_new:
            created += 1
        else:
            skipped += 1
    db.commit()
    return created, skipped


def test_replay_returns_the_existing_ticket(db):
    assert import_records(db, [record("logs-endpoint:doc-abc123")]) == (1, 0)

    assert import_records(db, [record("logs-endpoint:doc-abc123")]) == (0, 1)

    assert db.query(Alert).count() == 1
    assert db.query(Alert).one().external_id == "logs-endpoint:doc-abc123"


def test_distinct_documents_still_create_new_tickets(db):
    import_records(db, [record("logs-endpoint:doc-1")])
    import_records(db, [record("logs-endpoint:doc-2")])
    assert db.query(Alert).count() == 2


def test_a_record_without_an_identifier_cannot_be_deduplicated(db):
    # Nothing to match on: two ingests are two tickets, which is why the source
    # identifier is kept rather than dropped.
    import_records(db, [record(None)])
    import_records(db, [record(None)])
    assert db.query(Alert).count() == 2
    assert db.query(Alert).filter(Alert.external_id.isnot(None)).count() == 0


def test_mixed_batch_reports_created_and_skipped(db):
    import_records(db, [record("logs-endpoint:doc-1")])
    created, skipped = import_records(db, [record("logs-endpoint:doc-1"), record("logs-endpoint:doc-2")])
    assert (created, skipped) == (1, 1)
    assert db.query(Alert).count() == 2
