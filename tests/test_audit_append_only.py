"""The audit trail is append-only, and its export leaves the host.

Two separate promises: nothing in the application can rewrite a recorded action,
and the hash anchor is copied somewhere the database cannot reach.
"""

import json
import pathlib

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from sentriq.models import AuditLog
from sentriq.services import audit_export, audit_guard


@pytest.fixture
def audit_row(db):
    row = AuditLog(actor=None, action="test.action", message="recorded", target_type="test", target_id="1")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_inserting_an_audit_row_is_allowed(db, audit_row):
    assert db.query(AuditLog).count() == 1


def test_updating_an_audit_row_is_refused(db, audit_row):
    with pytest.raises(DBAPIError) as error:
        db.execute(text("update fastapi_audit_logs set message = 'rewritten' where id = :id"), {"id": audit_row.id})
        db.commit()
    db.rollback()
    assert "append-only" in str(error.value)
    assert db.get(AuditLog, audit_row.id).message == "recorded"


def test_deleting_an_audit_row_is_refused(db, audit_row):
    with pytest.raises(DBAPIError) as error:
        db.execute(text("delete from fastapi_audit_logs where id = :id"), {"id": audit_row.id})
        db.commit()
    db.rollback()
    assert "append-only" in str(error.value)
    assert db.get(AuditLog, audit_row.id) is not None


def test_truncating_the_trail_is_refused(db, audit_row):
    """A bulk delete is the obvious way to 'fix' a trail; it is refused too."""
    with pytest.raises(DBAPIError) as error:
        db.execute(text("truncate table fastapi_audit_logs"))
        db.commit()
    db.rollback()
    assert "append-only" in str(error.value)
    assert db.query(AuditLog).count() == 1


def test_the_guard_is_installed_and_reported(engine):
    report = audit_guard.report(engine)
    assert report["trigger_installed"] is True
    assert "sentriq_audit_append_only_row" in report["triggers"]
    assert "sentriq_audit_append_only_truncate" in report["triggers"]


def test_the_report_says_when_the_app_role_could_lift_the_guard(engine):
    """The trigger is the application's guard, not a DBA's: say so plainly."""
    report = audit_guard.report(engine)
    notes = audit_guard.advisory(report)
    if report["owns_table"]:
        assert any("owns fastapi_audit_logs" in note for note in notes)
    assert isinstance(notes, list)


# ---------------------------------------------------------------------------
# Export and off-host copy
# ---------------------------------------------------------------------------

def test_export_pushes_a_verified_copy_off_host(db, audit_row, tmp_path):
    export_dir = tmp_path / "exports"
    offhost = tmp_path / "offhost"
    result = audit_export.export(db, directory=export_dir)

    copied = audit_export.push(result, offhost)

    assert pathlib.Path(copied["file"]).exists()
    assert pathlib.Path(copied["file"]).with_suffix(".manifest.json").exists()
    anchor = pathlib.Path(f"{copied['file']}.head").read_text()
    assert copied["head"] in anchor
    assert "records=" in anchor
    # The copy verifies from the destination, not from the source.
    assert audit_export.verify(copied["file"])["ok"] is True


def test_a_tampered_copy_fails_verification(db, audit_row, tmp_path):
    result = audit_export.export(db, directory=tmp_path / "exports")
    copied = audit_export.push(result, tmp_path / "offhost")

    path = pathlib.Path(copied["file"])
    path.chmod(0o644)
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["record"]["message"] = "something the analyst never did"
    lines[0] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    check = audit_export.verify(path)
    assert check["ok"] is False
    assert check["broken_at"] == 1


def test_the_manifest_and_export_are_read_only(db, audit_row, tmp_path):
    result = audit_export.export(db, directory=tmp_path / "exports")
    for path in (result["path"], result["manifest"]):
        mode = pathlib.Path(path).stat().st_mode & 0o777
        assert mode == 0o444
