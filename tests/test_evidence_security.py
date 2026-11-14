"""Evidence: served as what it is, checked for integrity, scanned, sealed.

Each of these was a gap: the download answered with the uploader's claimed
Content-Type, the stored SHA-256 was never checked again, nothing looked at the
bytes for malware, and the evidence directory was plaintext on a share.
"""

import hashlib
import pathlib

import pytest
from fastapi.testclient import TestClient

from sentriq import config, models
from sentriq.auth import hash_password
from sentriq.models import Alert, AuditLog, Evidence, User
from sentriq.routes import evidence_routes
from sentriq.services import evidence_security
from sentriq.services.evidence_security import MAGIC, derive_media_type

from tests.support import make_session_factory

KEY_A = "a" * 64
KEY_B = "b" * 64


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add(User(username="l1", password_hash=hash_password("Password123!"), role="L1"))
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def sign_in(client):
    client.get("/login/")
    client.post("/login/", data={
        "username": "l1", "password": "Password123!", "csrf_token": client.cookies.get("csrf_token"),
    })
    return client.cookies.get("csrf_token")


def upload(client, csrf, name, content, content_type):
    return client.post(
        "/alerts/new/",
        data={"csrf_token": csrf, "title": "Evidence probe", "description": "probe",
              "severity": "Low", "sla_hours": "8"},
        files=[("evidence_files", (name, content, content_type))],
    )


def stored_path(tmp_path, sessions):
    db = sessions()
    try:
        evidence = db.query(Evidence).one()
        return pathlib.Path(evidence_routes.UPLOAD_DIR) / evidence.stored_name, evidence
    finally:
        db.close()


# ------------------------------------------------------------------ serving type

def test_the_extension_decides_the_type_not_the_uploader(client, sessions):
    """A .txt uploaded as text/html must come back as text/plain."""
    csrf = sign_in(client)
    assert upload(client, csrf, "payload.txt", b"<html><script>alert(1)</script></html>", "text/html").status_code == 303

    download = client.get("/evidence/1/")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/plain")
    assert download.headers["content-disposition"].startswith("attachment")
    assert download.headers["content-security-policy"] == "sandbox"
    assert download.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("name,expected", [
    ("a.png", "image/png"),
    ("a.csv", "text/csv"),
    ("a.json", "application/json"),
    ("a.pcap", "application/vnd.tcpdump.pcap"),
    ("a.log", "text/plain"),
    ("a.unknownext", "application/octet-stream"),
])
def test_media_types_come_from_the_extension(name, expected):
    assert derive_media_type(name) == expected


# ------------------------------------------------------------------ integrity

def test_a_tampered_file_is_refused_and_audited(client, sessions, tmp_path):
    csrf = sign_in(client)
    upload(client, csrf, "notes.txt", b"original evidence", "text/plain")
    path, evidence = stored_path(tmp_path, sessions)

    path.write_bytes(b"something else entirely")

    response = client.get(f"/evidence/{evidence.id}/")
    assert response.status_code == 409
    assert "does not match the hash" in response.text

    db = sessions()
    try:
        row = db.query(AuditLog).filter(AuditLog.action == "evidence.integrity_failed").one()
        assert "no longer hashes" in row.message
        assert evidence.sha256 in row.message
    finally:
        db.close()


def test_the_recorded_hash_is_of_the_plaintext(client, sessions, tmp_path):
    csrf = sign_in(client)
    body = b"proxy log line\n"
    upload(client, csrf, "proxy.log", body, "text/plain")
    _, evidence = stored_path(tmp_path, sessions)
    assert evidence.sha256 == hashlib.sha256(body).hexdigest()


# ------------------------------------------------------------------ encryption at rest

def test_evidence_is_sealed_on_disk_and_readable_through_the_app(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_A)
    csrf = sign_in(client)
    body = b"the plaintext must not sit on the share"
    upload(client, csrf, "notes.txt", body, "text/plain")

    path, evidence = stored_path(tmp_path, sessions)
    on_disk = path.read_bytes()
    assert on_disk.startswith(MAGIC)
    assert body not in on_disk, "the plaintext was written to disk"

    response = client.get(f"/evidence/{evidence.id}/")
    assert response.status_code == 200
    assert response.content == body


def test_a_file_written_before_the_key_existed_still_opens(client, sessions, tmp_path, monkeypatch):
    csrf = sign_in(client)
    upload(client, csrf, "old.txt", b"plaintext from before", "text/plain")
    path, evidence = stored_path(tmp_path, sessions)
    assert not path.read_bytes().startswith(MAGIC)

    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_A)
    response = client.get(f"/evidence/{evidence.id}/")
    assert response.status_code == 200
    assert response.content == b"plaintext from before"


def test_the_wrong_key_is_refused_rather_than_served(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_A)
    csrf = sign_in(client)
    upload(client, csrf, "notes.txt", b"sealed with key A", "text/plain")
    _, evidence = stored_path(tmp_path, sessions)

    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_B)
    response = client.get(f"/evidence/{evidence.id}/")
    assert response.status_code == 409
    assert "could not be decrypted" in response.text


def test_swapping_one_file_for_another_is_caught_by_the_name_binding(client, sessions, tmp_path, monkeypatch):
    """Ciphertext is bound to its stored name, so a swap does not decrypt."""
    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_A)
    csrf = sign_in(client)
    upload(client, csrf, "one.txt", b"first file", "text/plain")
    path_one, evidence_one = stored_path(tmp_path, sessions)
    upload(client, csrf, "two.txt", b"second file", "text/plain")

    db = sessions()
    try:
        other = db.query(Evidence).filter(Evidence.id != evidence_one.id).one()
    finally:
        db.close()
    path_two = pathlib.Path(evidence_routes.UPLOAD_DIR) / other.stored_name
    path_one.write_bytes(path_two.read_bytes())

    assert client.get(f"/evidence/{evidence_one.id}/").status_code == 409


# ------------------------------------------------------------------ malware scan

def make_scanner(tmp_path, exit_code):
    scanner = tmp_path / f"scanner-{exit_code}.sh"
    scanner.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    scanner.chmod(0o755)
    return str(scanner)


def test_an_infected_file_is_refused_before_it_is_stored(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_SCAN_COMMAND", make_scanner(tmp_path, 1))
    csrf = sign_in(client)
    response = upload(client, csrf, "malware.txt", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "text/plain")

    assert response.status_code == 200
    assert "failed the malware scan" in response.text
    db = sessions()
    try:
        assert db.query(Evidence).count() == 0, "an infected file reached the evidence store"
        assert db.query(Alert).count() == 0, "the ticket was created anyway"
    finally:
        db.close()


def test_a_clean_file_passes_the_scanner(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_SCAN_COMMAND", make_scanner(tmp_path, 0))
    csrf = sign_in(client)
    assert upload(client, csrf, "clean.txt", b"nothing to see", "text/plain").status_code == 303
    db = sessions()
    try:
        assert db.query(Evidence).count() == 1
    finally:
        db.close()


def test_a_broken_scanner_does_not_block_uploads_by_default(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_SCAN_COMMAND", make_scanner(tmp_path, 2))
    monkeypatch.setattr(config, "EVIDENCE_SCAN_REQUIRED", False)
    csrf = sign_in(client)
    assert upload(client, csrf, "clean.txt", b"nothing to see", "text/plain").status_code == 303


def test_a_broken_scanner_blocks_uploads_when_the_deployment_requires_scanning(
    client, sessions, tmp_path, monkeypatch
):
    monkeypatch.setattr(config, "EVIDENCE_SCAN_COMMAND", make_scanner(tmp_path, 2))
    monkeypatch.setattr(config, "EVIDENCE_SCAN_REQUIRED", True)
    csrf = sign_in(client)
    response = upload(client, csrf, "clean.txt", b"nothing to see", "text/plain")
    assert response.status_code == 200
    assert "refuses unscanned evidence" in response.text


def test_a_missing_scanner_is_an_error_not_a_pass(client, sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_SCAN_COMMAND", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(config, "EVIDENCE_SCAN_REQUIRED", True)
    csrf = sign_in(client)
    response = upload(client, csrf, "clean.txt", b"nothing", "text/plain")
    assert response.status_code == 200
    assert "could not run" in response.text


def test_seal_and_unseal_round_trip(monkeypatch):
    monkeypatch.setattr(config, "EVIDENCE_ENCRYPTION_KEY", KEY_A)
    sealed = evidence_security.seal(b"hello", "file_1.txt")
    assert sealed.startswith(MAGIC)
    assert evidence_security.unseal(sealed, "file_1.txt") == b"hello"
