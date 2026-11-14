"""Evidence download and image preview routes.

Evidence is attached when the alert is created (see routes/alert_routes.py); this
module only serves what is already stored, so there is no way to add a file to an
existing ticket.

Every read of an evidence file is written to the audit trail. Chain of custody is
the question a bank asks after an incident — "who pulled this packet capture, and
when" — and it cannot be answered from a mutable row that only records uploads.
"""

import logging
import re
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..auth import UserDep
from ..config import UPLOAD_DIR
from ..dependencies import get_db
from ..models import Alert, Evidence
from ..services.evidence_security import EvidenceError, derive_media_type, unseal, verify_digest
from ..utils import audit

logger = logging.getLogger("sentriq.evidence_routes")

router = APIRouter()


def _stored_path(evidence: Evidence) -> Path:
    path = UPLOAD_DIR / evidence.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    return path


def content_disposition(disposition: str, filename: str) -> str:
    """Build a header value that cannot break out of the quoted filename.

    The original name is analyst-supplied, so quotes and line breaks are stripped,
    a plain ASCII fallback is offered to old clients, and the real name rides in
    ``filename*`` (RFC 5987) for everything that understands UTF-8.
    """
    cleaned = re.sub(r'[\r\n"\\]', "", filename or "") or "evidence"
    fallback = cleaned.encode("ascii", "ignore").decode().strip() or "evidence"
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(cleaned)}"


def _record_read(db: Session, user, evidence: Evidence, action: str, request: Request) -> None:
    """Audit an evidence read, with the hash so the copy can be tied to the file."""
    audit(
        db, user, action,
        f"{user.username} read {evidence.original_name} "
        f"({evidence.size_bytes} bytes, sha256 {evidence.sha256[:16]}…) "
        f"from alert #{evidence.alert_id}.",
        "evidence", str(evidence.id), request,
    )
    db.commit()


def _record_integrity_failure(db: Session, user, evidence: Evidence, request: Request, detail: str) -> None:
    """A file that no longer matches its hash is an incident, not a 500."""
    audit(
        db, user, "evidence.integrity_failed",
        f"Refused to serve {evidence.original_name} from alert #{evidence.alert_id}: {detail}. "
        f"Recorded sha256 {evidence.sha256}.",
        "evidence", str(evidence.id), request,
    )
    db.commit()
    logger.error("Evidence integrity failure for id=%s (%s): %s", evidence.id, evidence.stored_name, detail)


def _read_verified(db: Session, user, evidence: Evidence, request: Request) -> bytes:
    """Read the file, decrypt it, and refuse anything that fails its own hash."""
    raw = _stored_path(evidence).read_bytes()
    try:
        content = unseal(raw, evidence.stored_name)
    except EvidenceError as error:
        _record_integrity_failure(db, user, evidence, request, str(error))
        raise HTTPException(status_code=409, detail=str(error))
    if not verify_digest(content, evidence.sha256):
        detail = "the file no longer hashes to the value recorded at upload"
        _record_integrity_failure(db, user, evidence, request, detail)
        raise HTTPException(
            status_code=409,
            detail="This evidence file does not match the hash recorded when it was "
                   "uploaded, so it was not served. The mismatch has been written to "
                   "the audit trail.",
        )
    return content


@router.get("/evidence/{evidence_id}/")
def evidence_download(evidence_id: int, request: Request, user: UserDep, db: Session = Depends(get_db)):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    if not db.get(Alert, evidence.alert_id):
        raise HTTPException(status_code=404)
    content = _read_verified(db, user, evidence, request)
    _record_read(db, user, evidence, "evidence.downloaded", request)
    return Response(
        content,
        # From the extension on disk, never from the type the uploader claimed.
        media_type=derive_media_type(evidence.stored_name),
        headers={
            "Content-Disposition": content_disposition("attachment", evidence.original_name),
            # Belt and braces for a file that is opened rather than saved: no
            # scripts, no same-origin privileges, no MIME sniffing.
            "Content-Security-Policy": "sandbox",
            "X-Download-Options": "noopen",
        },
    )


@router.get("/evidence/{evidence_id}/preview/")
def evidence_preview(evidence_id: int, request: Request, user: UserDep, db: Session = Depends(get_db)):
    """Serve an image inline so the ticket can show it in a popup.

    The media type comes from the extension, not from the stored upload header:
    the browser must never be told to interpret analyst-supplied bytes as
    anything other than an image.
    """
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    if not evidence.is_image:
        raise HTTPException(status_code=404)
    content = _read_verified(db, user, evidence, request)
    _record_read(db, user, evidence, "evidence.previewed", request)
    return Response(
        content,
        media_type=derive_media_type(evidence.stored_name),
        headers={
            "Content-Disposition": content_disposition("inline", evidence.original_name),
            "Content-Security-Policy": "sandbox",
            "Cache-Control": "private, max-age=300",
        },
    )
