"""Authentication, password hashing, and RBAC utilities."""

import logging
import hmac
import re
import secrets
import time
from hashlib import pbkdf2_hmac, sha256
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from .config import (
    COOKIE_SECURE,
    LEGACY_PASSWORD_ITERATIONS,
    PASSWORD_ITERATIONS,
    SECRET_KEY,
    SESSION_IDLE_SECONDS,
    SESSION_REFRESH_SECONDS,
    SESSION_TTL_SECONDS,
    cookie_name,
)
from .dependencies import get_db
from .models import User

logger = logging.getLogger("sentriq.auth")

signer = URLSafeTimedSerializer(SECRET_KEY, salt="sentriq")


def session_stamp(user: User) -> str:
    """Tie sessions to the current password hash without exposing that hash in cookies."""
    return hmac.new(SECRET_KEY.encode(), user.password_hash.encode(), sha256).hexdigest()


def hash_password(password: str, salt: str | None = None, iterations: int | None = None) -> str:
    """Hash a password with PBKDF2-SHA256, recording the cost inside the hash.

    The iteration count is part of the stored string, so raising it later does
    not lock anyone out: old hashes keep verifying at their own cost and are
    rewritten the next time their owner signs in (see ``needs_rehash``).
    """
    iterations = iterations or PASSWORD_ITERATIONS
    salt = salt or secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def _parse_hash(stored: str) -> tuple[int, str, str] | None:
    """Return (iterations, salt, digest), accepting the pre-0011 three-part form."""
    parts = (stored or "").split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        try:
            return int(parts[1]), parts[2], parts[3]
        except ValueError:
            return None
    if len(parts) == 3 and parts[0] == "pbkdf2_sha256":
        # Written before the cost was recorded; 240k was the only value.
        return LEGACY_PASSWORD_ITERATIONS, parts[1], parts[2]
    return None


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash using timing-safe comparison."""
    parsed = _parse_hash(stored_hash)
    if parsed is None:
        return False
    iterations, salt, digest = parsed
    candidate = pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return secrets.compare_digest(candidate, digest)


def needs_rehash(stored_hash: str) -> bool:
    """True when this hash was written with a different cost than we use now."""
    parsed = _parse_hash(stored_hash)
    return parsed is None or parsed[0] != PASSWORD_ITERATIONS


_dummy_hash: str | None = None


def dummy_password_hash() -> str:
    """A throwaway hash to verify against when the account does not exist.

    Without it, an unknown username returns in about 10 ms while a real one
    costs a full PBKDF2 round — a 15x timing difference that turns a wordlist
    into a confirmed list of analyst accounts. Computed once per process.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(16))
    return _dummy_hash


def validate_password_strength(password: str) -> str | None:
    """Validate password meets complexity requirements. Returns error message or None."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include a symbol."
    return None


def session_payload(user: User, issued_at: int | None = None, seen_at: int | None = None) -> dict:
    """The signed cookie body: who, which password, which epoch, and when.

    ``iat`` is the absolute deadline's anchor and is carried forward unchanged
    when the cookie is re-issued; ``seen`` is the idle clock and moves.
    """
    now = int(time.time())
    return {
        "user_id": user.id,
        "session_stamp": session_stamp(user),
        "epoch": int(user.session_epoch or 0),
        "iat": now if issued_at is None else int(issued_at),
        "seen": now if seen_at is None else int(seen_at),
    }


def set_session_cookie(response, payload: dict) -> None:
    """Write the session cookie with the flags a domain deployment needs."""
    response.set_cookie(
        cookie_name("session"),
        signer.dumps(payload),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )


def current_user(request: Request, db: Session) -> User | None:
    """Get current user from session cookie, or None if not authenticated."""
    raw = request.cookies.get(cookie_name("session"))
    if not raw:
        return None
    try:
        data = signer.loads(raw)
    except BadSignature:
        return None
    if not isinstance(data, dict):
        return None

    now = int(time.time())
    issued_at = data.get("iat")
    seen_at = data.get("seen")
    # Two deadlines: the absolute one from sign-in, and the idle one from the
    # last request. A cookie that predates either field is from the old format
    # and is treated as expired, which is the safe reading.
    if not isinstance(issued_at, int) or now - issued_at > SESSION_TTL_SECONDS:
        return None
    if not isinstance(seen_at, int) or now - seen_at > SESSION_IDLE_SECONDS:
        return None

    user = db.get(User, data.get("user_id"))
    if not user or not user.is_active:
        # A deactivated account loses its existing sessions on the next request.
        return None
    if int(data.get("epoch") or 0) != int(user.session_epoch or 0):
        # An administrator revoked this account's sessions, or its password or
        # role changed since this cookie was issued.
        return None
    if not hmac.compare_digest(data.get("session_stamp", ""), session_stamp(user)):
        return None

    if now - seen_at >= SESSION_REFRESH_SECONDS:
        # Slide the idle window. The absolute deadline rides in "iat" and does
        # not move, so activity alone cannot keep a session alive all day.
        request.state.session_refresh = session_payload(user, issued_at=issued_at, seen_at=now)
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency that requires authentication. Redirects to login if not authenticated."""
    user = current_user(request, db)
    if user:
        if user.must_change_password and request.url.path != "/account/password/":
            raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/account/password/"})
        return user
    raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login/"})


def user_role(user: User) -> str:
    """Get effective role (L3 for admins)."""
    return "L3" if user.is_admin else user.role


def can_create_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2", "L3"}


def can_edit_alert(user: User, alert) -> bool:
    role = user_role(user)
    return role in {"L2", "L3"} or (role == "L1" and alert.status != "Closed")


def can_delete_alert(user: User) -> bool:
    return user_role(user) == "L3"


def can_manage_users(user: User) -> bool:
    return user_role(user) == "L3"


def can_escalate_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2"}


def can_assign_alert(user: User) -> bool:
    return user_role(user) in {"L2", "L3"}


def assignable_roles_for(user: User) -> list[str]:
    """Get list of roles this user can assign alerts to."""
    role = user_role(user)
    if role == "L3":
        return ["L1", "L2"]
    if role == "L2":
        return ["L1"]
    return []


UserDep = Annotated[User, Depends(require_user)]
