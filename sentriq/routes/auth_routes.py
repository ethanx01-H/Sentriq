"""Authentication routes (login, logout)."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (
    UserDep,
    current_user,
    dummy_password_hash,
    hash_password,
    needs_rehash,
    session_payload,
    set_session_cookie,
    validate_password_strength,
    verify_password,
)
from ..config import LOGIN_LOCKOUT_SECONDS, PASSWORD_ITERATIONS, cookie_name
from ..dependencies import get_db
from ..middleware import clear_failed_logins, is_login_locked, record_failed_login
from ..models import AuditLog, User
from ..net import client_ip
from ..utils import audit, flash, redirect_to, render

logger = logging.getLogger("sentriq.auth_routes")

router = APIRouter()


@router.get("/login/", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "registration/login.html", {"error": None}, db)


@router.post("/login/")
def login(request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()], db: Session = Depends(get_db)):
    source_ip = client_ip(request)

    # Lockout is scoped to this (address, username) pair plus the account itself,
    # so one analyst's failed attempts cannot lock the whole team out behind a proxy.
    if is_login_locked(source_ip, username):
        logger.warning("Login lockout triggered for '%s' from %s", username, source_ip)
        response = render(request, "registration/login.html", {"error": "Too many failed attempts. Try again later."}, db, None)
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        response.headers["Retry-After"] = str(LOGIN_LOCKOUT_SECONDS)
        return response

    user = db.scalar(select(User).where(User.username == username))
    # Verify against a throwaway hash when the account does not exist, so an
    # unknown username costs the same as a real one and cannot be picked out by
    # response time.
    password_ok = verify_password(password, user.password_hash if user else dummy_password_hash())

    if user and not user.is_active:
        # Deactivated accounts are refused before the session is created, and are
        # not counted toward the lockout: the account is already disabled.
        db.add(AuditLog(
            actor=None,
            action="auth.login_inactive",
            message=f"Rejected sign-in for deactivated account '{username}'.",
            target_type="user",
            target_id=username,
            source_ip=source_ip,
        ))
        db.commit()
        logger.warning("Sign-in attempt for deactivated account '%s' from %s", username, source_ip)
        return render(request, "registration/login.html", {"error": "Invalid username or password."}, db)

    if not user or not password_ok:
        record_failed_login(source_ip, username)
        db.add(AuditLog(
            actor=user,
            action="auth.login_failed",
            message=f"Failed login attempt for '{username}'.",
            target_type="user",
            target_id=username,
            source_ip=source_ip,
        ))
        db.commit()
        logger.info("Failed login attempt for '%s' from %s", username, source_ip)
        return render(request, "registration/login.html", {"error": "Invalid username or password."}, db)

    # Clear only this pair's counters on success.
    clear_failed_logins(source_ip, username)
    if needs_rehash(user.password_hash):
        # The cost was raised since this password was set. Rewrite it now, while
        # the plaintext is in hand, and before the cookie is signed: the session
        # stamp is derived from the hash.
        user.password_hash = hash_password(password)
        logger.info("Upgraded password hash for '%s' to %s iterations", user.username, PASSWORD_ITERATIONS)
    response = redirect_to("/")
    set_session_cookie(response, session_payload(user))
    db.add(AuditLog(
        actor=user,
        action="auth.login",
        message=f"{user.username} logged in.",
        target_type="user",
        target_id=user.username,
        source_ip=source_ip,
    ))
    db.commit()
    logger.info("User '%s' logged in from %s", user.username, source_ip)
    return response


@router.post("/logout/")
def logout(request: Request, db: Session = Depends(get_db)):
    """Sign out, and revoke every session this account holds.

    Clearing the cookie is not revocation: a copied cookie would keep working
    until it expired. Bumping the epoch invalidates every cookie issued before
    now, including the one on a stolen laptop. The cost is that signing out ends
    the same account's other open tabs too.
    """
    user = current_user(request, db)
    if user:
        user.session_epoch = int(user.session_epoch or 0) + 1
        audit(db, user, "auth.logout", f"{user.username} signed out.", "user", user.username, request)
        db.commit()
    response = redirect_to("/login/")
    response.delete_cookie(cookie_name("session"))
    return response


@router.get("/account/password/", response_class=HTMLResponse)
def password_page(request: Request, user: UserDep, db: Session = Depends(get_db)):
    return render(request, "account/password.html", {"error": None}, db, user)


@router.post("/account/password/")
def password_change(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    if not verify_password(current_password, user.password_hash):
        return render(request, "account/password.html", {"error": "Current password is incorrect."}, db, user)
    error = validate_password_strength(new_password)
    if error:
        return render(request, "account/password.html", {"error": error}, db, user)
    if new_password != confirm_password:
        return render(request, "account/password.html", {"error": "New passwords do not match."}, db, user)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    # Changing the password already invalidates every session through the stamp;
    # the epoch bump makes that revocation explicit and survives a stamp collision.
    user.session_epoch = int(user.session_epoch or 0) + 1
    audit(db, user, "auth.password_changed", f"{user.username} changed their password.", "user", user.username, request)
    db.commit()
    response = redirect_to("/login/", "Password changed. Sign in with your new password.")
    response.delete_cookie(cookie_name("session"))
    return response
