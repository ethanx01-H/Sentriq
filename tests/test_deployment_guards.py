"""Deployment guards: the configuration refuses to start unsafe.

Every check here is a value that used to be accepted silently — a placeholder
signing key, a short key, no host allow-list, several workers without a shared
counter store, a non-Secure cookie. They are tested in a subprocess because
``sentriq.config`` reads the environment once, at import.
"""

import os
import pathlib
import subprocess
import sys

from sentriq.auth import (
    LEGACY_PASSWORD_ITERATIONS,
    hash_password,
    needs_rehash,
    verify_password,
)
from sentriq.config import PASSWORD_ITERATIONS
from tests.support import server_uri

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_config(**overrides):
    """Import sentriq.config in a subprocess with a controlled environment."""
    env = {
        **os.environ,
        "DATABASE_URL": server_uri(),
        # Explicit empty values beat the repo's .env, which load_dotenv does not
        # override but would otherwise supply.
        "APP_ENV": "production",
        "APP_SECRET_KEY": "",
        "COOKIE_SECURE": "1",
        "ALLOWED_HOSTS": "sentriq.example.com",
        "WEB_CONCURRENCY": "1",
        "REDIS_URL": "",
        "PASSWORD_ITERATIONS": "1000",
    }
    env.update({key: str(value) for key, value in overrides.items()})
    return subprocess.run(
        [sys.executable, "-c", "import sentriq.config"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60,
    )


def test_placeholder_secret_is_refused_in_every_environment():
    """The key printed in .env.example must not be usable, in any mode."""
    result = run_config(APP_ENV="review", APP_SECRET_KEY="replace-with-at-least-64-hex-characters")
    assert result.returncode != 0
    assert "placeholder" in result.stderr.lower()


def test_short_secret_is_refused():
    result = run_config(APP_SECRET_KEY="a" * 39)
    assert result.returncode != 0
    assert "at least 64 characters" in result.stderr


def test_production_requires_allowed_hosts():
    result = run_config(APP_SECRET_KEY="a" * 64, ALLOWED_HOSTS="")
    assert result.returncode != 0
    assert "ALLOWED_HOSTS" in result.stderr


def test_production_requires_redis_before_running_several_workers():
    """N workers without a shared store means N times every limit."""
    result = run_config(APP_SECRET_KEY="a" * 64, WEB_CONCURRENCY=4, REDIS_URL="")
    assert result.returncode != 0
    assert "REDIS_URL" in result.stderr


def test_production_requires_secure_cookies():
    result = run_config(APP_SECRET_KEY="a" * 64, COOKIE_SECURE=0)
    assert result.returncode != 0
    assert "COOKIE_SECURE" in result.stderr


def test_several_workers_without_a_secret_are_refused_in_review_too():
    """Per-worker random keys make the session cookie bounce between workers."""
    result = run_config(APP_ENV="review", COOKIE_SECURE=0, APP_SECRET_KEY="", WEB_CONCURRENCY=4)
    assert result.returncode != 0
    assert "APP_SECRET_KEY is required" in result.stderr


def test_a_valid_production_configuration_imports():
    result = run_config(APP_SECRET_KEY="b" * 64)
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# Password hashing: the cost travels with the hash
# ---------------------------------------------------------------------------

def test_hash_records_its_cost_and_verifies():
    stored = hash_password("CorrectHorse1!")
    assert stored.startswith(f"pbkdf2_sha256${PASSWORD_ITERATIONS}$")
    assert verify_password("CorrectHorse1!", stored) is True
    assert verify_password("WrongHorse1!", stored) is False
    assert needs_rehash(stored) is False


def test_a_hash_written_before_the_cost_was_recorded_still_verifies():
    """The old three-part format must keep working, at its own cost."""
    legacy = hash_password("CorrectHorse1!", iterations=LEGACY_PASSWORD_ITERATIONS)
    assert legacy.count("$") == 3
    assert verify_password("CorrectHorse1!", legacy) is True
    assert needs_rehash(legacy) is True


def test_invalid_hashes_are_refused_without_raising():
    assert verify_password("x", "not-a-hash") is False
    assert verify_password("x", "") is False
    assert verify_password("x", "pbkdf2_sha256$abc$salt$digest") is False


def test_the_session_cookie_gets_the_host_prefix_only_when_secure(monkeypatch):
    """__Host- requires Secure, so a plain-HTTP review cannot use it."""
    from sentriq import config

    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    assert config.cookie_name("session") == "__Host-session"
    monkeypatch.setattr(config, "COOKIE_SECURE", False)
    assert config.cookie_name("session") == "session"
