"""Application configuration from environment variables.

The defaults here fail closed: a deployment that forgets a value is refused at
import time with the command that fixes it, rather than starting with a
placeholder secret. Local development is the explicit exception, selected by
setting ``APP_ENV`` to something other than ``production``.
"""

import base64
import binascii
import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

from .dburl import normalise_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"

DATABASE_URL = normalise_database_url((os.environ.get("DATABASE_URL") or "").strip())
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required. Sentriq runs on Postgres only: set "
        "DATABASE_URL=postgresql://user:password@host:5432/sentriq in the "
        "environment or in .env."
    )
if not DATABASE_URL.startswith("postgresql"):
    raise RuntimeError(
        "DATABASE_URL must be a Postgres URL, got "
        f"{DATABASE_URL.split(':', 1)[0]}://... (SQLite is not supported.)"
    )
DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "10"))
DB_POOL_MAX_OVERFLOW = int(os.environ.get("DB_POOL_MAX_OVERFLOW", "20"))
WEB_CONCURRENCY = int(os.environ.get("WEB_CONCURRENCY", "1"))
APP_ENV = os.environ.get("APP_ENV", "development").lower()
# A key that ships in the repository is not a key. These are refused in every
# environment, because a "review" deployment on a real network is exactly how a
# placeholder reaches production.
PLACEHOLDER_SECRETS = {
    "replace-with-at-least-64-hex-characters",
    "replace-with-a-long-random-string",
    "replace-me",
    "change-me",
    "changeme",
    "development-only-secret",
}
MIN_SECRET_LENGTH = 64

_provided_secret = (os.environ.get("APP_SECRET_KEY") or "").strip()
if _provided_secret.lower() in PLACEHOLDER_SECRETS:
    raise RuntimeError(
        "APP_SECRET_KEY is still the example placeholder from .env.example. "
        "Generate a real one with: openssl rand -hex 32"
    )
if _provided_secret and len(_provided_secret) < MIN_SECRET_LENGTH:
    raise RuntimeError(
        f"APP_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters "
        f"(got {len(_provided_secret)}). Generate one with: openssl rand -hex 32"
    )
if not _provided_secret and WEB_CONCURRENCY > 1:
    # Without a fixed key every worker signs with its own random secret, so a
    # cookie set by one worker is rejected by the next and analysts see the
    # login page in a loop.
    raise RuntimeError(
        "APP_SECRET_KEY is required when WEB_CONCURRENCY is greater than 1: "
        "each worker would otherwise generate its own key and sessions would "
        "bounce between workers."
    )
if APP_ENV == "production" and not _provided_secret:
    raise RuntimeError(
        f"Production requires APP_SECRET_KEY of at least {MIN_SECRET_LENGTH} "
        "characters. Generate one with: openssl rand -hex 32"
    )
SECRET_KEY = _provided_secret or secrets.token_hex(32)

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1" if APP_ENV == "production" else "0") == "1"
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("Production requires COOKIE_SECURE=1 and an HTTPS reverse proxy.")

# Absolute session lifetime, and the idle timeout that sits inside it. A session
# dies at whichever comes first, so a stolen cookie stops working when the
# analyst stops using it rather than eight hours later.
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
SESSION_IDLE_SECONDS = int(os.environ.get("SESSION_IDLE_SECONDS", "1800"))
# How stale the activity stamp may get before the cookie is re-issued. Refreshing
# on every request would rewrite the cookie on every static asset fetch.
SESSION_REFRESH_SECONDS = int(os.environ.get("SESSION_REFRESH_SECONDS", "60"))
if SESSION_IDLE_SECONDS > SESSION_TTL_SECONDS:
    raise RuntimeError("SESSION_IDLE_SECONDS cannot exceed SESSION_TTL_SECONDS.")

# Host header allow-list. Behind a domain this is that domain; a request whose
# Host does not match is refused before it reaches a route.
ALLOWED_HOSTS = tuple(
    entry.strip().lower()
    for entry in (os.environ.get("ALLOWED_HOSTS") or "").split(",")
    if entry.strip()
)
if not ALLOWED_HOSTS:
    if APP_ENV == "production":
        raise RuntimeError(
            "ALLOWED_HOSTS is required in production: set it to the domain this "
            "app is served on, e.g. ALLOWED_HOSTS=sentriq.example.com"
        )
    ALLOWED_HOSTS = ("localhost", "127.0.0.1", "testserver")
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_EXEMPT_PATHS = ("/healthz", "/metrics")
RATE_LIMIT_EXEMPT_PREFIXES = ("/static/",)
# Only these peers may speak for the client through X-Forwarded-For / X-Real-IP.
# In production this is the single address your reverse proxy connects from, not
# a range: anything on the list can claim any client address, which is how the
# per-IP limits and the audit source IP are keyed.
_trusted_proxies_raw = (os.environ.get("TRUSTED_PROXIES") or "").strip()
TRUSTED_PROXIES = tuple(
    entry.strip() for entry in _trusted_proxies_raw.split(",") if entry.strip()
)
if not TRUSTED_PROXIES:
    if APP_ENV == "production":
        raise RuntimeError(
            "TRUSTED_PROXIES is required in production: set it to the address your "
            "reverse proxy connects from, e.g. TRUSTED_PROXIES=172.18.0.1/32 (find it "
            "with: docker network inspect sentriq_default -f "
            "'{{ (index .IPAM.Config 0).Gateway }}'). Without it every request looks "
            "like it came from the proxy, so per-client rate limits and the audit "
            "source IP are wrong; with a wide range, any container on that range can "
            "claim any address."
        )
    TRUSTED_PROXIES = ("127.0.0.1/32", "::1/128")
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(25 * 1024 * 1024)))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(6 * 1024 * 1024)))
ALLOWED_EVIDENCE_EXTENSIONS = {".xlsx", ".csv", ".jpg", ".jpeg", ".png", ".txt", ".log", ".json", ".pdf", ".pcap", ".pcapng"}

# Evidence handling. A scanner command is optional (ClamAV by convention, with {}
# standing for the temporary file). With REQUIRED set, a scanner that cannot run
# blocks the upload instead of letting an unscanned file through.
EVIDENCE_SCAN_COMMAND = (os.environ.get("EVIDENCE_SCAN_COMMAND") or "").strip() or None
EVIDENCE_SCAN_REQUIRED = os.environ.get("EVIDENCE_SCAN_REQUIRED", "0") == "1"
EVIDENCE_SCAN_TIMEOUT = int(os.environ.get("EVIDENCE_SCAN_TIMEOUT", "60"))

# AES-256-GCM key for evidence at rest, as 64 hex characters or base64. This
# protects a stolen backup or data directory; it does not protect a compromised
# host, where the key is in the process environment.
EVIDENCE_ENCRYPTION_KEY = (os.environ.get("EVIDENCE_ENCRYPTION_KEY") or "").strip() or None
if EVIDENCE_ENCRYPTION_KEY:
    try:
        _evidence_key = (
            bytes.fromhex(EVIDENCE_ENCRYPTION_KEY)
            if len(EVIDENCE_ENCRYPTION_KEY) == 64
            else base64.b64decode(EVIDENCE_ENCRYPTION_KEY, validate=True)
        )
    except (binascii.Error, ValueError) as error:
        raise RuntimeError(
            "EVIDENCE_ENCRYPTION_KEY must be 32 bytes as 64 hex characters or base64."
        ) from error
    if len(_evidence_key) != 32:
        raise RuntimeError("EVIDENCE_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")

STATUSES = ["Open", "Pending", "WIP", "Closed"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_LABELS = {
    "Critical": "0 - Critical",
    "High": "1 - High",
    "Medium": "2 - Medium",
    "Low": "3 - Low",
    "Informational": "4 - Informational",
}
ROLES = ["L1", "L2", "L3"]
# Timestamps are stored in UTC and rendered in this zone for analysts.
DISPLAY_TIMEZONE = os.environ.get("DISPLAY_TIMEZONE", "Asia/Yangon")
ALEMBIC_HEAD = "0011_audit_append_only"

LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_ACCOUNT_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_ACCOUNT_LOCKOUT_THRESHOLD", "10"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

# Password hashing. The iteration count is written into every hash, so it can be
# raised later and old hashes are upgraded as their owners sign in.
PASSWORD_ITERATIONS = int(os.environ.get("PASSWORD_ITERATIONS", "600000"))
LEGACY_PASSWORD_ITERATIONS = 240_000
if PASSWORD_ITERATIONS < 1000:
    raise RuntimeError("PASSWORD_ITERATIONS must be at least 1000.")

# Shared limiter/lockout store. Without it, counters live in each worker's
# memory, so N workers multiply every limit by N and a lockout only applies to
# the worker that saw the failed attempt.
REDIS_URL = os.environ.get("REDIS_URL") or None
if APP_ENV == "production" and WEB_CONCURRENCY > 1 and not REDIS_URL:
    raise RuntimeError(
        f"WEB_CONCURRENCY={WEB_CONCURRENCY} needs REDIS_URL. Without a shared "
        "store each worker keeps its own rate-limit and login-lockout counters, "
        "so the real limit is N times the configured one. Either set "
        "REDIS_URL=redis://redis:6379/0 or run with WEB_CONCURRENCY=1."
    )

# Retention and archival. The README promises 730 days; the job enforces it.
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "730"))
if RETENTION_DAYS < 1:
    raise RuntimeError("RETENTION_DAYS must be at least 1 day.")
# How many expired tickets one transaction handles. The daily job loops over
# batches, so this bounds transaction length and lock time, not the total.
RETENTION_BATCH_SIZE = int(os.environ.get("RETENTION_BATCH_SIZE", "500"))
if RETENTION_BATCH_SIZE < 1:
    raise RuntimeError("RETENTION_BATCH_SIZE must be at least 1.")
ARCHIVE_DIR = Path(os.environ.get("ARCHIVE_DIR", str(DATA_DIR / "archive")))
AUDIT_EXPORT_DIR = Path(os.environ.get("AUDIT_EXPORT_DIR", str(DATA_DIR / "audit-exports")))
# Where a scheduled export is copied so the anchor is not on the same host as the
# database it describes: a mounted share, an SFTP drop, object storage.
AUDIT_OFFHOST_DIR = Path(os.environ["AUDIT_OFFHOST_DIR"]) if os.environ.get("AUDIT_OFFHOST_DIR") else None
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", str(BASE_DIR / "backups")))
# A snapshot older than this makes /healthz report degraded.
BACKUP_MAX_AGE_HOURS = int(os.environ.get("BACKUP_MAX_AGE_HOURS", "36"))
# Bearer token for /metrics. Unset means /metrics only answers on loopback.
METRICS_TOKEN = os.environ.get("METRICS_TOKEN") or None

# Outbound notifications. Both channels stay inert until they are configured.
SMTP_HOST = os.environ.get("SMTP_HOST") or None
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER") or None
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") or None
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") == "1"
NOTIFY_EMAIL_FROM = os.environ.get("NOTIFY_EMAIL_FROM") or SMTP_USER
NOTIFY_EMAIL_TO = tuple(
    entry.strip() for entry in os.environ.get("NOTIFY_EMAIL_TO", "").split(",") if entry.strip()
)
NOTIFY_TEAMS_WEBHOOK = os.environ.get("NOTIFY_TEAMS_WEBHOOK") or None
NOTIFY_ON_ASSIGN = os.environ.get("NOTIFY_ON_ASSIGN", "1") == "1"
NOTIFY_ON_ESCALATE = os.environ.get("NOTIFY_ON_ESCALATE", "1") == "1"
# New tickets notify only at this severity or above.
NOTIFY_MIN_SEVERITY = os.environ.get("NOTIFY_MIN_SEVERITY", "High")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL") or ""


def cookie_name(base: str) -> str:
    """Prefix a cookie name with ``__Host-`` wherever the cookie is Secure.

    The ``__Host-`` prefix is what stops a sibling subdomain from overwriting
    this site's cookies, but browsers reject the prefix on a non-Secure cookie,
    so it is applied only when COOKIE_SECURE is on. That makes the name differ
    between a localhost review and a domain deployment, which is why every
    reader and writer of these cookies goes through this function.
    """
    return f"__Host-{base}" if COOKIE_SECURE else base


# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
