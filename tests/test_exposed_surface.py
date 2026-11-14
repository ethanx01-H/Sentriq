"""What the app publishes to a caller it cannot identify.

Three things used to be answered without a session: the OpenAPI schema (every
route and parameter), the newest backup file's name, and the ASGI server's own
banner. None of them is a secret in the sense that it stops an attacker, but
each is free reconnaissance, and the fix is cheap.
"""

import os
import pathlib
import subprocess
import sys

from fastapi.testclient import TestClient

from tests.support import server_uri

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_a_host_outside_the_allow_list_is_refused():
    """TrustedHost runs outermost, so a lookalike name never reaches a route."""
    from main import app
    stranger = TestClient(app, base_url="http://evil.example", follow_redirects=False)
    assert stranger.get("/login/").status_code == 400


def test_the_configured_host_is_accepted():
    from main import app
    local = TestClient(app, base_url="http://localhost", follow_redirects=False)
    assert local.get("/login/").status_code == 200


def test_healthz_does_not_publish_the_snapshot_name():
    from main import app
    body = TestClient(app, client=("127.0.0.1", 50000)).get("/healthz").json()
    assert body["status"] in {"ok", "degraded"}
    assert set(body["backup"]) == {"age_hours", "stale"}


def test_production_does_not_serve_the_api_schema():
    """The OpenAPI document maps every route and parameter for an attacker.

    Probed over HTTP rather than by walking app.routes: newer FastAPI wraps
    included routers in a container without ``.path``, so an introspection test
    can pass by matching nothing at all.
    """
    env = {
        **os.environ,
        "DATABASE_URL": server_uri(),
        "APP_ENV": "production",
        "APP_SECRET_KEY": "c" * 64,
        "COOKIE_SECURE": "1",
        "ALLOWED_HOSTS": "sentriq.example.com",
        "PASSWORD_ITERATIONS": "1000",
    }
    code = (
        "from fastapi.testclient import TestClient\n"
        "import main\n"
        "c = TestClient(main.app, base_url='https://sentriq.example.com', follow_redirects=False)\n"
        "print(c.get('/docs').status_code, c.get('/redoc').status_code,"
        " c.get('/openapi.json').status_code, c.get('/login/').status_code)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    docs, redoc, schema, login = result.stdout.split()
    assert (docs, redoc, schema) == ("404", "404", "404")
    # Control: the app is serving, so the 404s are a disabled route, not a dead app.
    assert login == "200"
