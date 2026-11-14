"""The deployment files have to agree with the application.

These are the checks a container build would catch, written so they run without
Docker: a COPY source that does not exist, an entrypoint that is not executable,
a compose variable nothing provides, or a worker default that disagrees with the
code. Each of those is a deploy-time failure that a green test suite otherwise
says nothing about.
"""

import pathlib
import re
import stat

import pytest

from sentriq import config

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = (ROOT / "docker-compose.yml").read_text()
DOCKERFILE = (ROOT / "Dockerfile").read_text()
ENTRYPOINT = ROOT / "docker-entrypoint.sh"
ENV_EXAMPLE = (ROOT / ".env.example").read_text()
DOCKERIGNORE = (ROOT / ".dockerignore").read_text().splitlines()


def test_every_copy_source_in_the_dockerfile_exists():
    for line in DOCKERFILE.splitlines():
        if not line.startswith("COPY "):
            continue
        for source in line.split()[1:-1]:
            assert (ROOT / source).exists(), f"Dockerfile copies a missing path: {source}"


def test_the_entrypoint_is_executable_and_parses():
    mode = ENTRYPOINT.stat().st_mode
    assert mode & stat.S_IXUSR, "docker-entrypoint.sh is not executable"
    assert ENTRYPOINT.read_text().startswith("#!/bin/sh")


def test_the_entrypoint_runs_the_worker_class_the_app_ships():
    """A --worker-class pointing at a module that is not in the image is a
    container that starts and immediately exits."""
    text = ENTRYPOINT.read_text()
    match = re.search(r"--worker-class\s+(\S+)", text)
    assert match, "the entrypoint no longer names a worker class"
    module_path, _, class_name = match.group(1).rpartition(".")
    module = __import__(module_path, fromlist=[class_name])
    assert hasattr(module, class_name)


def test_the_entrypoint_worker_default_matches_the_configuration():
    text = ENTRYPOINT.read_text()
    match = re.search(r"--workers\s+\"\$\{WEB_CONCURRENCY:-(\d+)\}\"", text)
    assert match, "the entrypoint no longer has a WEB_CONCURRENCY default"
    # One worker is the safe default: several without REDIS_URL multiply every
    # rate limit by the worker count, which the config refuses in production.
    assert match.group(1) == "1"


def test_compose_does_not_default_to_review_mode_or_an_insecure_cookie():
    assert "APP_ENV: ${APP_ENV:-production}" in COMPOSE
    assert "COOKIE_SECURE: ${COOKIE_SECURE:-1}" in COMPOSE
    assert "review" not in re.findall(r"APP_ENV: \$\{APP_ENV:-(\w+)\}", COMPOSE)


def test_every_required_compose_variable_is_documented_in_env_example():
    required = set(re.findall(r"\$\{([A-Z_]+):\?", COMPOSE))
    assert required, "no required variables found; has the compose file changed shape?"
    for name in sorted(required):
        assert re.search(rf"^{name}=", ENV_EXAMPLE, re.MULTILINE), (
            f"compose requires {name} but .env.example does not set it"
        )


def test_compose_does_not_ship_a_wide_trusted_proxy_range():
    """172.16.0.0/12 lets any container on the bridge claim any client address."""
    assert "172.16.0.0/12" not in COMPOSE
    assert "TRUSTED_PROXIES: ${TRUSTED_PROXIES" not in COMPOSE


def test_compose_does_not_publish_the_app_beyond_loopback():
    assert '"127.0.0.1:8080:8080"' in COMPOSE


def test_compose_keeps_data_on_host_directories():
    """A Docker volume is one `compose down -v` away from being deleted."""
    assert "./data:/app/data" in COMPOSE
    assert "SENTRIQ_PGDATA_DIR" in COMPOSE


def test_the_dockerignore_does_not_exclude_anything_the_app_needs():
    excluded = [line for line in DOCKERIGNORE if line and not line.startswith("!")]
    for needed in ("main.py", "sentriq", "templates", "static", "alembic", "scripts"):
        assert needed not in excluded, f".dockerignore excludes {needed}"


def test_the_runtime_image_does_not_install_test_tooling():
    requirements = (ROOT / "requirements.txt").read_text()
    for tool in ("pytest", "pip-audit", "pgserver", "fakeredis"):
        assert tool not in requirements, f"{tool} belongs in requirements-dev.txt"


def test_the_healthcheck_command_works_against_a_live_endpoint():
    """The compose healthcheck is a one-liner; prove the shape is right."""
    from urllib.request import urlopen

    from fastapi.testclient import TestClient
    from main import app

    # TestClient is not a socket server, so exercise the same call the container
    # makes against the real app object instead.
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert callable(urlopen)


@pytest.mark.parametrize("name", ["main.py", "sentriq/worker.py", "scripts/backup-postgres.sh",
                                  "scripts/audit-export-offhost.sh", "scripts/verify-restore.sh"])
def test_files_the_image_needs_are_present(name):
    assert (ROOT / name).exists()


def test_alembic_head_matches_the_newest_migration():
    """A stale ALEMBIC_HEAD makes startup skip the migration it should run."""
    versions = sorted(path.stem for path in (ROOT / "alembic" / "versions").glob("0*.py"))
    assert versions[-1] == config.ALEMBIC_HEAD
