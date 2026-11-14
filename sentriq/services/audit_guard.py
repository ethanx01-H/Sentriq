"""Append-only protection for the audit trail.

The audit table lives in the same database as the data it describes, which is
convenient and is also the weakness: anything that can reach the database can
rewrite history, and a trail that can be edited is not evidence.

Two layers, because neither is enough on its own:

* A trigger refuses UPDATE, DELETE and TRUNCATE on ``fastapi_audit_logs``. It
  applies to the application's own session, to a DBA in psql, and to a bug in a
  later migration — it does not depend on anyone remembering the rule.
* Privileges: the application's role should hold INSERT and SELECT only, and the
  table should be owned by a role the application cannot become. A trigger can be
  disabled by the table's owner, so this is the part that survives a determined
  insider with the app's credentials.

``python -m sentriq.manage audit-guard`` installs the trigger if it is missing and
reports which of the two layers are actually in place.
"""

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger("sentriq.audit_guard")

# Single definition, shared by the migration and the test harness. Do not edit
# this string once a release has shipped: add a new migration instead, so the
# history of what each database ran stays true.
APPEND_ONLY_SQL = """
CREATE OR REPLACE FUNCTION sentriq_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'fastapi_audit_logs is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Export the trail and archive the database instead of editing it.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sentriq_audit_append_only_row ON fastapi_audit_logs;
CREATE TRIGGER sentriq_audit_append_only_row
    BEFORE UPDATE OR DELETE ON fastapi_audit_logs
    FOR EACH ROW EXECUTE FUNCTION sentriq_audit_append_only();

DROP TRIGGER IF EXISTS sentriq_audit_append_only_truncate ON fastapi_audit_logs;
CREATE TRIGGER sentriq_audit_append_only_truncate
    BEFORE TRUNCATE ON fastapi_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION sentriq_audit_append_only();
"""

DROP_SQL = """
DROP TRIGGER IF EXISTS sentriq_audit_append_only_row ON fastapi_audit_logs;
DROP TRIGGER IF EXISTS sentriq_audit_append_only_truncate ON fastapi_audit_logs;
DROP FUNCTION IF EXISTS sentriq_audit_append_only();
"""


def install(engine: Engine) -> None:
    """Create the trigger and its function if they are not already there."""
    with engine.begin() as connection:
        connection.execute(text(APPEND_ONLY_SQL))


def drop(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text(DROP_SQL))


def triggers(engine: Engine) -> list[str]:
    """The append-only triggers present on the audit table."""
    with engine.connect() as connection:
        rows = connection.execute(text(
            "select tgname from pg_trigger t "
            "join pg_class c on c.oid = t.tgrelid "
            "where c.relname = 'fastapi_audit_logs' and not t.tgisinternal "
            "order by tgname"
        )).all()
    return [row[0] for row in rows]


def report(engine: Engine) -> dict:
    """What is actually protecting the trail right now."""
    with engine.connect() as connection:
        row = connection.execute(text(
            "select current_user, "
            "       (select rolsuper from pg_roles where rolname = current_user), "
            "       (select pg_get_userbyid(relowner) from pg_class where relname = 'fastapi_audit_logs')"
        )).one()
        privileges = connection.execute(text(
            "select privilege_type from information_schema.role_table_grants "
            "where table_name = 'fastapi_audit_logs' and grantee = current_user "
            "order by privilege_type"
        )).all()
    current_role, is_superuser, owner = row
    present = triggers(engine)
    return {
        "current_user": current_role,
        "superuser": bool(is_superuser),
        "table_owner": owner,
        "owns_table": owner == current_role,
        "triggers": present,
        "trigger_installed": "sentriq_audit_append_only_row" in present,
        "privileges": [entry[0] for entry in privileges],
    }


def revoke_write_privileges(engine: Engine, app_role: str) -> None:
    """Take UPDATE, DELETE and TRUNCATE away from the application's role.

    Run this as the table's owner (a DBA), not as the application: a role cannot
    revoke a privilege from itself and have that mean anything, because it can
    grant it straight back.
    """
    statements = [
        f"REVOKE UPDATE, DELETE, TRUNCATE ON fastapi_audit_logs FROM {app_role}",
        f"GRANT INSERT, SELECT ON fastapi_audit_logs TO {app_role}",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
            logger.info("Applied: %s", statement)


def advisory(report_result: dict) -> list[str]:
    """The things a report cannot fix on its own, in words an auditor accepts."""
    notes = []
    if not report_result["trigger_installed"]:
        notes.append("The append-only trigger is missing. Run: python -m sentriq.manage audit-guard --install")
    if report_result["owns_table"]:
        notes.append(
            "The application's own role owns fastapi_audit_logs, so it can disable the "
            "trigger. Hand ownership to a DBA role (ALTER TABLE fastapi_audit_logs OWNER TO "
            "<dba_role>) and revoke UPDATE, DELETE and TRUNCATE from the application role: "
            "python -m sentriq.manage audit-guard --app-role <app_role>."
        )
    if report_result["superuser"]:
        notes.append("The application connects as a superuser, which bypasses every grant. Use a plain role.")
    return notes
