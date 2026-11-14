"""One place that answers "may this role do this to this ticket?".

Authorization used to be spread across the routes: some actions checked a
``can_*`` helper, others compared role strings inline, and the rules did not
agree. A status change was limited to the assigned analyst or an assigning
role, while the edit and close routes only asked "is this ticket not closed?" —
so any L1 could rewrite or close an L2's investigation, which is the one thing
a two-tier SOC cannot allow.

The matrix below is the whole policy. Routes ask it a question and do not
re-implement the answer; the tests in ``tests/test_permissions.py`` assert the
matrix row by row, and ``tests/test_alert_authorization.py`` proves the routes
apply it.
"""

from .models import Alert, User

ROLES = ("L1", "L2", "L3")

# "own" means the ticket is assigned to this user. An unassigned ticket is
# nobody's: an L1 has to take it before editing or closing it, which leaves a
# timeline entry saying who picked it up.
OWN = "own"

MATRIX: dict[str, dict[str, bool | str]] = {
    "alert.view":     {"L1": True, "L2": True, "L3": True},
    "alert.create":   {"L1": True, "L2": True, "L3": True},
    "alert.edit":     {"L1": OWN,  "L2": True, "L3": True},
    "alert.close":    {"L1": OWN,  "L2": True, "L3": True},
    "alert.status":   {"L1": OWN,  "L2": True, "L3": True},
    "alert.take":     {"L1": True, "L2": True, "L3": True},
    "alert.escalate": {"L1": True, "L2": True, "L3": False},
    "alert.assign":   {"L1": False, "L2": True, "L3": True},
    "alert.merge":    {"L1": False, "L2": True, "L3": True},
    # Deleting a ticket would take its timeline and evidence with it.
    "alert.delete":   {"L1": False, "L2": False, "L3": False},
    "alert.export":   {"L1": True, "L2": True, "L3": True},
    "evidence.read":  {"L1": True, "L2": True, "L3": True},
    "user.manage":    {"L1": False, "L2": False, "L3": True},
    "audit.read":     {"L1": False, "L2": False, "L3": True},
}


def role_of(user: User | None) -> str | None:
    """Effective role. An admin flag outranks the stored role string."""
    if user is None:
        return None
    return "L3" if user.is_admin else user.role


def _is_own(user: User, alert: Alert | None) -> bool:
    return alert is not None and alert.assigned_to_id == user.id


def can(user: User | None, action: str, alert: Alert | None = None) -> bool:
    """True when this user may perform ``action``, optionally on ``alert``."""
    if user is None:
        return False
    role = role_of(user)
    if role is None:
        return False
    try:
        rule = MATRIX[action][role]
    except KeyError:
        # An action missing from the matrix is a programming error, and the safe
        # reading of a typo is "no".
        return False
    if rule is True:
        # Every action on a ticket is also blocked once the ticket is closed:
        # closed tickets are the record, not the working set.
        if alert is not None and alert.status == "Closed" and action != "alert.view":
            return False
        return True
    if rule == OWN:
        if alert is None or alert.status == "Closed":
            return False
        return _is_own(user, alert)
    return False


def assignable_roles_for(user: User) -> list[str]:
    """Roles this user may hand a ticket to: an L2 assigns to L1, an L3 to either."""
    role = role_of(user)
    if role == "L3":
        return ["L1", "L2"]
    if role == "L2":
        return ["L1"]
    return []
