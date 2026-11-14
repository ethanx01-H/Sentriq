"""The permission matrix, row by row.

The point of the table is that it can be read and disagreed with. These tests
pin every cell so a later "small" change to one route cannot quietly widen it.
"""

import pytest

from sentriq.models import Alert, User
from sentriq.permissions import MATRIX, assignable_roles_for, can, role_of

ALERT_ACTIONS = [action for action in MATRIX if action.startswith("alert.")]


def user(role, user_id=7, is_admin=False):
    return User(id=user_id, username=f"{role.lower()}{user_id}", role=role, is_admin=is_admin)


def alert(status="Open", assigned_to_id=None):
    return Alert(alert_id="#1", title="A ticket", status=status, assigned_to_id=assigned_to_id)


@pytest.mark.parametrize("role", ["L1", "L2", "L3"])
def test_every_role_can_view_create_take_and_export(role):
    actor = user(role)
    for action in ("alert.view", "alert.create", "alert.take", "alert.export", "evidence.read"):
        assert can(actor, action, alert()), f"{role} should be able to {action}"


@pytest.mark.parametrize("role", ["L1", "L2", "L3"])
def test_nobody_can_delete_a_ticket(role):
    assert can(user(role), "alert.delete", alert()) is False


@pytest.mark.parametrize("role", ["L1", "L2"])
def test_only_an_admin_manages_users(role):
    assert can(user(role), "user.manage") is False
    assert can(user("L3"), "user.manage") is True


@pytest.mark.parametrize("role", ["L1", "L2"])
def test_only_an_admin_reads_the_audit_log(role):
    assert can(user(role), "audit.read") is False
    assert can(user("L3"), "audit.read") is True


def test_l1_is_limited_to_their_own_tickets():
    actor = user("L1", 7)
    assert can(actor, "alert.edit", alert("WIP", 7)) is True
    assert can(actor, "alert.close", alert("WIP", 7)) is True
    assert can(actor, "alert.status", alert("WIP", 7)) is True
    assert can(actor, "alert.edit", alert("WIP", 8)) is False
    assert can(actor, "alert.close", alert("WIP", 8)) is False
    assert can(actor, "alert.status", alert("WIP", 8)) is False
    assert can(actor, "alert.edit", alert("Open", None)) is False


def test_l2_and_l3_work_on_any_open_ticket():
    for role in ("L2", "L3"):
        actor = user(role, 9)
        for action in ("alert.edit", "alert.close", "alert.status"):
            assert can(actor, action, alert("WIP", 8)) is True, f"{role} {action}"


def test_a_closed_ticket_is_read_only_for_everyone():
    for role in ("L1", "L2", "L3"):
        actor = user(role, 7)
        for action in ALERT_ACTIONS:
            if action in {"alert.view", "alert.export"}:
                continue
            assert can(actor, action, alert("Closed", 7)) is False, f"{role} {action} on a closed ticket"


def test_only_l1_and_l2_escalate():
    assert can(user("L1"), "alert.escalate", alert()) is True
    assert can(user("L2"), "alert.escalate", alert()) is True
    assert can(user("L3"), "alert.escalate", alert()) is False


def test_assignment_and_merge_start_at_l2():
    for action in ("alert.assign", "alert.merge"):
        assert can(user("L1"), action, alert()) is False
        assert can(user("L2"), action, alert()) is True
        assert can(user("L3"), action, alert()) is True


def test_an_admin_flag_outranks_the_stored_role():
    actor = user("L1", 5, is_admin=True)
    assert role_of(actor) == "L3"
    assert can(actor, "alert.assign", alert()) is True
    assert can(actor, "user.manage") is True


def test_an_unknown_action_is_denied_rather_than_allowed():
    """A typo in an action name must not fall through to a default of yes."""
    assert can(user("L3"), "alert.teleport", alert()) is False


def test_no_user_means_no_permission():
    assert can(None, "alert.view") is False


def test_assignable_roles():
    assert assignable_roles_for(user("L1")) == []
    assert assignable_roles_for(user("L2")) == ["L1"]
    assert assignable_roles_for(user("L3")) == ["L1", "L2"]
    assert assignable_roles_for(user("L1", is_admin=True)) == ["L1", "L2"]
