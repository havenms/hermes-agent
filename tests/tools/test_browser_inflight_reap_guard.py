"""The browser idle reaper must not close a session while a tool call of its task is in flight.

On 2026-10-21 a bot waited for a client's 2FA code and the janitor closed the login tab after
``browser.inactivity_timeout`` (120 s): only browser calls stamp activity, and a call that waits
for the user does not. Same idea as the terminal fix in upstream e24c9a5086.
"""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import patch

import pytest

from tools import browser_session as bs
from tools import browser_session_holds as holds
from tools import browser_session_lifecycle as lifecycle


@pytest.fixture()
def idle_session(monkeypatch):
    """One local session of task ``task-1`` whose last activity is far past the timeout."""
    monkeypatch.setattr(bs, "_active_sessions", {"task-1@home": {"session_name": "s", "features": {"local": True}}})
    monkeypatch.setattr(bs, "_session_last_activity", {"task-1@home": time.time() - 3600})
    monkeypatch.setattr(bs, "_session_owner_homes", {})
    monkeypatch.setattr(bs, "BROWSER_SESSION_INACTIVITY_TIMEOUT", 120)
    monkeypatch.setattr(holds, "_held", {})
    monkeypatch.setattr(lifecycle, "_human_holds_shared_browser", lambda key: False)
    closed = []
    monkeypatch.setattr(lifecycle, "_cleanup_one_inactive", lambda key, elapsed: closed.append(key))
    return closed


def test_a_held_task_keeps_its_idle_browser(idle_session):
    with holds.hold_browser_for_task("task-1"):
        lifecycle.cleanup_inactive_sessions()
        assert idle_session == []


def test_release_restarts_the_idle_countdown_then_the_reaper_applies(idle_session):
    with holds.hold_browser_for_task("task-1"):
        pass
    assert time.time() - bs._session_last_activity["task-1@home"] < 5, "release restamps"
    lifecycle.cleanup_inactive_sessions()
    assert idle_session == []
    bs._session_last_activity["task-1@home"] = time.time() - 3600
    lifecycle.cleanup_inactive_sessions()
    assert idle_session == ["task-1@home"]


def test_holds_are_refcounted_and_per_task(idle_session):
    with holds.hold_browser_for_task("task-1"):
        with holds.hold_browser_for_task("task-1"):
            pass
        assert holds.is_task_held("task-1")
        assert not holds.is_task_held("task-2")
    assert not holds.is_task_held("task-1")


def test_a_call_that_raises_releases_its_hold(idle_session):
    with pytest.raises(RuntimeError):
        with holds.hold_browser_for_task("task-1"):
            raise RuntimeError("boom")
    assert not holds.is_task_held("task-1")


def test_a_waiting_vault_prompt_keeps_the_login_page_open(idle_session, monkeypatch):
    """browser_vault enter_code blocks in the code prompt; the janitor runs meanwhile."""
    from tools import browser_vault_tool as vault

    swept = threading.Event()

    def page_op(task_id, fn):
        lifecycle.cleanup_inactive_sessions()  # the janitor fires while the user is still typing
        swept.set()
        return json.dumps({"success": True})

    monkeypatch.setattr(vault, "_fenced_page_op", page_op)
    vault._handle_vault({"action": "enter_code"}, task_id="task-1")
    assert swept.is_set()
    assert idle_session == []


def test_browser_vault_is_exempt_from_the_generic_tool_deadline():
    """The 420 s generic deadline ended every vault wait early and left a live card behind."""
    from agent.tool_executor import _SEQUENTIAL_DEADLINE_EXEMPT_TOOLS
    assert "browser_vault" in _SEQUENTIAL_DEADLINE_EXEMPT_TOOLS


def test_the_executor_holds_the_task_browser_around_every_call(monkeypatch):
    """Every dispatched call (sequential or concurrent) goes through _dispatch_authorized_once."""
    import inspect
    from agent import tool_executor
    assert "hold_browser_for_task(ref.task_id)" in inspect.getsource(tool_executor._dispatch_authorized_once)


def test_no_browser_stack_means_nothing_to_restamp(monkeypatch):
    import sys
    monkeypatch.setattr(holds, "_held", {})
    monkeypatch.delitem(sys.modules, "tools.browser_session", raising=False)
    with holds.hold_browser_for_task("t"):
        pass  # must not import or fail
    assert not holds.is_task_held("t")


def test_a_cdp_attached_browser_has_no_session_record_to_reap(monkeypatch):
    """With ``browser.cdp_url`` the browser belongs to someone else: browser_exec only exports the
    endpoint, so the janitor never sees a record and never closes that browser."""
    from tools.browser_session_lifecycle import release_session_backend
    with patch("tools.browser_launcher.stop_browser") as stop:
        release_session_backend("k", {"session_name": "cdp_x", "cdp_url": "ws://x", "features": {"cdp_override": True}})
    stop.assert_not_called()
