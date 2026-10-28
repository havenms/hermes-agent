"""A pasted password stays out of the inbound log, and only the message that holds it is deleted.

Round 4 review fix (findings/10-review-fork.md). Fake values only."""

import asyncio
import json
import logging
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.session import SessionSource
from tests.gateway.vault_review_helpers import (
    KEY, OTHER, OWNER, ButtonAdapter as _ButtonAdapter, FakeAdapter as _Adapter, clear_clarify,
    make_event as _event, password_entry as _password_entry, runner_for as _runner,
)
from tools import clarify_gateway as cm


@pytest.fixture(autouse=True)
def _clean():
    clear_clarify()
    yield
    clear_clarify()


# ── 7: the inbound log line and the pasted-login delete ──────────────────────────────────────


def test_the_inbound_log_scrub_masks_password_shapes():
    from agent.redact import scrub_secret_shapes
    out = scrub_secret_shapes("my QuickBooks login is me@example.com / Pass1234!")
    assert "Pass1234" not in out and "me@example.com" in out and "QuickBooks" in out


def test_the_inbound_log_line_uses_the_scrub():
    import inspect
    from gateway import run_turn
    src = inspect.getsource(run_turn)
    assert "scrub_secret_shapes(event.text" in src


def _scrub_runner(text, deleted):
    from gateway.run_turn_runner import TurnRunner

    class _A:
        async def delete_message(self, chat_id, message_id):
            deleted.append(message_id)
            return True

    runner = TurnRunner.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(_status_adapter=_A(), source=SimpleNamespace(chat_id="777", message_id="m-2"),
                                  inbound_message_id="m-2", message=text, persist_user_message=None)
    loop = asyncio.new_event_loop()

    def _schedule(coro, _why):
        return SimpleNamespace(result=lambda timeout=None: loop.run_until_complete(coro))
    runner._schedule = _schedule
    return runner, loop


def test_the_pasted_scrub_deletes_only_a_message_that_holds_the_password():
    deleted = []
    runner, loop = _scrub_runner("QuickBooks", deleted)
    try:
        assert runner._scrub_turn_message_sync(("Pass1234",)) is False
        assert deleted == [], "the turn's message has no password: nothing is deleted"
        runner._ctx.message = "me@example.com Pass1234"
        assert runner._scrub_turn_message_sync(("Pass1234",)) is True
        assert deleted == ["m-2"]
    finally:
        loop.close()


def test_save_login_passes_the_pasted_values_to_the_scrub(monkeypatch):
    from agent.vault_backends import unlock as vault_unlock
    from tools import browser_vault_tool as vault
    seen = []

    def scrub(values=()):
        seen.append(values)
        return False
    vault_unlock.set_pasted_secret_scrub_callback(scrub)
    try:
        assert vault._scrub_pasted_message(("pw",)) is False
    finally:
        vault_unlock.set_pasted_secret_scrub_callback(None)
    assert seen == [("pw",)]
