""""Wrong email" on the password card goes back to the email card; skip, cancel and stop decline.

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


# ── 3: "wrong email" goes back to the email card ─────────────────────────────────────────────


@pytest.mark.parametrize("word", ["wrong", "Wrong email", "that's wrong.", "not my email"])
def test_wrong_words_say_wrong_not_decline(word):
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, word, OWNER) == cm.TEXT_RESOLVED
    assert entry.response == cm.WRONG_ANSWER


@pytest.mark.parametrize("word", ["skip", "cancel", "stop"])
def test_skip_cancel_and_stop_still_decline(word):
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, word, OWNER) == cm.TEXT_RESOLVED
    assert entry.response == cm.SKIPPED


def test_wrong_email_on_the_password_card_asks_the_email_again():
    from gateway.vault_prompts import build_vault_prompt_callbacks
    replies = iter(["typo@example.com", cm.WRONG_ANSWER, "me@example.com", "hunter2"])
    questions = []

    def ask(question, **kw):
        questions.append(question)
        return next(replies)

    answer = build_vault_prompt_callbacks(ask)["save_login"]("https://a.example.com", "TestCo Books")
    assert answer == {"identifier": "me@example.com", "password": "hunter2"}
    assert "(1/2)" in questions[2] and questions[2].startswith("No problem")
    assert "me@example.com" in questions[3]


def test_wrong_on_a_code_card_is_still_a_decline():
    from gateway.vault_prompts import build_vault_prompt_callbacks
    assert build_vault_prompt_callbacks(lambda q, **kw: cm.WRONG_ANSWER)["code"]("a.example.com", "") == ""


def test_save_login_does_not_report_a_decline_for_wrong_email(monkeypatch):
    from agent.vault_backends import unlock as vault_unlock
    from gateway.vault_prompts import build_vault_prompt_callbacks
    from tools import browser_vault_tool as vault
    replies = iter(["typo@example.com", cm.WRONG_ANSWER, "me@example.com", "hunter2"])
    vault_unlock.set_save_login_prompt_callback(
        build_vault_prompt_callbacks(lambda q, **kw: next(replies))["save_login"])
    monkeypatch.setattr(vault_unlock, "can_prompt_here", lambda: True)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://a.example.com")
    monkeypatch.setattr(vault, "_page_title", lambda task_id: "")
    saved = []
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: SimpleNamespace(
        add_item=lambda kind, label, data, origin=None, **kw: saved.append(data) or SimpleNamespace(id="vault_h1")))
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps({"success": True}))
    try:
        out = json.loads(vault.browser_vault_save_login(label="TestCo Books", task_id="t"))
    finally:
        vault_unlock.set_save_login_prompt_callback(None)
    assert out["success"] is True and out["identifier"] == "me@example.com"
    assert saved[0]["identifier"] == "me@example.com"
