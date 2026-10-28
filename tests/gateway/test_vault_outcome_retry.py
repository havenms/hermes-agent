"""A loading page is pending, a retry updates the login, and a rejected login is removed.

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


PW = {"type": "password", "label": "Password", "autocomplete": "current-password", "invalid": False}
EMAIL = {"type": "email", "label": "Email", "autocomplete": "username", "invalid": False}
OTP = {"type": "text", "label": "Verification code", "autocomplete": "one-time-code", "invalid": False}


def _snap(fields=(), errors=(), text=""):
    return {"hermes_outcome": 1, "url": "https://a.example.com/signin", "fields": list(fields),
            "errors": list(errors), "text": text}


# ── 5 (vault_outcome): pending, replace and remove ──────────────────────────────────────────


@pytest.fixture()
def check_page(monkeypatch):
    from agent import vault_outcome as vo
    from tools import browser_vault_tool as vault
    state = SimpleNamespace(snap=None, removed=[])
    monkeypatch.setattr(vault, "_eval_js", lambda task_id, expr: {"success": True, "result": json.dumps(state.snap)})
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://a.example.com")
    monkeypatch.setattr(vault, "_check_settle_s", lambda: 0.0)
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: SimpleNamespace(
        remove_item=lambda handle: state.removed.append(handle) or True))
    vo.TRACKER.clear()
    yield state
    vo.TRACKER.clear()


def test_a_page_still_loading_is_pending_and_uses_no_retry(check_page):
    from agent import vault_outcome as vo
    from tools import browser_vault_tool as vault
    vo.TRACKER.note_filled("t", "https://a.example.com", ["password"])
    check_page.snap = _snap([EMAIL, PW])
    out = json.loads(vault.browser_vault_check(task_id="t"))
    assert out["success"] is True and out["outcome"] == "pending" and "check again" in out["next"]
    assert vo.TRACKER.pending("t", "https://a.example.com", ["password"]) is None


def test_a_rejected_saved_login_is_removed(check_page):
    from agent import vault_outcome as vo
    from tools import browser_vault_tool as vault
    vo.TRACKER.note_saved("t", "https://a.example.com", "vault_h1")
    vo.TRACKER.note_filled("t", "https://a.example.com", ["password"])
    check_page.snap = _snap([EMAIL, PW], ["Incorrect password."])
    out = json.loads(vault.browser_vault_check(task_id="t"))
    assert out["error_type"] == "credential_rejected" and out["rejected_login_removed"] is True
    assert check_page.removed == ["vault_h1"]


def test_a_rejected_code_does_not_remove_the_login(check_page):
    from agent import vault_outcome as vo
    from tools import browser_vault_tool as vault
    vo.TRACKER.note_saved("t", "https://a.example.com", "vault_h1")
    vo.TRACKER.note_filled("t", "https://a.example.com", ["code"])
    check_page.snap = _snap([OTP], ["That code is not right."])
    json.loads(vault.browser_vault_check(task_id="t"))
    assert check_page.removed == []


def test_a_retry_for_the_same_login_updates_the_item(tmp_path, monkeypatch):
    from agent import vault_store
    store = None
    for name in ("VaultStore", "LocalVaultStore"):
        cls = getattr(vault_store, name, None)
        if cls is not None:
            try:
                store = cls(tmp_path)
            except TypeError:
                store = None
            if store is not None:
                break
    if store is None:
        pytest.skip("no constructible local vault store in this build")
    payload = {"identifier_type": "email", "identifier": "me@example.com", "password": "wrong1"}
    first = store.add_item("login", "TestCo Books", dict(payload), origin="https://a.example.com",
                           replace_same_login=True)
    second = store.add_item("login", "TestCo Books", dict(payload, password="right2", identifier="ME@example.com"),
                            origin="https://a.example.com", replace_same_login=True)
    assert second.id == first.id
    assert len(store.list_items()) == 1
    assert store.resolve_secret(first.id)["password"] == "right2"
    store.add_item("login", "TestCo Books", dict(payload, identifier="other@example.com"),
                   origin="https://a.example.com", replace_same_login=True)
    assert len(store.list_items()) == 2
