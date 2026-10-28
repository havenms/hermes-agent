"""save_login accepts a login the client already pasted in chat, as a fallback to the prompt.

The clients are small-business owners. Many paste "email / password" straight into the chat. The
bot must still get the login done: store it exactly like a prompted login (bound to the page
origin), register the password with the redaction boundary first, and remove the chat message
when the platform allows it.
"""

import json
from types import SimpleNamespace

import pytest

from agent.vault_backends import unlock as vault_unlock
from tools import browser_vault_tool as vault


@pytest.fixture()
def page(monkeypatch):
    saved, redacted, filled = [], [], []
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://app.example.com")
    store = SimpleNamespace(add_item=lambda kind, label, data, origin: saved.append((kind, label, dict(data), origin))
                            or SimpleNamespace(id="vault:h1"))
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda value: redacted.append(value))
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: filled.append(handle)
                        or json.dumps({"success": True, "filled_fields": 1}))
    vault_unlock.set_save_login_prompt_callback(None)
    vault_unlock.set_pasted_secret_scrub_callback(None)
    yield SimpleNamespace(saved=saved, redacted=redacted, filled=filled)
    vault_unlock.set_pasted_secret_scrub_callback(None)


def test_a_pasted_login_is_saved_bound_to_the_page_and_filled(page):
    out = json.loads(vault.browser_vault_save_login(identifier=" owner@shop.com ", password="pw 123", task_id="t"))
    assert out["success"] is True and out["source"] == "pasted"
    assert page.saved == [("login", "app.example.com",
                           {"identifier_type": "email", "identifier": "owner@shop.com", "password": "pw 123"},
                           "https://app.example.com")]
    assert page.redacted == ["pw 123"], "the password is registered for redaction before use"
    assert page.filled == ["vault:h1"]
    assert "pw 123" not in json.dumps(out), "the tool result never carries the password"


def test_the_pasted_path_works_where_no_prompt_can_be_shown(page):
    """No prompt callback (cron, API, a surface without prompts): the pasted login still saves."""
    assert vault_unlock.can_prompt_here() is False
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", task_id="t"))
    assert out["success"] is True


def test_the_clients_message_is_removed_when_the_surface_can(page):
    vault_unlock.set_pasted_secret_scrub_callback(lambda: True)
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", task_id="t"))
    assert out["chat_message_removed"] is True


def test_a_message_that_stays_tells_the_bot_to_ask_the_client_to_delete_it(page):
    vault_unlock.set_pasted_secret_scrub_callback(lambda: False)
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", task_id="t"))
    assert out["chat_message_removed"] is False
    assert "delete" in out["next"]


def test_a_password_without_an_identifier_is_refused(page):
    out = json.loads(vault.browser_vault_save_login(password="pw", task_id="t"))
    assert out["success"] is False and out["error_type"] == "identifier_required"
    assert page.saved == []


def test_without_pasted_values_the_prompt_path_is_unchanged(page):
    asked = []
    vault_unlock.set_save_login_prompt_callback(lambda origin, host: asked.append(host)
                                                or {"identifier": "owner", "password": "pw"})
    try:
        vault_unlock.set_code_prompt_callback(None)
        out = json.loads(vault.browser_vault_save_login(task_id="t"))
    finally:
        vault_unlock.set_save_login_prompt_callback(None)
    assert asked == ["app.example.com"] and out["success"] is True and "source" not in out


def test_the_handler_passes_pasted_values_through(page, monkeypatch):
    monkeypatch.setattr(vault, "_fenced_page_op", lambda tid, fn: fn())
    out = json.loads(vault._handle_vault({"action": "save_login", "identifier": "owner", "password": "pw"},
                                         task_id="t"))
    assert out["success"] is True


def test_the_scrub_callback_reaches_tool_worker_threads():
    from tools.thread_context import _callback_api
    pairs = _callback_api()
    assert (vault_unlock.get_pasted_secret_scrub_callback, vault_unlock.set_pasted_secret_scrub_callback) in pairs
