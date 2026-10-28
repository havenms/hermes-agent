"""The vault tool text steers the model to the login prompt but never makes it refuse a pasted login.

Clients paste logins in chat. A description that says "never type a password or ask for one" made
the bot refuse to use the login and leave the job undone. The prompt stays the preferred path and
the model-blind fill stays the default; only the refusal goes.
"""

import json

from tools import browser_vault_tool as vault


def test_the_schema_prefers_the_prompt_and_accepts_a_pasted_login():
    text = vault.BROWSER_VAULT_SCHEMA["description"]
    assert "Prefer the login prompt" in text
    assert "already pasted" in text
    assert "Never repeat a password" in text
    assert "ask for or repeat a password" not in text
    props = vault.BROWSER_VAULT_SCHEMA["parameters"]["properties"]
    assert "identifier" in props and "password" in props
    assert vault.BROWSER_VAULT_SCHEMA["parameters"]["required"] == ["action"]


def test_the_empty_list_hint_no_longer_forbids_a_pasted_login(monkeypatch):
    monkeypatch.setattr("agent.vault_backends.enabled_backends", lambda: [])
    hint = json.loads(vault.browser_vault_list())["hint"]
    assert "ask for one in chat" not in hint
    assert "pasted" in hint and "Never repeat a password" in hint
