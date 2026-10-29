"""save_login with a known identifier asks only for what is missing.

Round 6, live 2026-10-29: the bot had already typed the username on the page, but save_login still
asked the client for both the username and the password. With identifier= the cards ask only for
the password (and any extra field), the private form shows only those fields, and the login is
stored with the given identifier. Fake values only.
"""

import json
from types import SimpleNamespace

import pytest

from agent.vault_backends import unlock as vault_unlock
from gateway.vault_prompts import build_vault_prompt_callbacks
from tools import browser_vault_tool as vault
from tools import clarify_gateway as cm


def _form_answer(values):
    return cm.FORM_ANSWER_PREFIX + json.dumps(values)


# ── the gateway cards ──────────────────────────────────────────────────────────────────────────

def test_a_known_identifier_asks_only_for_the_password():
    asked = []

    def ask(question, **kw):
        asked.append((question, kw))
        return "Summer2024?"

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "TestCo Books", identifier="MICHAEL PERSONETTE")
    assert got == {"identifier": "MICHAEL PERSONETTE", "password": "Summer2024?"}
    assert len(asked) == 1, "no email or username card"
    question, kw = asked[0]
    assert "(1/1)" in question and "MICHAEL PERSONETTE" in question and "password" in question
    assert kw["secret"] is True and kw["chat_guard"] is True and kw.get("answer_pattern") is None
    assert [f["key"] for f in kw["form_fields"]] == ["password"]


def test_a_known_identifier_with_an_extra_field_renumbers_the_cards():
    asked = []
    answers = iter(["pw", "4321"])

    def ask(question, **kw):
        asked.append((question, kw))
        return next(answers)

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Bank", ("PIN",), identifier="owner")
    assert got == {"identifier": "owner", "password": "pw", "extra": {"PIN": "4321"}}
    assert "(1/2)" in asked[0][0] and "(2/2)" in asked[1][0] and "PIN" in asked[1][0]
    assert [f["key"] for f in asked[0][1]["form_fields"]] == ["password", "extra:PIN"]
    assert asked[1][1]["last"] is True


def test_the_short_form_answers_every_card_at_once():
    asked = []

    def ask(question, **kw):
        asked.append(kw)
        return _form_answer({"password": " pw ", "extra:PIN": "4321"})

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Bank", ("PIN",), identifier="owner")
    assert got == {"identifier": "owner", "password": " pw ", "extra": {"PIN": "4321"}}
    assert len(asked) == 1


def test_wrong_email_on_the_password_card_goes_to_the_email_card():
    asked = []
    answers = iter([cm.WRONG_ANSWER, "right@example.com", "pw"])

    def ask(question, **kw):
        asked.append(question)
        return next(answers)

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Shop", identifier="wrong@example.com")
    assert got == {"identifier": "right@example.com", "password": "pw"}
    assert "(1/1)" in asked[0]
    assert "(1/2)" in asked[1] and "email or username" in asked[1] and "No problem" in asked[1]
    assert "(2/2)" in asked[2]


def test_no_identifier_keeps_the_two_cards():
    asked = []
    answers = iter(["owner", "pw"])
    build_vault_prompt_callbacks(lambda q, **kw: asked.append(q) or next(answers))["save_login"]("https://x", "Shop")
    assert "(1/2)" in asked[0] and "(2/2)" in asked[1]


# ── the tool ───────────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def page(monkeypatch):
    saved = []
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://books.example.com")
    monkeypatch.setattr(vault, "_page_title", lambda task_id: "Sign in - Books")
    store = SimpleNamespace(add_item=lambda kind, label, data, origin: saved.append(dict(data))
                            or SimpleNamespace(id="vault_h1"))
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda value: None)
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps(
        {"success": True, "filled_fields": 1}))
    monkeypatch.setattr(vault_unlock, "can_prompt_here", lambda: True)
    from agent.vault_outcome import TRACKER
    TRACKER.clear()
    yield SimpleNamespace(saved=saved)
    TRACKER.clear()
    vault_unlock.set_save_login_prompt_callback(None)


def test_the_tool_passes_a_known_identifier_and_stores_it(page):
    seen = []

    def prompt(origin, site, extra_fields=(), notice="", identifier=""):
        seen.append(identifier)
        return {"identifier": identifier, "password": "pw"}

    vault_unlock.set_save_login_prompt_callback(prompt)
    out = json.loads(vault.browser_vault_save_login(identifier="MICHAEL PERSONETTE", task_id="t"))
    assert out["success"] is True and out["identifier"] == "MICHAEL PERSONETTE"
    assert seen == ["MICHAEL PERSONETTE"]
    assert page.saved[0]["identifier"] == "MICHAEL PERSONETTE" and page.saved[0]["identifier_type"] == "username"


def test_a_surface_that_cannot_take_it_still_asks_for_both(page):
    vault_unlock.set_save_login_prompt_callback(lambda origin, site: {"identifier": "typed", "password": "pw"})
    out = json.loads(vault.browser_vault_save_login(identifier="owner", task_id="t"))
    assert out["success"] is True and page.saved[0]["identifier"] == "typed"


def test_a_refused_identifier_is_asked_again(page, monkeypatch):
    from agent.vault_outcome import TRACKER
    monkeypatch.setattr(TRACKER, "pending", lambda task_id, origin, fields: (
        {"field": "identifier", "reason": "rejected", "count": 1, "blocked": False}
        if "identifier" in list(fields) else None))
    seen = []

    def prompt(origin, site, extra_fields=(), notice="", identifier=""):
        seen.append(identifier)
        return {"identifier": "new@example.com", "password": "pw"}

    vault_unlock.set_save_login_prompt_callback(prompt)
    out = json.loads(vault.browser_vault_save_login(identifier="old@example.com", task_id="t"))
    assert out["success"] is True and seen == [""]


def test_the_tool_description_names_the_shortcut():
    assert "If you already know the username, pass identifier= and only the password is asked." in (
        vault.BROWSER_VAULT_SCHEMA["description"])
