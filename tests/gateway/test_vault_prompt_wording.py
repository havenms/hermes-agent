"""Login prompt cards speak to small-business owners, not engineers.

The clients are new to AI. Words like vault, token, 2FA or credentials made them stop and ask what
to do. Every card the client sees must avoid them and say plainly what to reply with.
"""

import re
from pathlib import Path

import pytest
import hermes_yaml as yaml

from gateway.vault_prompts import build_vault_prompt_callbacks

FORBIDDEN = re.compile(r"\b(vault|token|2fa|credentials?)\b", re.IGNORECASE)


def _cards():
    seen = []

    def ask(question, **kw):
        seen.append(question)
        return "owner@shop.com" if len(seen) == 1 else "x"

    callbacks = build_vault_prompt_callbacks(ask)
    callbacks["save_login"]("https://app.example.com", "app.example.com")
    callbacks["code"]("app.example.com", "")
    callbacks["unlock"]("bitwarden", "Bitwarden")
    return seen


def test_cards_use_plain_words():
    for card in _cards():
        assert not FORBIDDEN.search(card), card


def test_cards_say_what_to_reply_with():
    login, password, code, unlock = _cards()
    assert "email or username" in login and "(1/2)" in login
    assert "password" in password and "remove your message" in password and "(2/2)" in password
    assert "just sent a code to your phone or email" in code
    assert "Reply" in unlock


@pytest.mark.parametrize("key", [
    ("gateway", "clarify", "not_an_answer"), ("gateway", "clarify", "secret_not_deleted"),
    ("platform", "discord", "prompt", "secret_hint"), ("platform", "discord", "prompt", "secret_not_owner"),
    ("platform", "discord", "prompt", "secret_received"),
])
def test_client_facing_english_strings_use_plain_words(key):
    node = yaml.safe_load(open(Path(__file__).resolve().parents[2] / "locales" / "en.yaml", encoding="utf-8"))
    for part in key:
        node = node[part]
    assert not FORBIDDEN.search(node), node
