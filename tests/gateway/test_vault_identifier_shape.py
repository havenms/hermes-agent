"""The email card never takes "hi" or "thanks" as the email, and a pasted login on it is deleted.

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


@pytest.mark.parametrize("text, ok", [
    ("me@example.com", True), ("+15551234567", True), ("jsmith", True), ("okayfine", True),
    ("hi", False), ("Hi!", False), ("hello", False), ("thanks", False), ("ok", False), ("yes", False),
    ("x", False), ("hi there", False),
])
def test_the_email_or_username_shape(text, ok):
    from gateway.vault_prompts import IDENTIFIER_PATTERN
    assert bool(re.fullmatch(IDENTIFIER_PATTERN, text)) is ok


def test_hi_on_the_email_card_is_not_an_answer():
    from gateway.vault_prompts import IDENTIFIER_PATTERN
    entry = cm.register("e1", KEY, "email?", None, owner_user_id=OWNER, answer_pattern=IDENTIFIER_PATTERN,
                        kind="save_login")
    assert cm.attempt_text_response_for_session(KEY, "hi", OWNER) == cm.TEXT_NOT_AN_ANSWER
    assert cm.attempt_text_response_for_session(KEY, "me@example.com", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "me@example.com"


@pytest.mark.asyncio
async def test_a_full_login_on_the_email_card_is_deleted():
    from gateway.vault_prompts import IDENTIFIER_PATTERN
    adapter = _Adapter()
    runner = _runner(adapter)
    cm.register("e1", KEY, "email?", None, owner_user_id=OWNER, answer_pattern=IDENTIFIER_PATTERN,
                kind="save_login")
    event = _event("me@example.com Pass1234")
    assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert adapter.deleted == ["m-1"]
    chat = _event("hi there", mid="m-3")
    assert await runner._hm_clarify_reply(chat, chat.source, KEY) == ""
    assert adapter.deleted == ["m-1"], "plain chat is not deleted"
