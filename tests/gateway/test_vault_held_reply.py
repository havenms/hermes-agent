"""A typed reply to a password card is used only when it is clearly a password; anything else is held
and the client confirms it with a button. A typed "yes" never becomes the password.

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


# ── 1 and 2: the typed password reply is held, never guessed ─────────────────────────────────


@pytest.mark.parametrize("text, secret", [
    ("Summer2024?", True), ("pa$$word", True), ("hunter2", True), ("Tr0ub4dor&3", True),
    ("yes", False), ("Yes!", False), ("ok", False), ("thanks", False), ("hello", False),
    ("password", False), ("me@example.com", False), ("https://example.com/x1", False),
    ("correct horse battery staple", False), ("Awesome!", False), ("123456", False), ("ab1", False),
])
def test_looks_like_secret(text, secret):
    assert cm.looks_like_secret(text) is secret


def test_a_clear_password_is_used_at_once():
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, "Summer2024?", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "Summer2024?"


@pytest.mark.parametrize("text", ["yes", "hey did that work?", "correct horse battery staple", "hello"])
def test_anything_else_is_held_and_the_card_stays_open(text):
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, text, OWNER) == cm.TEXT_HELD
    assert not entry.event.is_set()


def test_a_typed_yes_never_becomes_the_password():
    entry = _password_entry()
    hold = cm.hold_reply(entry, "correct horse battery staple")
    assert cm.attempt_text_response_for_session(KEY, "yes", OWNER) == cm.TEXT_HOLD_PENDING
    assert cm.attempt_text_response_for_session(KEY, "Yes.", OWNER) == cm.TEXT_HOLD_PENDING
    assert not entry.event.is_set()
    assert cm.get_hold(hold) is not None


def test_the_yes_button_uses_the_held_reply():
    entry = _password_entry()
    hold = cm.hold_reply(entry, "correct horse battery staple")
    assert cm.answer_held_reply(hold, True, OTHER)[0] == cm.HOLD_NOT_OWNER
    outcome, held = cm.answer_held_reply(hold, True, OWNER)
    assert outcome == cm.HOLD_USED and held.clarify_id == "p1"
    assert entry.response == "correct horse battery staple"
    assert cm.get_hold(hold) is None
    assert cm.answer_held_reply(hold, True, OWNER)[0] == cm.HOLD_GONE


def test_the_no_button_releases_the_text_and_keeps_the_card_open():
    entry = _password_entry()
    released = []
    hold = cm.hold_reply(entry, "hey did that work?", release=lambda: released.append(1))
    outcome, held = cm.answer_held_reply(hold, False, OWNER)
    assert outcome == cm.HOLD_RELEASED and held.text == "hey did that work?"
    assert not entry.event.is_set()


def test_yes_after_the_card_ended_drops_the_text():
    entry = _password_entry()
    hold = cm.hold_reply(entry, "letmein")
    cm.resolve_gateway_clarify("p1", cm.CANCELLED)
    cm.wait_for_response("p1", 0.01)
    assert cm.answer_held_reply(hold, True, OWNER) == (cm.HOLD_PROMPT_CLOSED, None)


def test_the_held_text_is_not_in_repr_and_clear_session_drops_it():
    entry = _password_entry()
    hold = cm.hold_reply(entry, "letmein")
    assert "letmein" not in repr(cm.get_hold(hold))
    cm.clear_session(KEY)
    assert cm.get_hold(hold) is None


def test_the_private_box_still_takes_any_passphrase():
    entry = _password_entry()
    assert cm.attempt_text_response_for_entry("p1", "correct horse battery staple", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "correct horse battery staple"


@pytest.mark.asyncio
async def test_inbound_holds_the_reply_deletes_it_and_posts_the_button_card(caplog):
    adapter = _ButtonAdapter()
    runner = _runner(adapter)
    entry = _password_entry()
    event = _event("correct horse battery staple")
    with caplog.at_level(logging.DEBUG):
        reply = await runner._hm_clarify_reply(event, event.source, KEY)
    assert reply == "", "the message is held: no turn, nothing routed"
    assert adapter.deleted == ["m-1"]
    assert len(adapter.cards) == 1 and adapter.cards[0][1:] == (OWNER, "p1")
    assert not entry.event.is_set()
    assert "correct horse" not in caplog.text, "the held text is never logged"
    hold_id = adapter.cards[0][0]
    outcome, held = cm.answer_held_reply(hold_id, False, OWNER)
    assert outcome == cm.HOLD_RELEASED
    await held.release()
    (released,) = adapter.handled
    assert released.text == "correct horse battery staple"
    from gateway.run_inbound import CLARIFY_BYPASS_KEY
    assert released.metadata.get(CLARIFY_BYPASS_KEY) is True
    # The released message is not taken by the open card a second time.
    assert await runner._hm_clarify_reply(released, released.source, KEY) is None
    # Round 5: "No, that was a message" closes the card, so the message is not stuck behind it.
    assert entry.response == cm.CANCELLED_BY_MESSAGE


@pytest.mark.asyncio
async def test_without_buttons_the_reply_is_kept_back_and_never_used():
    adapter = _Adapter()
    runner = _runner(adapter)
    entry = _password_entry()
    event = _event("hey did that work?")
    assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert adapter.deleted == ["m-1"] and not entry.event.is_set()
    assert cm._held == {}, "no button can use it, so it is dropped"
    assert any("did not use your last message" in text for text, _ in adapter.sent)


@pytest.mark.asyncio
async def test_inbound_typed_yes_while_a_hold_waits_asks_for_the_buttons():
    adapter = _ButtonAdapter()
    runner = _runner(adapter)
    entry = _password_entry()
    cm.hold_reply(entry, "hello")
    event = _event("yes", mid="m-2")
    assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert not entry.event.is_set()
    assert any("tap one of the buttons" in text for text, _ in adapter.sent)


def _view_adapter():
    from plugins.platforms.discord.adapter import DiscordAdapter
    adapter = DiscordAdapter(PlatformConfig(enabled=True, token="test-token", extra={}))
    adapter._client = MagicMock()
    adapter._allowed_user_ids = {OWNER, OTHER}
    adapter._allowed_role_ids = set()
    return adapter


def _interaction(user_id):
    return SimpleNamespace(
        user=SimpleNamespace(id=user_id, display_name="u", roles=[]),
        response=SimpleNamespace(send_message=AsyncMock(), send_modal=AsyncMock(), edit_message=AsyncMock()),
        message=None,
    )


async def _send_held_card(adapter, hold_id):
    channel = MagicMock()
    sent = MagicMock()
    sent.id = 556
    sent.embeds = []
    sent.edit = AsyncMock()
    channel.send = AsyncMock(return_value=sent)
    adapter._client.get_channel = MagicMock(return_value=channel)
    result = await adapter.send_held_reply_card("777", hold_id, OWNER, "p1")
    assert result.success
    view = channel.send.call_args.kwargs["view"]
    view.live_auth = None
    return view, channel.send.call_args.kwargs["content"]


@pytest.mark.asyncio
async def test_discord_held_card_has_two_buttons_and_names_the_private_route():
    adapter = _view_adapter()
    entry = _password_entry()
    hold = cm.hold_reply(entry, "letmein")
    view, content = await _send_held_card(adapter, hold)
    labels = [item.label for item in view.children]
    assert labels == ["Yes, that was my password", "No, that was a message"]
    assert "Enter privately" in content and "letmein" not in content


@pytest.mark.asyncio
async def test_discord_yes_button_answers_the_card_only_for_the_owner():
    adapter = _view_adapter()
    entry = _password_entry()
    hold = cm.hold_reply(entry, "letmein")
    view, _ = await _send_held_card(adapter, hold)
    stranger = _interaction(OTHER)
    await view._on_yes(stranger)
    assert not entry.event.is_set()
    owner = _interaction(OWNER)
    await view._on_yes(owner)
    assert entry.response == "letmein"


@pytest.mark.asyncio
async def test_discord_no_button_releases_the_message_as_chat():
    adapter = _view_adapter()
    entry = _password_entry()
    released = []

    async def release():
        released.append(True)
    hold = cm.hold_reply(entry, "hey did that work?", release=release)
    view, _ = await _send_held_card(adapter, hold)
    await view._on_no(_interaction(OWNER))
    assert released == [True] and not entry.event.is_set()
