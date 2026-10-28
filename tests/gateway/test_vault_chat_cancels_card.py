"""Round 5: a client can talk to the bot while a login card is open.

The live test: with a card open, "what's up ?" got only the waiting line, and a card can stay open
for 4 hours. Now the first plain non-answer gets the named nudge. A second one, or any clearly
conversational message, closes the card and goes to the agent as a normal turn. The vault tool
returns prompt_cancelled_by_client_message. A reply that may hold a secret is never routed.
Fake values only."""

import json
import threading

import pytest

from gateway.vault_prompts import CODE_PATTERN, IDENTIFIER_PATTERN
from tests.gateway.vault_review_helpers import (
    KEY, OWNER, ButtonAdapter, FakeAdapter, clear_clarify, make_event, password_entry, runner_for,
)
from tools import clarify_gateway as cm


@pytest.fixture(autouse=True)
def _clean():
    clear_clarify()
    cm.mark_cancelled_by_message(False)
    yield
    clear_clarify()
    cm.mark_cancelled_by_message(False)


def _email_card(cid="e1"):
    return cm.register(cid, KEY, "🔑 login (1/2)", None, owner_user_id=OWNER, answer_pattern=IDENTIFIER_PATTERN,
                       kind="save_login", need="your email or username for TestCo Books")


def _code_card(cid="c1"):
    return cm.register(cid, KEY, "🔢 code", None, secret=True, owner_user_id=OWNER, answer_pattern=CODE_PATTERN,
                       kind="code", need="the code TestCo Books sent you")


@pytest.mark.parametrize("text, chat", [
    ("what's up ?", True), ("whats up", True), ("what's up", True), ("hey can you check my invoices?", True),
    ("hey can you check my invoices", True), ("how is it going?", True), ("are you there", True),
    ("hi there", False), ("hi", False), ("me@example.com", False), ("me@example.com is it?", False),
    ("is my password Summer2024? ok", False), ("123456", False), ("jsmith", False),
])
def test_what_counts_as_conversational(text, chat):
    assert cm.looks_conversational(text) is chat


@pytest.mark.asyncio
async def test_whats_up_on_the_email_card_closes_it_and_routes_the_message():
    adapter = FakeAdapter()
    runner = runner_for(adapter)
    entry = _email_card()
    event = make_event("what's up ?")
    assert await runner._hm_clarify_reply(event, event.source, KEY) is None  # routed as a normal turn
    assert entry.event.is_set() and entry.response == cm.CANCELLED_BY_MESSAGE
    assert not any("still waiting" in c for c, _ in adapter.sent)


@pytest.mark.asyncio
async def test_the_first_plain_non_answer_gets_the_named_nudge_and_the_second_closes_the_card():
    adapter = FakeAdapter()
    runner = runner_for(adapter)
    entry = _email_card()
    first = make_event("hi there")
    assert await runner._hm_clarify_reply(first, first.source, KEY) == ""
    assert not entry.event.is_set()
    assert any("your email or username for TestCo Books" in c for c, _ in adapter.sent)
    second = make_event("ok", mid="m-2")
    assert await runner._hm_clarify_reply(second, second.source, KEY) is None
    assert entry.response == cm.CANCELLED_BY_MESSAGE


@pytest.mark.asyncio
async def test_a_message_with_a_code_never_closes_the_code_card():
    adapter = FakeAdapter()
    runner = runner_for(adapter)
    entry = _code_card()
    for n, text in enumerate(["the code is 123456", "it is 123456 i think"]):
        event = make_event(text, mid=f"m-{n}")
        assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert not entry.event.is_set()


@pytest.mark.asyncio
async def test_a_secret_shaped_word_never_closes_the_card():
    adapter = FakeAdapter()
    runner = runner_for(adapter)
    entry = _email_card()
    for n, text in enumerate(["what about Summer2024? now", "me@example.com and what?"]):
        event = make_event(text, mid=f"m-{n}")
        assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert not entry.event.is_set()


@pytest.mark.asyncio
async def test_a_question_on_the_password_card_is_still_held_not_routed():
    adapter = ButtonAdapter()
    runner = runner_for(adapter)
    entry = password_entry()
    event = make_event("what's up ?")
    assert await runner._hm_clarify_reply(event, event.source, KEY) == ""
    assert not entry.event.is_set() and adapter.cards and adapter.handled == []


@pytest.mark.asyncio
async def test_no_that_was_a_message_closes_the_password_card_then_routes_the_message():
    adapter = ButtonAdapter()
    runner = runner_for(adapter)
    entry = password_entry()
    event = make_event("what's up ?")
    await runner._hm_clarify_reply(event, event.source, KEY)
    hold_id = adapter.cards[0][0]
    outcome, held = cm.answer_held_reply(hold_id, False, OWNER)
    assert outcome == cm.HOLD_RELEASED
    await held.release()
    assert entry.response == cm.CANCELLED_BY_MESSAGE
    assert len(adapter.handled) == 1


def test_the_vault_ask_reports_a_card_closed_by_a_message():
    from types import SimpleNamespace
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(source=SimpleNamespace(user_id=OWNER))
    runner._ask_clarify_question = lambda q, c, m, **kw: (cm.CANCELLED_BY_MESSAGE, True)
    assert runner._vault_ask_sync("login?", kind="save_login") == ""
    assert cm.pop_cancelled_by_message() is True
    assert cm.pop_cancelled_by_message() is False


def test_a_plain_decline_is_not_reported_as_a_message():
    from types import SimpleNamespace
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(source=SimpleNamespace(user_id=OWNER))
    cm.mark_cancelled_by_message(True)  # left over from an earlier card
    runner._ask_clarify_question = lambda q, c, m, **kw: (cm.SKIPPED, True)
    assert runner._vault_ask_sync("login?", kind="save_login") == ""
    assert cm.pop_cancelled_by_message() is False


def test_the_marker_is_per_thread():
    cm.mark_cancelled_by_message(True)
    seen = []
    t = threading.Thread(target=lambda: seen.append(cm.pop_cancelled_by_message()))
    t.start()
    t.join()
    assert seen == [False] and cm.pop_cancelled_by_message() is True


def test_the_tool_result_is_clean_and_tells_the_model_to_answer_first():
    from tools.browser_vault_tool import _cancelled_by_message_result
    result = json.loads(_cancelled_by_message_result("TestCo Books"))
    assert result["error_type"] == "prompt_cancelled_by_client_message" and result["success"] is False
    assert "Answer it first" in result["error"] and "TestCo Books" in result["error"]
    assert set(result) == {"success", "error_type", "error"}


def test_the_tool_description_names_the_new_result():
    from tools import browser_vault_tool as bv
    import inspect
    assert "On \"\n        \"prompt_cancelled_by_client_message, answer the client's message first" in inspect.getsource(bv)
