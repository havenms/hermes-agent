"""Round 5, fix 1: a refused login answer always gets one short line that names the thing.

The live test: the private login form came back with an email that did not look like an email.
The log said ``outcome=not_an_answer`` and the client saw nothing. Now the modal replies at once
(ephemeral), names the box and the reason, and the card and its button stay for another try. The
typed nudge names what the card asks for ("your email or username for TestCo Books")."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import PlatformConfig
from gateway.vault_prompts import _login_form_fields, build_vault_prompt_callbacks
from tools import clarify_gateway as cm

KEY = "agent:main:discord:dm:1001"
OWNER = "1001"
FORM = _login_form_fields([])


@pytest.fixture(autouse=True)
def _clean_clarify_state():
    def clear():
        with cm._lock:
            cm._entries.clear()
            cm._session_index.clear()
            cm._notify_cbs.clear()
    clear()
    yield
    clear()


# ── the reason for a refused form ───────────────────────────────────────────────────────────

def test_form_problem_names_the_email_box_when_it_is_not_an_email():
    cm.register("p1", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    assert cm.form_problem("p1", {"identifier": "two words", "password": "pw"}) == (
        "Email or username", cm.FORM_PROBLEM_IDENTIFIER)


def test_form_problem_names_an_empty_box_without_the_secret_suffix():
    cm.register("p2", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    assert cm.form_problem("p2", {"identifier": "owner@example.com", "password": "  "}) == (
        "Password", cm.FORM_PROBLEM_EMPTY)


def test_form_problem_is_none_for_a_good_form_or_a_closed_prompt():
    cm.register("p3", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    assert cm.form_problem("p3", {"identifier": "owner@example.com", "password": "pw"}) is None
    assert cm.form_problem("gone", {"identifier": "x"}) is None


def test_the_form_problem_text_is_plain_and_holds_no_value():
    from plugins.platforms.discord.adapter_secret_prompt_view import form_problem_text
    text = form_problem_text("Email or username", cm.FORM_PROBLEM_IDENTIFIER)
    assert "does not look like an email address" in text and "Enter privately" in text
    assert "Password" in form_problem_text("Password", cm.FORM_PROBLEM_EMPTY)
    assert "PIN" in form_problem_text("PIN", cm.FORM_PROBLEM_SHAPE)


# ── what each card needs ────────────────────────────────────────────────────────────────────

def test_every_vault_card_says_what_it_needs():
    seen = []

    def ask(question, secret=True, last=True, kind="code", answer_pattern=None, chat_guard=False,
            form_fields=None, need=""):
        seen.append(need)
        return "" if len(seen) > 3 else {1: "owner@example.com", 2: "Summer2024?", 3: "1234"}[len(seen)]

    cbs = build_vault_prompt_callbacks(ask)
    cbs["save_login"]("https://books.example.com", "TestCo Books", extra_fields=("PIN",))
    cbs["code"]("TestCo Books", "")
    cbs["unlock"]("bitwarden", "Bitwarden")
    assert seen == ["your email or username for TestCo Books", "your password for TestCo Books",
                    "your PIN for TestCo Books", "the code TestCo Books sent you",
                    "the main password for Bitwarden"]


def test_an_ask_without_need_still_works():
    def ask(question, secret=True, last=True, kind="code", answer_pattern=None, chat_guard=False):
        return "123456"
    assert build_vault_prompt_callbacks(ask)["code"]("TestCo Books", "") == "123456"


def test_the_runner_passes_need_to_the_card():
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(source=SimpleNamespace(user_id=OWNER))
    calls = []
    runner._ask_clarify_question = lambda q, c, m, **kw: calls.append(kw) or ("x", True)
    runner._vault_ask_sync("login?", secret=False, kind="save_login", need="your email for TestCo Books")
    assert calls[0]["need"] == "your email for TestCo Books"


def test_the_typed_nudge_names_the_thing():
    from gateway.run_inbound import not_an_answer_text
    entry = cm.register("n1", KEY, "login?", None, owner_user_id=OWNER,
                        need="your email or username for TestCo Books")
    text = not_an_answer_text(entry)
    assert "your email or username for TestCo Books" in text
    assert "what I asked for above" not in text
    plain = cm.register("n2", KEY, "q?", None)
    assert "what I asked for above" in not_an_answer_text(plain)


# ── Discord: the modal replies at once and keeps the card ───────────────────────────────────

def _discord_adapter():
    from plugins.platforms.discord.adapter import DiscordAdapter
    adapter = DiscordAdapter(PlatformConfig(enabled=True, token="test-token", extra={}))
    adapter._client = MagicMock()
    adapter._allowed_user_ids = {OWNER}
    adapter._allowed_role_ids = set()
    return adapter


def _interaction(fail_response=False):
    send = AsyncMock(side_effect=RuntimeError("already responded")) if fail_response else AsyncMock()
    return SimpleNamespace(
        user=SimpleNamespace(id=OWNER, display_name="u", roles=[]),
        response=SimpleNamespace(send_message=send, send_modal=AsyncMock(), edit_message=AsyncMock()),
        followup=SimpleNamespace(send=AsyncMock()),
        message=None,
    )


async def _send_form_card(adapter, clarify_id):
    cm.register(clarify_id, KEY, "login (1/2)?", None, owner_user_id=OWNER, form_fields=FORM, kind="save_login",
                need="your email or username for TestCo Books")
    channel = MagicMock()
    sent = MagicMock()
    sent.id = 555
    sent.embeds = []
    sent.edit = AsyncMock()
    channel.send = AsyncMock(return_value=sent)
    adapter._client.get_channel = MagicMock(return_value=channel)
    result = await adapter.send_clarify(chat_id="777", question="login (1/2)?", choices=None,
                                        clarify_id=clarify_id, session_key=KEY)
    assert result.success
    view = channel.send.call_args.kwargs.get("view")
    view.live_auth = None
    return view


@pytest.mark.asyncio
async def test_a_bad_email_in_the_form_gets_an_ephemeral_line_and_the_card_stays():
    adapter = _discord_adapter()
    view = await _send_form_card(adapter, "d1")
    owner = _interaction()
    await view.submit_form(owner, {"identifier": "not an email", "password": "Summer2024?"})
    reply = owner.response.send_message.call_args
    assert reply.kwargs.get("ephemeral") is True
    assert "does not look like an email address" in reply.args[0]
    assert "Summer2024?" not in reply.args[0]
    assert cm.get_pending("d1") is not None and not view.resolved
    # Another try on the same card works.
    again = _interaction()
    await view.submit_form(again, {"identifier": "owner@example.com", "password": "Summer2024?"})
    assert cm.get_pending("d1") is None


@pytest.mark.asyncio
async def test_a_failed_ephemeral_reply_falls_back_to_a_follow_up():
    adapter = _discord_adapter()
    view = await _send_form_card(adapter, "d2")
    owner = _interaction(fail_response=True)
    await view.submit_form(owner, {"identifier": "", "password": "pw"})
    sent = owner.followup.send.call_args
    assert sent.kwargs.get("ephemeral") is True and "Email or username" in sent.args[0]
