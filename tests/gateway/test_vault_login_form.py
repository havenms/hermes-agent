"""One private form for every login field (Discord).

The first login card offers ONE "Enter privately" button. It opens one modal with a text input per
field (email or username, password, extras such as a PIN). Its submit answers the whole sequence at
once, so the remaining cards are never sent. A typed reply still goes card by card. Only the asking
user can open or submit the form.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import PlatformConfig
from gateway.vault_prompts import MAX_FORM_FIELDS, build_vault_prompt_callbacks
from tools import clarify_gateway as cm

KEY = "agent:main:discord:dm:1001"
OWNER, OTHER = "1001", "2002"


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


def _form_answer(values):
    return cm.FORM_ANSWER_PREFIX + json.dumps(values)


# ── vault_prompts: the first card carries the form ────────────────────────────────────────────

def test_the_first_card_offers_one_form_with_every_field_and_a_submit_answers_all():
    asked = []

    def ask(question, **kw):
        asked.append((question, kw))
        return _form_answer({"identifier": "owner@example.com", "password": "pw", "extra:PIN": "4321"})

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "TestCo Books", ("PIN",))
    assert got == {"identifier": "owner@example.com", "password": "pw", "extra": {"PIN": "4321"}}
    assert len(asked) == 1, "a form submit skips the remaining cards"
    form = asked[0][1]["form_fields"]
    assert [f["key"] for f in form] == ["identifier", "password", "extra:PIN"]
    assert [f["secret"] for f in form] == [False, True, True]
    assert all("pattern" not in f for f in form), "round 6: the private form has no shape check"
    assert "(secret)" in form[1]["label"] and "PIN" in form[2]["label"]
    assert "(1/3)" in asked[0][0]


def test_a_typed_reply_still_goes_card_by_card():
    asked = []
    answers = iter(["owner", "pw", "4321"])

    def ask(question, **kw):
        asked.append(kw)
        return next(answers)

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Shop", ("PIN",))
    assert got == {"identifier": "owner", "password": "pw", "extra": {"PIN": "4321"}}
    assert len(asked) == 3 and "form_fields" in asked[0]
    assert all("form_fields" not in kw for kw in asked[1:])


def test_a_login_with_more_fields_than_discord_allows_has_no_form():
    asked = []
    answers = iter(["owner", "pw", "1", "2", "3", "4"])
    extras = ("PIN", "Answer", "Word", "Code word")
    assert 2 + len(extras) > MAX_FORM_FIELDS

    def ask(question, **kw):
        asked.append(kw)
        return next(answers)
    build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Shop", extras)
    assert all("form_fields" not in kw for kw in asked)


def test_a_surface_without_a_form_gets_the_old_cards():
    asked = []
    answers = iter(["owner", "pw"])

    def ask(question, secret=False, last=True, kind="", answer_pattern=None, chat_guard=False):
        asked.append(question)
        return next(answers)
    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Shop")
    assert got == {"identifier": "owner", "password": "pw"} and len(asked) == 2


def test_a_form_answer_with_a_missing_field_stores_nothing():
    ask = lambda q, **kw: _form_answer({"identifier": "owner", "password": ""})  # noqa: E731
    assert build_vault_prompt_callbacks(ask)["save_login"]("https://x", "Shop") is None


# ── clarify_gateway: the form answer ─────────────────────────────────────────────────────────

FORM = [{"key": "identifier", "label": "Email or username", "secret": False},
        {"key": "password", "label": "Password (secret)", "secret": True}]


def test_only_the_asking_user_can_submit_the_form():
    entry = cm.register("f1", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    values = {"identifier": "owner", "password": " pass word "}
    assert cm.attempt_form_response_for_entry("f1", values, responder_id=OTHER) == cm.TEXT_NOT_OWNER
    assert not entry.event.is_set()
    assert cm.attempt_form_response_for_entry("f1", values, responder_id=OWNER) == cm.TEXT_RESOLVED
    # Round 6: a password is kept as typed. Only the identifier loses the spaces at its ends.
    assert json.loads(entry.response[len(cm.FORM_ANSWER_PREFIX):]) == {"identifier": "owner",
                                                                        "password": " pass word "}


@pytest.mark.parametrize("values", [{"identifier": "owner"}, {"identifier": "owner", "password": "   "},
                                    {"identifier": "", "password": "pw"}])
def test_a_form_with_a_missing_or_bad_field_keeps_the_prompt_open(values):
    entry = cm.register("f2", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    assert cm.attempt_form_response_for_entry("f2", values, responder_id=OWNER) == cm.TEXT_NOT_AN_ANSWER
    assert not entry.event.is_set()


def test_a_prompt_without_a_form_refuses_a_form_answer():
    cm.register("f3", KEY, "code?", None, secret=True, owner_user_id=OWNER)
    assert cm.attempt_form_response_for_entry("f3", {"x": "1"}, responder_id=OWNER) == cm.TEXT_NOT_AN_ANSWER


def test_the_runner_passes_the_form_to_the_card():
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(source=SimpleNamespace(user_id=OWNER))
    calls = []
    runner._ask_clarify_question = lambda q, c, m, **kw: calls.append(kw) or ("x", True)
    runner._vault_ask_sync("login?", secret=False, kind="save_login", form_fields=FORM)
    assert calls[0]["form_fields"] == FORM and calls[0]["owner_user_id"] == OWNER


# ── Discord: one button, one modal ───────────────────────────────────────────────────────────

def _discord_adapter():
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


async def _send_form_card(adapter, clarify_id="f9", form=FORM):
    cm.register(clarify_id, KEY, "login (1/2)?", None, owner_user_id=OWNER, form_fields=form, kind="save_login")
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
    return view, sent, channel.send.call_args.kwargs["content"]


@pytest.fixture()
def fake_modal(monkeypatch):
    import plugins.platforms.discord.adapter as discord_adapter

    class _Modal:
        def __init__(self, *, title=None, timeout=None):
            self.title, self.items = title, []

        def add_item(self, item):
            self.items.append(item)

    monkeypatch.setattr(discord_adapter.discord.ui, "Modal", _Modal, raising=False)
    monkeypatch.setattr(discord_adapter.discord.ui, "TextInput", lambda **kw: SimpleNamespace(value="", **kw),
                        raising=False)
    monkeypatch.setattr(discord_adapter.discord, "TextStyle", SimpleNamespace(short=1), raising=False)


@pytest.mark.asyncio
async def test_the_first_card_has_one_button_that_opens_one_modal_with_every_field(fake_modal):
    adapter = _discord_adapter()
    view, _, content = await _send_form_card(adapter)
    assert view.form_fields and "all 2" in content
    stranger = _interaction(OTHER)
    await view._on_click(stranger)
    stranger.response.send_modal.assert_not_awaited()
    owner = _interaction(OWNER)
    await view._on_click(owner)
    modal = owner.response.send_modal.call_args.args[0]
    assert [i.label for i in modal.items] == ["Email or username", "Password (secret)"]
    assert all(len(i.label) <= 45 for i in modal.items) and len(modal.title) <= 45


@pytest.mark.asyncio
async def test_a_form_submit_resolves_the_card_privately():
    adapter = _discord_adapter()
    view, sent, _ = await _send_form_card(adapter, "f10")
    owner = _interaction(OWNER)
    await view.submit_form(owner, {"identifier": "owner", "password": "pw"})
    assert cm.get_pending("f10") is None
    reply = owner.response.send_message.call_args
    assert reply.kwargs.get("ephemeral") is True and "pw" not in reply.args[0]
    assert view.resolved and "f10" not in adapter._secret_prompt_views
    sent.edit.assert_awaited()


@pytest.mark.asyncio
async def test_another_member_cannot_submit_the_form():
    adapter = _discord_adapter()
    view, _, _ = await _send_form_card(adapter, "f11")
    stranger = _interaction(OTHER)
    await view.submit_form(stranger, {"identifier": "x", "password": "y"})
    assert cm.get_pending("f11") is not None and not view.resolved


@pytest.mark.asyncio
async def test_a_typed_reply_retires_the_form_button():
    adapter = _discord_adapter()
    view, _, _ = await _send_form_card(adapter, "f12")
    await adapter.retire_clarify_card("f12", "✅ answered")
    assert view.resolved and "f12" not in adapter._secret_prompt_views
def test_the_login_form_keeps_the_password_as_typed():
    cm.register("f1", KEY, "login", None, owner_user_id=OWNER, kind="save_login",
                form_fields=[{"key": "identifier", "label": "Email", "secret": False},
                             {"key": "password", "label": "Password (secret)", "secret": True}])
    assert cm.attempt_form_response_for_entry("f1", {"identifier": "  a@example.com ", "password": "  pw  "},
                                              OWNER) == cm.TEXT_RESOLVED
    answer = json.loads(cm._entries["f1"].response[len(cm.FORM_ANSWER_PREFIX):])
    assert answer == {"identifier": "a@example.com", "password": "  pw  "}


@pytest.mark.parametrize("values", [
    {"identifier": "MICHAEL PERSONETTE", "password": "pw"},
    {"identifier": "two words", "password": "pw"},
    {"identifier": "x", "password": "a b c"},
    {"identifier": "hi", "password": "?"},
])
def test_the_login_form_takes_any_value_that_is_not_empty(values):
    # Round 6, live 2026-10-29: the form refused "MICHAEL PERSONETTE" as not an email or username.
    entry = cm.register("f9", KEY, "login?", None, owner_user_id=OWNER, form_fields=FORM)
    assert cm.attempt_form_response_for_entry("f9", values, responder_id=OWNER) == cm.TEXT_RESOLVED
    assert json.loads(entry.response[len(cm.FORM_ANSWER_PREFIX):]) == values


def test_the_private_box_skips_the_shape_check_but_the_chat_keeps_it():
    from gateway.vault_prompts import CODE_PATTERN
    entry = cm.register("f10", KEY, "code?", None, secret=True, owner_user_id=OWNER, answer_pattern=CODE_PATTERN,
                        kind="code")
    assert cm.attempt_text_response_for_session(KEY, "hello", OWNER) == cm.TEXT_NOT_AN_ANSWER
    assert cm.attempt_text_response_for_entry("f10", "  abc  ", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "abc", "a code loses the spaces at its ends"


def test_the_private_password_box_keeps_the_value_as_typed():
    entry = cm.register("f11", KEY, "pw?", None, secret=True, owner_user_id=OWNER, kind="save_login",
                        chat_guard=True)
    assert cm.attempt_text_response_for_entry("f11", "   ", OWNER) == cm.TEXT_NOT_AN_ANSWER
    assert cm.attempt_text_response_for_entry("f11", " my pass ", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == " my pass "


