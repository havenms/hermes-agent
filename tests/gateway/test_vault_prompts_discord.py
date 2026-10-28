"""Vault prompts on Discord: who may answer, what counts as an answer, how long they wait,
and how the secret leaves the channel.

The PR that added gateway vault prompts was tested on Telegram only. These pin the parts that
differ on Discord: a thread session is shared by every member, the adapter had no
``delete_message``, a bot cannot delete the other person's message in a DM, and a modal can take
the secret without it ever being posted.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource
from tools import clarify_gateway as cm

# A Discord thread session key: shared by every member of the thread (no user part).
THREAD_KEY = "agent:main:discord:thread:777:777"
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


# ── clarify_gateway: owner and answer shape ─────────────────────────────────────────────────


def test_an_owner_bound_prompt_ignores_another_members_reply():
    entry = cm.register("v1", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER)
    assert cm.attempt_text_response_for_session(THREAD_KEY, "123456", responder_id=OTHER) == cm.TEXT_NOT_OWNER
    assert not entry.event.is_set(), "another member's message must leave the prompt armed"
    assert cm.attempt_text_response_for_session(THREAD_KEY, "123456", responder_id=OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "123456"


def test_an_ordinary_clarify_stays_answerable_by_anyone_in_the_thread():
    entry = cm.register("c1", THREAD_KEY, "which?", None)
    assert cm.attempt_text_response_for_session(THREAD_KEY, "the blue one", responder_id=OTHER) == cm.TEXT_RESOLVED
    assert entry.response == "the blue one"


def test_a_reply_that_is_not_shaped_like_the_answer_keeps_the_prompt_open():
    from gateway.vault_prompts import CODE_PATTERN
    entry = cm.register("v2", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER,
                        answer_pattern=CODE_PATTERN)
    for chatter in ("are you there?", "hello", "ok"):
        assert cm.attempt_text_response_for_session(THREAD_KEY, chatter, OWNER) == cm.TEXT_NOT_AN_ANSWER
    assert not entry.event.is_set()
    assert cm.attempt_text_response_for_session(THREAD_KEY, "123 456", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "123 456"


def test_skip_always_counts_and_reaches_the_waiter_as_the_skip_sentinel():
    from gateway.vault_prompts import IDENTIFIER_PATTERN
    entry = cm.register("v3", THREAD_KEY, "user?", None, owner_user_id=OWNER, answer_pattern=IDENTIFIER_PATTERN)
    assert cm.attempt_text_response_for_session(THREAD_KEY, "skip", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == cm.SKIPPED


@pytest.mark.parametrize("text, ok", [
    ("123456", True), ("123 456", True), ("G-123456", True), ("X7K-9PQ", True),
    ("are you there", False), ("hello?", False), ("12", False), ("abcdef", False),
])
def test_code_pattern(text, ok):
    import re
    from gateway.vault_prompts import CODE_PATTERN
    assert bool(re.fullmatch(CODE_PATTERN, text)) is ok


# ── the runner seam: owner, wait and pattern per prompt kind ────────────────────────────────


def _runner_with_source(user_id):
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(source=SimpleNamespace(user_id=user_id))
    calls = []
    runner._ask_clarify_question = lambda q, c, m, **kw: calls.append(kw) or ("answer", True)
    return runner, calls


def test_vault_ask_binds_the_prompt_to_the_turns_user_and_its_kinds_wait(monkeypatch):
    import gateway.vault_prompts as vp
    monkeypatch.setattr(vp, "vault_prompt_timeout", lambda kind: {"code": 1800.0, "save_login": 14400.0}[kind])
    runner, calls = _runner_with_source(OWNER)
    assert runner._vault_ask_sync("code?", secret=True, kind="code", answer_pattern=vp.CODE_PATTERN) == "answer"
    assert runner._vault_ask_sync("user?", secret=False, last=False, kind="save_login") == "answer"
    assert calls[0]["owner_user_id"] == OWNER and calls[0]["timeout"] == 1800.0
    assert calls[0]["answer_pattern"] == vp.CODE_PATTERN
    assert calls[1]["timeout"] == 14400.0 and calls[1]["rearm"] is False


@pytest.mark.parametrize("sentinel", [cm.SKIPPED, cm.CANCELLED])
def test_vault_ask_turns_skip_and_cancel_into_a_decline(sentinel):
    """A typed "skip" must never be stored as a username or typed into the page as a code."""
    from gateway.run_turn_runner import TurnRunner
    runner = object.__new__(TurnRunner)
    runner._ctx = None
    runner._ask_clarify_question = lambda q, c, m, **kw: (sentinel, True)
    assert runner._vault_ask_sync("code?", secret=True) == ""


def test_vault_prompt_timeout_defaults_and_config(monkeypatch):
    import gateway.vault_prompts as vp
    import tools.browser_session_cloud as cloud
    monkeypatch.setattr(cloud, "browser_section", lambda: {})
    assert vp.vault_prompt_timeout("save_login") == 4 * 3600
    assert vp.vault_prompt_timeout("code") == 30 * 60
    monkeypatch.setattr(cloud, "browser_section", lambda: {"vault_code_timeout": 300, "vault_save_login_timeout": 0})
    assert vp.vault_prompt_timeout("code") == 300
    assert vp.vault_prompt_timeout("save_login") == 0, "0 means no limit"


def test_the_password_card_names_the_identifier_it_will_save():
    from gateway.vault_prompts import IDENTIFIER_PATTERN, build_vault_prompt_callbacks
    seen = []

    def ask(question, **kw):
        seen.append((question, kw))
        return "someone@example.com" if len(seen) == 1 else "pw"

    build_vault_prompt_callbacks(ask)["save_login"]("https://example.com", "example.com")
    assert seen[0][1]["answer_pattern"] == IDENTIFIER_PATTERN and seen[0][1]["kind"] == "save_login"
    assert "someone@example.com" in seen[1][0]


def test_clarify_wait_uses_the_given_timeout_instead_of_the_clarify_timeout(monkeypatch):
    from gateway import run_turn_runner_clarify_delivery as delivery
    seen = {}
    fake_mod = SimpleNamespace(
        get_clarify_timeout=lambda: 3600, CANCELLED=cm.CANCELLED, clear_session=lambda key: 0,
        wait_for_response=lambda cid, timeout: seen.setdefault("timeout", timeout) and None,
    )
    monkeypatch.setattr("gateway.run._approval_send_outcome", lambda fut, timeout: "sent")
    response, answered = delivery._clarify_send_then_wait(
        SimpleNamespace(), clarify_id="x", session_key="k", clarify_mod=fake_mod, timeout=1800.0)
    assert seen["timeout"] == 1800.0
    assert answered is False and "30m" in response


# ── the inbound intercept on a shared Discord thread ────────────────────────────────────────


class _Adapter(BasePlatformAdapter):
    def __init__(self, delete_ok=True):
        super().__init__(PlatformConfig(enabled=True, token="t"), Platform.DISCORD)
        self.deleted, self.sent, self.delete_ok = [], [], delete_ok

    async def connect(self, *, is_reconnect: bool = False):
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append((chat_id, content, reply_to, metadata))
        return SendResult(success=True, message_id="m")

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}

    async def delete_message(self, chat_id, message_id):
        self.deleted.append((chat_id, message_id))
        return self.delete_ok


class _FellThrough(Exception):
    pass


def _event(text, user_id):
    return MessageEvent(
        text=text, message_type=MessageType.TEXT, message_id=f"msg-{user_id}",
        source=SessionSource(platform=Platform.DISCORD, chat_id="777", chat_type="thread",
                             user_id=user_id, thread_id="777"),
    )


def _runner(adapter):
    from gateway.run import GatewayRunner
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._startup_restore_in_progress = False
    runner._scale_to_zero_note_real_inbound = lambda: None
    runner._is_user_authorized = lambda source: True
    runner._session_key_for_source = lambda source: THREAD_KEY
    runner._delivery_adapter_for = lambda source: adapter
    runner._update_prompt_pending = {}
    return runner


async def _dispatch(runner, event):
    import tools.slash_confirm as slash_confirm_mod

    def _tripwire(_key):
        raise _FellThrough()

    with patch("hermes_cli.plugins.invoke_hook", return_value=[]), \
            patch.object(slash_confirm_mod, "get_pending", _tripwire):
        return await runner._handle_message(event)


@pytest.mark.asyncio
async def test_another_thread_member_cannot_answer_a_vault_prompt():
    adapter = _Adapter()
    entry = cm.register("v4", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER)
    with pytest.raises(_FellThrough):
        await _dispatch(_runner(adapter), _event("999999", OTHER))
    assert not entry.event.is_set()
    assert adapter.deleted == [], "another member's message is not a secret answer and is not deleted"


@pytest.mark.asyncio
async def test_the_owners_secret_is_consumed_and_deleted():
    adapter = _Adapter()
    entry = cm.register("v5", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER)
    assert await _dispatch(_runner(adapter), _event("123456", OWNER)) == ""
    assert entry.response == "123456"
    assert adapter.deleted == [("777", f"msg-{OWNER}")]
    assert all("123456" not in sent[1] for sent in adapter.sent), "the secret is never echoed"


@pytest.mark.asyncio
async def test_a_secret_the_platform_cannot_delete_gets_an_unanchored_notice():
    """A Discord DM: the bot cannot delete the user's message. Say so, without a reply anchor
    (a Discord reply previews the message it answers, which would show the secret again)."""
    adapter = _Adapter(delete_ok=False)
    cm.register("v6", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER)
    assert await _dispatch(_runner(adapter), _event("123456", OWNER)) == ""
    assert len(adapter.sent) == 1
    chat_id, text, reply_to, _meta = adapter.sent[0]
    assert reply_to is None and "123456" not in text


@pytest.mark.asyncio
async def test_chatter_after_a_long_wait_keeps_the_prompt_and_gets_a_hint():
    from gateway.vault_prompts import CODE_PATTERN
    adapter = _Adapter()
    entry = cm.register("v7", THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER,
                        answer_pattern=CODE_PATTERN)
    assert await _dispatch(_runner(adapter), _event("hi, are you still there?", OWNER)) == ""
    assert not entry.event.is_set()
    assert len(adapter.sent) == 1 and adapter.sent[0][2] is None


# ── the Discord adapter: delete, private-entry button and modal ─────────────────────────────


def _discord_adapter():
    from plugins.platforms.discord.adapter import DiscordAdapter
    adapter = DiscordAdapter(PlatformConfig(enabled=True, token="test-token", extra={}))
    adapter._client = MagicMock()
    # Both users pass the allowlist: the owner check is what must stop the other member.
    adapter._allowed_user_ids = {OWNER, OTHER}
    adapter._allowed_role_ids = set()
    return adapter


@pytest.mark.asyncio
async def test_discord_delete_message_deletes_through_the_channel():
    adapter = _discord_adapter()
    partial = MagicMock()
    partial.delete = AsyncMock()
    channel = MagicMock()
    channel.get_partial_message = MagicMock(return_value=partial)
    adapter._client.get_channel = MagicMock(return_value=channel)
    assert await adapter.delete_message("777", "42") is True
    channel.get_partial_message.assert_called_once_with(42)
    partial.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_discord_delete_message_reports_a_refusal_as_false():
    adapter = _discord_adapter()
    partial = MagicMock()
    partial.delete = AsyncMock(side_effect=RuntimeError("403 Forbidden (error code: 50003)"))
    channel = MagicMock()
    channel.get_partial_message = MagicMock(return_value=partial)
    adapter._client.get_channel = MagicMock(return_value=channel)
    assert await adapter.delete_message("777", "42") is False


async def _send_secret_card(adapter, clarify_id="v8"):
    cm.register(clarify_id, THREAD_KEY, "code?", None, secret=True, owner_user_id=OWNER)
    channel = MagicMock()
    sent = MagicMock()
    sent.id = 555
    sent.embeds = []
    sent.edit = AsyncMock()
    channel.send = AsyncMock(return_value=sent)
    adapter._client.get_channel = MagicMock(return_value=channel)
    result = await adapter.send_clarify(chat_id="777", question="code?", choices=None,
                                        clarify_id=clarify_id, session_key=THREAD_KEY)
    assert result.success
    view = channel.send.call_args.kwargs.get("view")
    if view is not None:
        view.live_auth = None  # no gateway behind this adapter: the connect-time allowlist decides
    return view, sent


def _interaction(user_id):
    return SimpleNamespace(
        user=SimpleNamespace(id=user_id, display_name="u", roles=[]),
        response=SimpleNamespace(send_message=AsyncMock(), send_modal=AsyncMock(), edit_message=AsyncMock()),
        message=None,
    )


@pytest.mark.asyncio
async def test_a_secret_card_carries_a_private_entry_button_and_a_plain_card_does_not():
    from plugins.platforms.discord.adapter import SecretPromptView
    adapter = _discord_adapter()
    view, _ = await _send_secret_card(adapter)
    assert isinstance(view, SecretPromptView) and view.owner_user_id == OWNER
    cm.register("plain", THREAD_KEY, "name?", None)
    channel = adapter._client.get_channel.return_value
    await adapter.send_clarify(chat_id="777", question="name?", choices=None, clarify_id="plain",
                               session_key=THREAD_KEY)
    assert "view" not in channel.send.call_args.kwargs


@pytest.mark.asyncio
async def test_only_the_owner_can_open_the_modal(monkeypatch):
    import plugins.platforms.discord.adapter as discord_adapter
    adapter = _discord_adapter()
    view, _ = await _send_secret_card(adapter)

    class _Modal:
        def __init__(self, *, title=None, timeout=None):
            self.title, self.items = title, []

        def add_item(self, item):
            self.items.append(item)

    monkeypatch.setattr(discord_adapter.discord.ui, "Modal", _Modal, raising=False)
    monkeypatch.setattr(discord_adapter.discord.ui, "TextInput", lambda **kw: SimpleNamespace(value="", **kw),
                        raising=False)
    monkeypatch.setattr(discord_adapter.discord, "TextStyle", SimpleNamespace(short=1), raising=False)

    stranger = _interaction(OTHER)
    await view._on_click(stranger)
    stranger.response.send_modal.assert_not_awaited()
    stranger.response.send_message.assert_awaited_once()
    assert stranger.response.send_message.call_args.kwargs.get("ephemeral") is True

    owner = _interaction(OWNER)
    await view._on_click(owner)
    owner.response.send_modal.assert_awaited_once()
    modal = owner.response.send_modal.call_args.args[0]
    assert len(modal.title) <= 45


@pytest.mark.asyncio
async def test_a_modal_answer_resolves_the_prompt_privately_and_closes_the_card():
    adapter = _discord_adapter()
    view, sent = await _send_secret_card(adapter, "v9")
    owner = _interaction(OWNER)
    await view.submit(owner, " 123456 ")
    assert cm.get_pending("v9") is None
    reply = owner.response.send_message.call_args
    assert reply.kwargs.get("ephemeral") is True and "123456" not in reply.args[0]
    assert view.resolved and "v9" not in adapter._secret_prompt_views
    sent.edit.assert_awaited()


@pytest.mark.asyncio
async def test_retire_closes_a_secret_card_after_a_typed_answer():
    adapter = _discord_adapter()
    view, sent = await _send_secret_card(adapter, "v10")
    await adapter.retire_clarify_card("v10", "✅ answered")
    assert view.resolved and view.is_finished()
    assert "v10" not in adapter._secret_prompt_views
    await adapter.retire_clarify_card("not-a-secret-card", "whatever")  # no-op
