"""A typed reply to a password prompt that reads like chat is never used as the password.

With a 4-hour wait, a client who comes back and types "hey did that work?" had that message saved
as the password and deleted without a word. Now such a reply stays in the chat, the prompt stays
open, the bot asks "Is that your password?", and the message continues as normal chat.
"""

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource
from tools import clarify_gateway as cm

KEY = "agent:main:discord:thread:777:777"
OWNER = "1001"


@pytest.fixture(autouse=True)
def _clean():
    def clear():
        with cm._lock:
            cm._entries.clear()
            cm._session_index.clear()
    clear()
    yield
    clear()


@pytest.mark.parametrize("text, chat", [
    ("hey did that work?", True), ("ok", True), ("Thanks!", True), ("any update", True),
    ("still waiting", True), ("is it done", True), ("pass?word", True), ("my new pass word", True),
    ("hunter2", False), ("Tr0ub4dor&3", False), ("correct horse", False), ("candle123", False),
])
def test_looks_like_chat(text, chat):
    assert cm.looks_like_chat(text) is chat


def test_a_stale_card_accepts_only_a_reply_without_whitespace():
    assert cm.looks_like_chat("correct horse", stale=True) is True
    assert cm.looks_like_chat("hunter2", stale=True) is False


def _password_entry(cid="p1", age_s=0.0):
    entry = cm.register(cid, KEY, "password?", None, secret=True, owner_user_id=OWNER,
                        chat_guard=True, kind="save_login")
    entry.created_at -= age_s
    return entry


def test_chat_is_not_consumed_and_the_prompt_stays_open():
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, "hey did that work?", OWNER) == cm.TEXT_LOOKS_LIKE_CHAT
    assert not entry.event.is_set()
    assert cm.attempt_text_response_for_session(KEY, "hunter2", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "hunter2"


def test_after_15_minutes_a_two_word_reply_is_asked_about():
    entry = _password_entry(age_s=16 * 60)
    assert cm.attempt_text_response_for_session(KEY, "correct horse", OWNER) == cm.TEXT_LOOKS_LIKE_CHAT
    assert not entry.event.is_set()
    fresh = cm.register("p2", KEY + ":fresh", "password?", None, secret=True, owner_user_id=OWNER,
                        chat_guard=True, kind="save_login")
    assert cm.attempt_text_response_for_session(KEY + ":fresh", "correct horse", OWNER) == cm.TEXT_RESOLVED
    assert fresh.response == "correct horse"


def test_the_private_form_accepts_a_passphrase_with_spaces():
    entry = _password_entry(age_s=3600)
    assert cm.attempt_text_response_for_entry("p1", "correct horse battery staple", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "correct horse battery staple"


def test_skip_still_declines():
    entry = _password_entry()
    assert cm.attempt_text_response_for_session(KEY, "skip", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == cm.SKIPPED


def test_ordinary_prompts_have_no_chat_guard():
    entry = cm.register("q1", KEY, "which colour?", None)
    assert cm.attempt_text_response_for_session(KEY, "hey, blue please?", OWNER) == cm.TEXT_RESOLVED
    assert entry.response == "hey, blue please?"


def test_an_owner_prompt_makes_busy_routing_queue_instead_of_interrupt():
    from gateway.run_busy import _owner_prompt_pending
    assert _owner_prompt_pending(KEY) is False
    _password_entry()
    assert _owner_prompt_pending(KEY) is True
    cm.resolve_gateway_clarify("p1", "x")
    assert _owner_prompt_pending(KEY) is False


def test_only_password_cards_carry_the_guard():
    from gateway.vault_prompts import build_vault_prompt_callbacks
    seen = []

    def ask(question, **kw):
        seen.append(kw)
        return "owner@shop.com" if len(seen) == 1 else "x1"

    callbacks = build_vault_prompt_callbacks(ask)
    callbacks["save_login"]("https://a.example", "a.example")
    callbacks["unlock"]("bitwarden", "Bitwarden")
    callbacks["code"]("a.example", "")
    assert [kw.get("chat_guard", False) for kw in seen] == [False, True, True, False]


# ── the inbound path ───────────────────────────────────────────────────────────────────────


class _Adapter(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="t"), Platform.DISCORD)
        self.deleted, self.sent = [], []

    async def connect(self, *, is_reconnect: bool = False):
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append((content, reply_to))
        return SendResult(success=True, message_id="m")

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}

    async def delete_message(self, chat_id, message_id):
        self.deleted.append(message_id)
        return True


class _FellThrough(Exception):
    pass


@pytest.mark.asyncio
async def test_chat_on_a_password_card_is_kept_answered_and_routed_as_chat():
    from gateway.run import GatewayRunner
    import tools.slash_confirm as slash_confirm_mod
    adapter = _Adapter()
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._startup_restore_in_progress = False
    runner._scale_to_zero_note_real_inbound = lambda: None
    runner._is_user_authorized = lambda source: True
    runner._session_key_for_source = lambda source: KEY
    runner._delivery_adapter_for = lambda source: adapter
    runner._update_prompt_pending = {}
    entry = _password_entry()
    event = MessageEvent(text="hey did that work?", message_type=MessageType.TEXT, message_id="m-1",
                         source=SessionSource(platform=Platform.DISCORD, chat_id="777", chat_type="thread",
                                              user_id=OWNER, thread_id="777"))

    def _tripwire(_key):
        raise _FellThrough()

    with patch("hermes_cli.plugins.invoke_hook", return_value=[]), \
            patch.object(slash_confirm_mod, "get_pending", _tripwire), pytest.raises(_FellThrough):
        await runner._handle_message(event)
    assert not entry.event.is_set(), "the prompt stays open"
    assert adapter.deleted == [], "the chat message is left in place"
    assert len(adapter.sent) == 1 and adapter.sent[0][1] is None
    assert "Is that your password?" in adapter.sent[0][0]


# ── Discord card and tool results ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_discord_password_card_leads_with_the_private_route():
    from unittest.mock import AsyncMock
    from plugins.platforms.discord.adapter import DiscordAdapter
    adapter = DiscordAdapter(PlatformConfig(enabled=True, token="test-token", extra={}))
    adapter._client = MagicMock()
    adapter._allowed_user_ids = {OWNER}
    adapter._allowed_role_ids = set()
    _password_entry("p9")
    channel = MagicMock()
    sent = MagicMock()
    sent.id = 1
    channel.send = AsyncMock(return_value=sent)
    adapter._client.get_channel = MagicMock(return_value=channel)
    await adapter.send_clarify(chat_id="777", question="🔑 Thanks! Now I need the password (2/2).",
                               choices=None, clarify_id="p9", session_key=KEY)
    content = channel.send.call_args.kwargs["content"]
    assert content.index("Tap 🔒 Enter privately to type your password") < content.index("(2/2)")


def test_save_login_tells_the_bot_plainly_when_the_password_fails(monkeypatch):
    from agent.vault_backends import unlock as vault_unlock
    from tools import browser_vault_tool as vault
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://app.example.com")
    monkeypatch.setattr("agent.vault_store.get_vault_store",
                        lambda: SimpleNamespace(add_item=lambda *a, **k: SimpleNamespace(id="vault:h1")))
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda value: None)
    vault_unlock.set_pasted_secret_scrub_callback(None)
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps({"success": True}))
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", task_id="t"))
    assert "DID NOT WORK" in out["if_rejected"] and "app.example.com" in out["if_rejected"]
    monkeypatch.setattr(vault, "browser_vault_fill",
                        lambda handle, task_id=None: json.dumps({"success": False, "error": "no field"}))
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", task_id="t"))
    assert out["password_typed"] is False and "could not be typed" in out["next"]


@pytest.mark.asyncio
async def test_an_extra_login_field_card_does_not_call_it_a_password():
    """A PIN or security-answer card gets the plain private-box hint, not "type your password"."""
    from unittest.mock import AsyncMock
    from plugins.platforms.discord.adapter import DiscordAdapter
    adapter = DiscordAdapter(PlatformConfig(enabled=True, token="test-token", extra={}))
    adapter._client = MagicMock()
    adapter._allowed_user_ids = {OWNER}
    adapter._allowed_role_ids = set()
    cm.register("x9", KEY, "🔑 TestCo Books also asks for your PIN (3/3).", None, secret=True,
                owner_user_id=OWNER, chat_guard=True, kind="save_login")
    channel = MagicMock()
    sent = MagicMock()
    sent.id = 1
    channel.send = AsyncMock(return_value=sent)
    adapter._client.get_channel = MagicMock(return_value=channel)
    await adapter.send_clarify(chat_id="777", question="🔑 TestCo Books also asks for your PIN (3/3).",
                               choices=None, clarify_id="x9", session_key=KEY)
    content = channel.send.call_args.kwargs["content"]
    assert "Enter privately" in content and "your password" not in content
