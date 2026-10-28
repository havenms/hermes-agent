"""Shared helpers for the round 4 vault review tests (fake values only)."""

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource
from tools import clarify_gateway as cm

KEY = "agent:main:discord:thread:777:777"
OWNER = "1001"
OTHER = "2002"


def clear_clarify():
    with cm._lock:
        cm._entries.clear()
        cm._session_index.clear()
        cm._held.clear()


def password_entry(cid="p1", key=KEY):
    return cm.register(cid, key, "🔑 Thanks! Now I need the password for me@example.com (2/2).", None,
                       secret=True, owner_user_id=OWNER, chat_guard=True, kind="save_login")


class FakeAdapter(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="t"), Platform.DISCORD)
        self.deleted, self.sent, self.cards, self.handled = [], [], [], []

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

    async def handle_message(self, event):
        self.handled.append(event)


class ButtonAdapter(FakeAdapter):
    async def send_held_reply_card(self, chat_id, hold_id, owner_user_id, clarify_id, metadata=None):
        self.cards.append((hold_id, owner_user_id, clarify_id))
        return SendResult(success=True, message_id="card")


def runner_for(adapter):
    from gateway.run import GatewayRunner
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._startup_restore_in_progress = False
    runner._scale_to_zero_note_real_inbound = lambda: None
    runner._is_user_authorized = lambda source: True
    runner._session_key_for_source = lambda source: KEY
    runner._delivery_adapter_for = lambda source: adapter
    runner._update_prompt_pending = {}
    runner._thread_metadata_for_target = lambda *a, **k: None
    return runner


def make_event(text, user=OWNER, mid="m-1"):
    return MessageEvent(text=text, message_type=MessageType.TEXT, message_id=mid,
                        source=SessionSource(platform=Platform.DISCORD, chat_id="777", chat_type="thread",
                                             user_id=user, thread_id="777"))
