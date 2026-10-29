"""Round 5, fix 2: under ``display.tool_progress: quiet`` no status line shows internals.

The live test showed "⏳ Working — 3 min — iteration 4/90, browser_vault" while a login card
waited. Quiet mode now shows "Still working on it…" for long work, nothing while a login card
waits, one plain busy reply, and one plain timeout reply."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource
from tools import clarify_gateway as cm


@pytest.fixture(autouse=True)
def _clean():
    with cm._lock:
        cm._entries.clear()
        cm._session_index.clear()
    yield
    with cm._lock:
        cm._entries.clear()
        cm._session_index.clear()


def _heartbeat_runner(monkeypatch, ticks=3):
    from gateway.run import GatewayRunner
    monkeypatch.setenv("HERMES_AGENT_NOTIFY_INTERVAL", "0.01")
    runner = object.__new__(GatewayRunner)
    runner._running_agents = {}
    runner._draining = runner._restart_requested = False
    adapter = MagicMock()
    adapter.send = AsyncMock(return_value=SimpleNamespace(success=True, message_id="hb-1"))
    adapter.edit_message = AsyncMock(return_value=SimpleNamespace(success=True))
    runner._delivery_adapter_for = lambda source: adapter
    runner._agent_activity_summary = staticmethod(
        lambda agent: {"api_call_count": 4, "max_iterations": 90, "current_tool": "browser_vault"})
    left = {"n": ticks}

    def _emit(*a, **k):
        left["n"] -= 1
        return left["n"] >= 0
    runner._should_emit_long_running_notification = _emit
    return runner, adapter


def _disp(mode):
    disp = MagicMock()
    disp._display_surface_mode.return_value = "on"
    disp.resolve_display_setting.return_value = True
    disp.progress_mode = mode
    return disp


def _ctx(session_key="sess"):
    from gateway.turn_context import TurnContext
    ctx = TurnContext(source=SimpleNamespace(chat_id="c", platform="discord"), session_key=session_key)
    ctx.agent_holder[0] = MagicMock()
    return ctx


def _texts(adapter):
    return [c.args[1] for c in adapter.send.await_args_list] + \
           [c.args[2] for c in adapter.edit_message.await_args_list]


@pytest.mark.asyncio
async def test_quiet_heartbeat_says_still_working_and_nothing_else(monkeypatch):
    runner, adapter = _heartbeat_runner(monkeypatch)
    await asyncio.wait_for(runner._run_agent_notify_long_running(_disp("quiet"), _ctx(), [None]), 5)
    texts = _texts(adapter)
    assert texts and all(x == "Still working on it…" for x in texts)


@pytest.mark.asyncio
async def test_quiet_heartbeat_is_silent_while_a_login_card_waits(monkeypatch):
    runner, adapter = _heartbeat_runner(monkeypatch)
    cm.register("v1", "sess", "login?", None, owner_user_id="1001", kind="save_login")
    await asyncio.wait_for(runner._run_agent_notify_long_running(_disp("quiet"), _ctx(), [None]), 5)
    assert _texts(adapter) == []


@pytest.mark.asyncio
async def test_other_modes_keep_the_detailed_heartbeat(monkeypatch):
    runner, adapter = _heartbeat_runner(monkeypatch, ticks=3)
    await asyncio.wait_for(runner._run_agent_notify_long_running(_disp("all"), _ctx(), [None]), 5)
    texts = _texts(adapter)
    assert any("browser_vault" in x for x in texts), texts


def _event():
    return MessageEvent(text="hi", message_type=MessageType.TEXT, message_id="m",
                        source=SessionSource(platform=Platform.DISCORD, chat_id="c", chat_type="dm", user_id="1"))


@pytest.mark.parametrize("flags", [
    dict(is_steer_mode=True, is_queue_mode=False, is_redirect_mode=False),
    dict(is_steer_mode=False, is_queue_mode=True, is_redirect_mode=False),
    dict(is_steer_mode=False, is_queue_mode=False, is_redirect_mode=False),
])
def test_quiet_busy_reply_is_one_plain_line(monkeypatch, flags):
    import gateway.run as run_mod
    from gateway.run import GatewayRunner
    monkeypatch.setattr(run_mod, "_load_gateway_config", lambda: {"display": {"tool_progress": "quiet"}})
    runner = object.__new__(GatewayRunner)
    runner._agent_has_active_subagents = lambda agent: False
    agent = MagicMock()
    agent.get_activity_summary.return_value = {"api_call_count": 4, "max_iterations": 90,
                                               "current_tool": "browser_vault"}
    text = runner._compose_busy_ack_message(_event(), 100.0, None, agent, demoted_for_subagents=False,
                                            demoted_for_compression=False, **flags)
    assert text == "One moment, I am finishing something. I will answer you right after."


def test_busy_reply_is_not_quiet_without_the_setting(monkeypatch):
    import gateway.run as run_mod
    from gateway.run import GatewayRunner
    monkeypatch.setattr(run_mod, "_load_gateway_config", lambda: {"display": {"tool_progress": "all"}})
    runner = object.__new__(GatewayRunner)
    assert runner._busy_ack_is_quiet(_event()) is False


def test_quiet_heartbeat_block_check_is_safe():
    from gateway.run_turn import quiet_heartbeat_blocked
    assert quiet_heartbeat_blocked(None) is False
    cm.register("v2", "s2", "code?", None, owner_user_id="1001", kind="code")
    assert quiet_heartbeat_blocked("s2") is True
