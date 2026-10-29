"""Round 6: quiet client chats never see counts, iterations, times, "turn" or "/stop".

Live 2026-10-29 on Discord: "⚡ Interrupting current task (13 min elapsed, iteration 30/500). I'll
respond to your message shortly." Under ``display.tool_progress: quiet`` every busy mode says one
plain line, and the other gateway status lines with internal words are gated the same way."""
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource

QUIET_ACK = "One moment, I am finishing something. I will answer you right after."
INTERNAL = re.compile(r"iteration|elapsed|\bturns?\b|/stop|/new|\d+\s*min|\d+/\d+", re.I)


def _source():
    return SessionSource(platform=Platform.DISCORD, chat_id="c", chat_type="dm", user_id="1")


def _event():
    return MessageEvent(text="hi", message_type=MessageType.TEXT, message_id="m", source=_source())


@pytest.fixture()
def quiet(monkeypatch):
    import gateway.run as run_mod
    monkeypatch.setattr(run_mod, "_load_gateway_config", lambda: {"display": {"tool_progress": "quiet"}})


@pytest.fixture()
def loud(monkeypatch):
    import gateway.run as run_mod
    monkeypatch.setattr(run_mod, "_load_gateway_config", lambda: {"display": {"tool_progress": "all"}})
    from gateway import quiet_status
    monkeypatch.setattr(quiet_status, "_env_mode", lambda: None)


def _busy_runner():
    from gateway.run import GatewayRunner
    runner = object.__new__(GatewayRunner)
    runner._agent_has_active_subagents = lambda agent: False
    return runner


def _agent():
    agent = MagicMock()
    agent.get_activity_summary.return_value = {"api_call_count": 30, "max_iterations": 500, "current_tool": "browser"}
    return agent


def _interrupt_ack():
    busy = SimpleNamespace(turn=SimpleNamespace(started_ts=1.0))
    return _busy_runner()._compose_busy_ack_message(
        _event(), 13 * 60 + 2.0, busy, _agent(), is_steer_mode=False, is_queue_mode=False,
        is_redirect_mode=False, demoted_for_subagents=False, demoted_for_compression=False)


def test_the_interrupt_notice_is_plain_in_quiet_mode(quiet):
    text = _interrupt_ack()
    assert text == QUIET_ACK and not INTERNAL.search(text)


def test_the_interrupt_notice_keeps_its_detail_in_other_modes(loud):
    text = _interrupt_ack()
    assert "Interrupting" in text and "13 min" in text


def test_the_env_setting_counts_as_quiet_too(monkeypatch):
    import gateway.run as run_mod
    from gateway import quiet_status
    monkeypatch.setattr(run_mod, "_load_gateway_config", lambda: {})
    monkeypatch.setattr(quiet_status, "_env_mode", lambda: None)
    assert quiet_status.is_quiet(_event()) is False
    monkeypatch.setattr(quiet_status, "_env_mode", lambda: "quiet")
    assert quiet_status.is_quiet(_event()) is True
    assert quiet_status.is_quiet(None) is False


@pytest.mark.parametrize("key", [
    "gateway.busy.drain_queued", "gateway.busy.drain_rejected", "gateway.busy.drain_rejected_new_work",
    "gateway.busy.draining_maintenance", "gateway.busy.another_turn_running",
    "gateway.errors.interrupted_before_start", "gateway.errors.previous_turn_cleanup",
    "gateway.errors.session_storage_unavailable", "gateway.errors.session_storage_unavailable_disk",
    "gateway.progress.stuck_warning",
])
def test_every_gated_line_is_plain_in_quiet_mode(quiet, key):
    from agent.i18n import t
    from gateway.quiet_status import status_line
    kwargs = {"action": "restarting", "minutes": 5, "remaining": 3}
    normal = t(key, **kwargs)
    plain = status_line(key, _source(), **kwargs)
    assert plain and plain != normal and not INTERNAL.search(plain), plain


def test_gated_lines_do_not_change_in_other_modes(loud):
    from agent.i18n import t
    from gateway.quiet_status import status_line
    assert status_line("gateway.busy.another_turn_running", _source()) == t("gateway.busy.another_turn_running")
    assert status_line("gateway.busy.another_turn_running", None) == t("gateway.busy.another_turn_running")


def test_the_empty_reply_after_a_stop_race_is_plain(quiet):
    from gateway.run import _normalize_empty_agent_response
    text = _normalize_empty_agent_response({"interrupted": True, "api_calls": 0}, "", source=_source())
    assert text == "Sorry, I could not take that message. Please send it again."
    assert "/stop" in _normalize_empty_agent_response({"interrupted": True, "api_calls": 0}, "")


@pytest.mark.asyncio
async def test_the_drain_notice_is_plain(quiet):
    runner = _busy_runner()
    runner._delivery_adapter_for = lambda source: MagicMock()
    runner._queue_during_drain_enabled = lambda mode: True
    runner._queue_or_replace_pending_event = lambda *a: None
    runner._status_action_gerund = lambda: "restarting"
    runner._send_busy_reply = AsyncMock()
    await runner._send_busy_drain_notice(_event(), "k", "interrupt")
    assert runner._send_busy_reply.await_args.args[2] == (
        "One moment, I am restarting. I will answer you when I am back.")
