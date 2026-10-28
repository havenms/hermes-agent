"""display.restart_notice: client — quiet, plain restart notices for client chats."""

import json
from unittest.mock import AsyncMock

import pytest

import gateway.run as gateway_run
import gateway.warning_notifications as warning_notifications
from gateway import client_restart_notice as crn
from gateway.config import HomeChannel, Platform
from gateway.display_config import resolve_display_setting
from gateway.platforms.base import SendResult
from gateway.session import build_session_key
from tests.gateway.restart_test_helpers import make_restart_runner, make_restart_source
from unittest.mock import MagicMock

CLIENT_CFG = {"display": {"restart_notice": "client"}}


@pytest.fixture
def client_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    monkeypatch.setattr(warning_notifications, "effective_user_config", lambda: CLIENT_CFG)
    return tmp_path


def _runner_with_home():
    runner, adapter = make_restart_runner()
    runner.config.platforms[Platform.TELEGRAM].home_channel = HomeChannel(
        platform=Platform.TELEGRAM, chat_id="home-42", name="Home")
    adapter.send = AsyncMock(return_value=SendResult(success=True, message_id="m"))
    return runner, adapter


def test_setting_resolves_with_platform_override():
    assert resolve_display_setting({}, "discord", "restart_notice") == "full"
    cfg = {"display": {"platforms": {"discord": {"restart_notice": "client"}}}}
    assert resolve_display_setting(cfg, "discord", "restart_notice") == "client"
    assert resolve_display_setting(cfg, "telegram", "restart_notice") == "full"
    assert resolve_display_setting({"display": {"restart_notice": "bogus"}}, "x", "restart_notice") == "full"


@pytest.mark.asyncio
async def test_client_mode_sends_nothing_without_a_running_task(client_mode):
    runner, adapter = _runner_with_home()
    await runner._notify_active_sessions_of_shutdown()
    adapter.send.assert_not_awaited()
    assert crn.pop_client_restart_targets(client_mode) == []


@pytest.mark.asyncio
async def test_client_mode_sends_one_plain_line_to_the_running_chat(client_mode):
    runner, adapter = _runner_with_home()
    source = make_restart_source(chat_id="active-42", chat_type="dm")
    key = build_session_key(source)
    runner._running_agents[key] = object()
    runner.session_store._entries[key] = MagicMock(origin=source)

    await runner._notify_active_sessions_of_shutdown()

    calls = adapter.send.await_args_list
    assert [c.args[0] for c in calls] == ["active-42"]
    text = calls[0].args[1]
    assert text == "I'm restarting for a quick update. I'll be right back."
    assert "Hermes" not in text
    data = json.loads((client_mode / crn.CLIENT_RESTART_TARGETS_FILENAME).read_text())
    assert data["targets"][0][:2] == ["telegram", "active-42"]


@pytest.mark.asyncio
async def test_full_mode_keeps_the_old_notices(monkeypatch, tmp_path):
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    monkeypatch.setattr(warning_notifications, "effective_user_config", lambda: {})
    runner, adapter = _runner_with_home()
    source = make_restart_source(chat_id="active-42", chat_type="dm")
    key = build_session_key(source)
    runner._running_agents[key] = object()
    runner.session_store._entries[key] = MagicMock(origin=source)

    await runner._notify_active_sessions_of_shutdown()

    assert [c.args[0] for c in adapter.send.await_args_list] == ["active-42", "home-42"]
    assert not (tmp_path / crn.CLIENT_RESTART_TARGETS_FILENAME).exists()


@pytest.mark.asyncio
async def test_client_mode_boot_says_back_only_to_recorded_chats(client_mode):
    runner, adapter = _runner_with_home()
    crn.record_client_restart_targets([("telegram", "active-42", None, None)], client_mode)

    delivered = await runner._send_home_channel_startup_notifications()
    sent = await runner._send_client_back_online_notices()

    assert ("telegram", "home-42", None) in delivered  # discharged without a send
    assert sent == 1
    calls = adapter.send.await_args_list
    assert [c.args[0] for c in calls] == ["active-42"]
    assert calls[0].args[1] == "I'm back. Send me a message and I'll carry on."
    assert not (client_mode / crn.CLIENT_RESTART_TARGETS_FILENAME).exists()


@pytest.mark.asyncio
async def test_back_online_skips_the_restart_requester(client_mode):
    runner, adapter = _runner_with_home()
    crn.record_client_restart_targets([("telegram", "active-42", None, None)], client_mode)
    assert await runner._send_client_back_online_notices(skip_target=("telegram", "active-42", None)) == 0
    adapter.send.assert_not_awaited()


def test_stale_targets_are_dropped(tmp_path):
    crn.record_client_restart_targets([("discord", "c", "t", None)], tmp_path)
    assert crn.pop_client_restart_targets(tmp_path, now=10**12) == []
    assert not (tmp_path / crn.CLIENT_RESTART_TARGETS_FILENAME).exists()
