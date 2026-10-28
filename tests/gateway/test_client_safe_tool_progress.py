"""``display.tool_progress: quiet``: client chats see one plain line, never tool names."""

import queue
from types import SimpleNamespace

from gateway.display_config import resolve_display_setting, resolve_tool_progress
from gateway.run_turn_progress import GatewayTurnProgressMixin
from hermes_cli.focus_view import normalize_tool_progress_mode


class _Progress(GatewayTurnProgressMixin):
    def __init__(self, ctx):
        self._ctx = ctx
        self._runner = SimpleNamespace(_delivery_adapter_for=lambda source: None)


def _ctx(mode):
    return SimpleNamespace(
        progress_mode=mode, progress_queue=queue.Queue(), log_queue=None, tool_progress_enabled=True,
        _run_still_current=lambda: True, long_tool_hint_fired=[True], _thinking_enabled=False,
        _native_slack_task_cards=False, last_tool=[None], last_progress_msg=[None], repeat_count=[0],
        last_was_terminal_block=[False], agent_holder=[None], stream_consumer_holder=[None],
        _live_status_adapter=None, _live_status_mode="off", source=SimpleNamespace(platform=None, chat_id="c"),
        user_config={},
    )


def _drain(q):
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    return items


def test_quiet_is_a_known_mode_everywhere():
    cfg = {"display": {"platforms": {"discord": {"tool_progress": "quiet"}}}}
    assert resolve_display_setting(cfg, "discord", "tool_progress") == "quiet"
    assert resolve_tool_progress({"display": {"tool_progress": "quiet"}}, "discord") == ("quiet", True)
    assert normalize_tool_progress_mode("quiet") == "quiet"


def test_quiet_mode_shows_one_plain_line_for_many_tools():
    ctx = _ctx("quiet")
    progress = _Progress(ctx)
    for name, preview in [("skill_view", "native-mcp"), ("browser_exec", "open the page"),
                          ("browser_vault", "save_login"), ("browser_vault", "fill"), ("tool_describe", None)]:
        progress.progress_callback("tool.started", name, preview, {"x": 1})
    items = _drain(ctx.progress_queue)
    assert items == ["Working on it…"]
    for item in items:
        for word in ("skill", "browser", "vault", "tool_describe", "native-mcp"):
            assert word not in str(item)


def test_all_mode_still_names_tools():
    ctx = _ctx("all")
    _Progress(ctx).progress_callback("tool.started", "tool_describe", None, None)
    assert "tool_describe" in str(_drain(ctx.progress_queue))
