"""Client-safe status lines under ``display.tool_progress: quiet``.

TAPAS client chats run with ``display.tool_progress: quiet``. In that mode a status line the gateway
sends on its own (a busy reply, a restart notice, a stall warning, a "send it again" notice) must
not show internals: no iteration counts, no elapsed times, no "turn", no "/stop" or "/new", no tool
or config names. Each sender asks :func:`is_quiet` and, when it is True, sends the plain line
from :data:`QUIET_LINES` instead.

The mode is resolved the same way as the turn's own progress mode (``gateway.run_turn``): the
platform's YAML value first, then ``HERMES_TOOL_PROGRESS_MODE`` from the active profile scope.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from agent.i18n import t

logger = logging.getLogger(__name__)

# Internal status key -> the plain line for a client chat (locale keys).
QUIET_LINES = {
    "gateway.busy.drain_queued": "gateway.busy.quiet_restart_queued",
    "gateway.busy.drain_rejected": "gateway.busy.quiet_restart_rejected",
    "gateway.busy.drain_rejected_new_work": "gateway.busy.quiet_restart_rejected",
    "gateway.busy.draining_maintenance": "gateway.busy.quiet_restart_rejected",
    "gateway.busy.another_turn_running": "gateway.busy.quiet_resend",
    "gateway.errors.interrupted_before_start": "gateway.busy.quiet_resend",
    "gateway.errors.previous_turn_cleanup": "gateway.busy.quiet_resend",
    "gateway.errors.session_storage_unavailable": "gateway.busy.quiet_resend",
    "gateway.errors.session_storage_unavailable_disk": "gateway.busy.quiet_resend",
    "gateway.progress.stuck_warning": "gateway.progress.quiet_stuck",
}


def _platform_of(where: Any) -> Any:
    """The platform of a source, an event or a platform value itself."""
    source = getattr(where, "source", None)
    if source is not None and getattr(source, "platform", None) is not None:
        return source.platform
    platform = getattr(where, "platform", None)
    return platform if platform is not None else where


def _env_mode() -> Optional[str]:
    try:
        from agent.secret_scope import get_secret
        return get_secret("HERMES_TOOL_PROGRESS_MODE")
    except Exception:  # health: allow BLE001 -- no profile scope here: YAML alone decides
        return None


def is_quiet(where: Any) -> bool:
    """True when ``display.tool_progress`` is ``quiet`` for the platform of ``where`` (a source, an
    event or a platform). False on any read failure, so other modes never change."""
    if where is None:
        return False
    try:
        from gateway.display_config import resolve_tool_progress
        from gateway.run import _load_gateway_config, _platform_config_key
        mode, _explicit = resolve_tool_progress(
            _load_gateway_config(), _platform_config_key(_platform_of(where)), _env_mode())
        return mode == "quiet"
    except Exception:  # health: allow BLE001 -- a config read failure keeps the normal line
        logger.debug("quiet status check failed", exc_info=True)
        return False


def status_line(key: str, where: Any = None, **kwargs: Any) -> str:
    """``t(key, **kwargs)``, or its plain line when ``where`` is a quiet client chat."""
    quiet_key = QUIET_LINES.get(key)
    if quiet_key and is_quiet(where):
        return t(quiet_key)
    return t(key, **kwargs)
