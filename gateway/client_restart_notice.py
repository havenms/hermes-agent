"""Client-safe restart notices (``display.restart_notice: client``).

With ``full`` (the default) the gateway keeps its usual notices: a shutdown line in every chat
with a running task and in every home channel, and a "Gateway online" line in the home channels.

With ``client`` (global or ``display.platforms.<platform>.restart_notice``):

- A chat with no running task gets nothing. Home channels get nothing.
- A chat with a running task gets one plain line (``gateway.shutdown.notice_client``).
- After the restart, the same chats get one plain line (``gateway.startup.online_client``).

The shutdown pass records those chats in ``.client_restart_targets.json`` under the profile home.
The next boot sends the back-online line and removes the file. A stale file (older than
``MAX_TARGET_AGE_S``) is removed without a send.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

CLIENT_RESTART_TARGETS_FILENAME = ".client_restart_targets.json"
MAX_TARGET_AGE_S = 6 * 3600


def restart_notice_is_client(platform: Any, user_config: Optional[dict] = None) -> bool:
    """True when the active profile asks for client-safe restart notices on *platform*."""
    try:
        from gateway.display_config import resolve_display_setting
        if user_config is None:
            from gateway.warning_notifications import effective_user_config
            user_config = effective_user_config()
        key = getattr(platform, "value", platform)
        return resolve_display_setting(user_config or {}, str(key), "restart_notice", "full") == "client"
    except Exception:
        logger.debug("restart_notice lookup failed; using full notices", exc_info=True)
        return False


def _targets_path(home: Optional[Path] = None) -> Path:
    if home is None:
        from gateway.run import _hermes_home
        home = _hermes_home
    return Path(home) / CLIENT_RESTART_TARGETS_FILENAME


def record_client_restart_targets(targets: Iterable[Iterable[Any]], home: Optional[Path] = None) -> None:
    """Remember the chats that got the client shutdown line. Best-effort, never raises."""
    rows = [[str(p), str(c), (str(th) if th else None), (str(pr) if pr else None)]
            for p, c, th, pr in targets]
    if not rows:
        return
    try:
        from utils import atomic_json_write
        atomic_json_write(_targets_path(home), {"written_at": time.time(), "targets": rows}, indent=None)
    except Exception:
        logger.debug("Could not record client restart targets", exc_info=True)


def pop_client_restart_targets(home: Optional[Path] = None, now: Optional[float] = None) -> list:
    """Return the recorded chats and remove the file. A stale or broken file returns ``[]``."""
    path = _targets_path(home)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        written = float(data.get("written_at") or 0)
        if (now if now is not None else time.time()) - written > MAX_TARGET_AGE_S:
            return []
        return [list(row) for row in data.get("targets") or [] if isinstance(row, list) and len(row) == 4]
    except Exception:
        logger.debug("Could not read client restart targets", exc_info=True)
        return []
    finally:
        try:
            path.unlink()
        except OSError:
            pass
