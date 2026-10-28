"""Keep the browser idle reaper off a task that has a tool call in flight.

The janitor in :mod:`tools.browser_session_lifecycle` closes a session whose last browser
activity is older than ``browser.inactivity_timeout`` (default 120 s). Only browser calls stamp
that activity. A call that waits without touching the page, such as ``browser_vault`` waiting for
the user's one-time code, or any other tool the turn runs between two browser steps, let the
janitor close the tab mid-login (2026-10-21: the Intuit tab closed while the bot waited for a 2FA
code). The terminal reaper had the same gap; upstream e24c9a5086 closed it with a refcounted
in-flight hold, and this module applies the same idea to the browser.

The hold is per task id, because a browser session key is ``<task>``, ``<task>@<home>`` or
``<task>::local`` (``tools.browser_session.owner_task_id``). Stdlib only, so the tool executor can
take a hold on every call without importing the browser stack.
"""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from typing import Iterator, Optional

_lock = threading.Lock()
_held: dict[str, int] = {}  # task id -> calls in flight


@contextmanager
def hold_browser_for_task(task_id: Optional[str]) -> Iterator[None]:
    """Hold ``task_id``'s browser sessions against the idle reaper while the block runs.

    Refcounted, so parallel calls of one task share the hold. On release the sessions of the task
    are restamped, so the idle countdown starts when the last call ends, not when it started.
    """
    task = task_id or "default"
    with _lock:
        _held[task] = _held.get(task, 0) + 1
    try:
        yield
    finally:
        with _lock:
            left = _held.pop(task, 1) - 1
            if left > 0:
                _held[task] = left
        if left <= 0:
            _restamp_task_sessions(task)


def is_task_held(task_id: Optional[str]) -> bool:
    """True while a tool call of ``task_id`` is in flight."""
    with _lock:
        return _held.get(task_id or "default", 0) > 0


def _restamp_task_sessions(task: str) -> None:
    """Restart the idle countdown of the task's sessions. A process that never imported the
    browser stack has no sessions, so there is nothing to restamp."""
    bs = sys.modules.get("tools.browser_session")
    if bs is None:
        return
    now = time.time()
    with bs._cleanup_lock:
        for key in list(bs._session_last_activity):
            if key == task or bs.owner_task_id(key) == task:
                bs._session_last_activity[key] = now
