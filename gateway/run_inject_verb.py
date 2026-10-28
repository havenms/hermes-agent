"""Control-socket ``inject-message``: put a text into a conversation as if its client wrote it.

TAPAS patch. The takeover page (a local web page where a client finishes a login by hand) has a
Done button. Without this verb the client had to go back to Discord and type "done". The page's
server now calls this verb, and the bot resumes in the same conversation.

Local only and same OS user only: the verb is a *private* control-socket handler, so the server
accepts it only from a peer with this process's uid (``SO_PEERCRED``) over the 0600 socket in the
profile home. The text is marked (``[via takeover page] done``), so the agent and the transcript
show where it came from.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 2000
DEFAULT_MARKER = "via takeover page"


def inject_message_verb(runner: Any, loop: asyncio.AbstractEventLoop) -> Callable[[dict, str], dict]:
    """Handler ``(params, peer_subject) -> result`` for ``GatewayControlServer.private_handlers``.

    params: ``session_key`` (required; ``HERMES_SESSION_KEY`` of the conversation), ``text``
    (required, at most 2000 characters), ``marker`` (optional, default "via takeover page")."""

    def _handler(params: dict, peer_subject: str) -> dict:
        from gateway.platforms.event import MessageEvent, MessageType
        session_key = str(params.get("session_key") or "").strip()
        text = str(params.get("text") or "").strip()
        marker = str(params.get("marker") or DEFAULT_MARKER).strip()[:60] or DEFAULT_MARKER
        if not session_key or not text:
            raise ValueError("session_key and text are required")
        if len(text) > MAX_TEXT_CHARS:
            raise ValueError(f"text is longer than {MAX_TEXT_CHARS} characters")
        entry = runner.session_store.lookup_by_session_key(session_key)
        origin = getattr(entry, "origin", None)
        if origin is None:
            raise LookupError(f"no conversation with session_key {session_key!r}")
        event = MessageEvent(text=f"[{marker}] {text}", message_type=MessageType.TEXT, source=origin)

        async def _dispatch() -> bool:
            adapter = runner._delivery_adapter_for(origin)
            if adapter is None:
                return False
            await adapter.handle_message(event)  # returns at once; the turn runs in the background
            return True

        dispatched = asyncio.run_coroutine_threadsafe(_dispatch(), loop).result(timeout=10)
        if not dispatched:
            raise RuntimeError(f"no connected adapter for {getattr(origin.platform, 'value', origin.platform)}")
        logger.info("Injected a local message into session %s (marker=%r, chars=%d, peer=%s)",
                    session_key, marker, len(text), peer_subject)
        return {"injected": True, "session_key": session_key,
                "platform": getattr(origin.platform, "value", str(origin.platform)), "chat_id": origin.chat_id}

    return _handler
