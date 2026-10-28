"""Control-socket ``inject-message``: tell a conversation that the client pressed Done on the takeover page.

TAPAS patch. The takeover page (a local web page where a client finishes a login by hand) has a
Done button. Without this verb the client had to go back to Discord and type "done". The page's
server now calls this verb, and the bot resumes in the same conversation.

Local only and same OS user only: the verb is a *private* control-socket handler, so the server
accepts it only from a peer with this process's uid (``SO_PEERCRED``) over the 0600 socket in the
profile home. The text is fixed: ``[via takeover page] done``. The verb takes no free text and no
marker, so a forged call (any process of the shared OS user) cannot put other words in the client's
name. The message also skips an open prompt card, so a code card cannot swallow it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 2000  # kept for callers; only DONE_TEXT is accepted
DEFAULT_MARKER = "via takeover page"
DONE_TEXT = "done"
INJECTED_TEXT = f"[{DEFAULT_MARKER}] {DONE_TEXT}"


def inject_message_verb(runner: Any, loop: asyncio.AbstractEventLoop) -> Callable[[dict, str], dict]:
    """Handler ``(params, peer_subject) -> result`` for ``GatewayControlServer.private_handlers``.

    params: ``session_key`` (required; ``HERMES_SESSION_KEY`` of the conversation) and ``text``
    (optional; only "done" is accepted). Any other text, or a ``marker``, is refused."""

    def _handler(params: dict, peer_subject: str) -> dict:
        from gateway.platforms.event import MessageEvent, MessageType
        from gateway.run_inbound import CLARIFY_BYPASS_KEY
        session_key = str(params.get("session_key") or "").strip()
        text = str(params.get("text") or DONE_TEXT).strip()
        if not session_key:
            raise ValueError("session_key is required")
        if text.casefold().rstrip(".!") != DONE_TEXT:
            raise ValueError('only the text "done" can be injected')
        if str(params.get("marker") or "").strip() not in ("", DEFAULT_MARKER):
            raise ValueError("the marker is fixed")
        entry = runner.session_store.lookup_by_session_key(session_key)
        origin = getattr(entry, "origin", None)
        if origin is None:
            raise LookupError(f"no conversation with session_key {session_key!r}")
        event = MessageEvent(text=INJECTED_TEXT, message_type=MessageType.TEXT, source=origin,
                             metadata={CLARIFY_BYPASS_KEY: True})

        async def _dispatch() -> bool:
            adapter = runner._delivery_adapter_for(origin)
            if adapter is None:
                return False
            await adapter.handle_message(event)  # returns at once; the turn runs in the background
            return True

        dispatched = asyncio.run_coroutine_threadsafe(_dispatch(), loop).result(timeout=10)
        if not dispatched:
            raise RuntimeError(f"no connected adapter for {getattr(origin.platform, 'value', origin.platform)}")
        logger.info("Injected the takeover-page done into session %s (peer=%s)", session_key, peer_subject)
        return {"injected": True, "session_key": session_key,
                "platform": getattr(origin.platform, "value", str(origin.platform)), "chat_id": origin.chat_id}

    return _handler
