"""``hermes gateway inject``: tell a conversation of the running gateway that the client pressed Done (TAPAS patch).

Example (the takeover page's Done button)::

    hermes -p srijit gateway inject --session "$HERMES_SESSION_KEY" --text "done"

The gateway receives the fixed text ``[via takeover page] done``. It accepts no other text and no
marker. Talks to the profile's control socket, so only the same OS user can use it. Exit 0 on
success, 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def inject_message(home: Path, session_key: str, text: str, marker: str = "") -> dict:
    """Send the ``inject-message`` request; returns the gateway's full answer (``ok`` + ``result`` or ``error``)."""
    from gateway import control_socket as cs
    params = {"session_key": session_key, "text": text}
    if marker:
        params["marker"] = marker
    request = json.dumps({"protocol": cs.CONTROL_PROTOCOL_VERSION, "verb": "inject-message", "id": 1,
                          "params": params}).encode("utf-8") + b"\n"
    raw = cs._query_unix_socket(Path(home), request, 15.0)
    if not raw:
        return {"ok": False, "error": "no gateway answered on the control socket (is it running?)"}
    return json.loads(raw.decode("utf-8"))


def cmd_gateway_inject(args) -> int:
    from hermes_constants import get_hermes_home
    answer = inject_message(Path(get_hermes_home()), args.session, args.text, args.marker or "")
    print(json.dumps(answer))
    if not answer.get("ok"):
        sys.exit(1)
    return 0


def add_inject_parser(gateway_subparsers) -> None:
    parser = gateway_subparsers.add_parser(
        "inject", help='Tell a conversation that the client pressed Done (fixed text "done"; local, same user)')
    parser.add_argument("--session", required=True, help="Session key of the conversation (HERMES_SESSION_KEY)")
    parser.add_argument("--text", default="done", help='Only "done" is accepted (the default)')
    parser.add_argument("--marker", default="", help="Deprecated: the marker is fixed")
    parser.set_defaults(func=cmd_gateway_inject)
