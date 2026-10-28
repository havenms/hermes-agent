"""inject-message: the takeover page's Done button reaches the conversation (TAPAS patch)."""

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

from gateway.config import Platform
from gateway.control_socket import GatewayControlServer
from gateway.run_inject_verb import inject_message_verb
from gateway.session import SessionSource

KEY = "agent:main:discord:thread:777:777"
ORIGIN = SessionSource(platform=Platform.DISCORD, chat_id="777", chat_type="thread", user_id="1001", thread_id="777")


@pytest.fixture()
def loop():
    lp = asyncio.new_event_loop()
    t = threading.Thread(target=lp.run_forever, daemon=True)
    t.start()
    yield lp
    lp.call_soon_threadsafe(lp.stop)
    t.join(timeout=5)


def _runner(adapter, entries=None):
    entries = {KEY: SimpleNamespace(origin=ORIGIN)} if entries is None else entries
    return SimpleNamespace(session_store=SimpleNamespace(lookup_by_session_key=entries.get),
                           _delivery_adapter_for=lambda source: adapter)


class _Adapter:
    def __init__(self):
        self.events = []

    async def handle_message(self, event):
        self.events.append(event)


def test_the_text_arrives_as_the_clients_message_with_a_marker(loop):
    adapter = _Adapter()
    result = inject_message_verb(_runner(adapter), loop)({"session_key": KEY, "text": "done"}, "uid:1")
    assert result["injected"] is True and result["chat_id"] == "777"
    (event,) = adapter.events
    assert event.text == "[via takeover page] done"
    assert event.source is ORIGIN


def test_unknown_session_and_missing_text_are_refused(loop):
    handler = inject_message_verb(_runner(_Adapter()), loop)
    with pytest.raises(LookupError):
        handler({"session_key": "agent:main:nope", "text": "done"}, "uid:1")
    with pytest.raises(ValueError):
        handler({"session_key": KEY, "text": "  "}, "uid:1")
    with pytest.raises(ValueError):
        handler({"session_key": KEY, "text": "x" * 2001}, "uid:1")


def test_the_socket_refuses_a_peer_that_is_not_the_same_user(loop, tmp_path):
    server = GatewayControlServer(home=tmp_path)
    adapter = _Adapter()
    server.private_handlers["inject-message"] = inject_message_verb(_runner(adapter), loop)
    line = json.dumps({"protocol": 1, "verb": "inject-message", "id": 1,
                       "params": {"session_key": KEY, "text": "done"}}).encode()
    refused = json.loads(server.handle_request_line(line, peer_subject=None))
    assert refused["ok"] is False and "PermissionError" in refused["error"]
    assert adapter.events == []
    accepted = json.loads(server.handle_request_line(line, peer_subject="uid:1000"))
    assert accepted["ok"] is True and accepted["result"]["injected"] is True


def test_the_cli_parser_has_gateway_inject():
    import argparse
    from hermes_cli.gateway_inject import add_inject_parser, cmd_gateway_inject
    parser = argparse.ArgumentParser()
    add_inject_parser(parser.add_subparsers(dest="cmd"))
    args = parser.parse_args(["inject", "--session", KEY, "--text", "done"])
    assert args.func is cmd_gateway_inject and args.session == KEY and args.text == "done"
