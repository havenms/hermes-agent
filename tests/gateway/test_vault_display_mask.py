"""browser_vault password and extra values never show in a tool-progress display.

Round 4 review fix (findings/10-review-fork.md). Fake values only."""

import asyncio
import json
import logging
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.session import SessionSource
from tests.gateway.vault_review_helpers import (
    KEY, OTHER, OWNER, ButtonAdapter as _ButtonAdapter, FakeAdapter as _Adapter, clear_clarify,
    make_event as _event, password_entry as _password_entry, runner_for as _runner,
)
from tools import clarify_gateway as cm


@pytest.fixture(autouse=True)
def _clean():
    clear_clarify()
    yield
    clear_clarify()


# ── 8: display mask ──────────────────────────────────────────────────────────────────────────


def test_browser_vault_password_and_extra_are_masked_for_display():
    from agent.display import VAULT_ARG_MASK, redact_tool_args_for_display
    args = {"action": "save_login", "identifier": "me@example.com", "password": "Pass1234",
            "extra": {"PIN": "4321"}}
    out = redact_tool_args_for_display("browser_vault", args)
    assert out["password"] == VAULT_ARG_MASK and out["extra"] == {"PIN": VAULT_ARG_MASK}
    assert out["identifier"] == "me@example.com"
    assert "Pass1234" not in json.dumps(out) and "4321" not in json.dumps(out)
    assert args["password"] == "Pass1234", "the tool still gets the real value"


def test_the_verbose_progress_line_never_shows_the_password():
    import inspect
    from gateway import run_turn_progress
    assert "redact_tool_args_for_display(tool_name, args)" in inspect.getsource(run_turn_progress)
