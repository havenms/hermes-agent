"""The code card never takes chat such as "wait 5 min" as a one-time code.

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


# ── 4 and 5: the code card and the email card ignore chat ───────────────────────────────────


@pytest.mark.parametrize("text, ok", [
    ("123456", True), ("123 456", True), ("123-456", True), ("G-123456", True), ("AB12CD", True),
    ("4321", True), ("12345678", True),
    ("wait 5 min", False), ("in 10 mins", False), ("give me 2", False), ("1 sec", False),
    ("2 min pls", False), ("ok 1", False), ("10mins", False), ("wait5min", False), ("ABCDEF", False),
])
def test_the_code_shape(text, ok):
    from gateway.vault_prompts import CODE_PATTERN
    assert bool(re.fullmatch(CODE_PATTERN, text)) is ok
