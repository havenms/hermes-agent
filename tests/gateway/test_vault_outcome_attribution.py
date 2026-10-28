"""A site error that offers a code does not move a password rejection to the code field.

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


# ── 6: field attribution ────────────────────────────────────────────────────────────────────


PW = {"type": "password", "label": "Password", "autocomplete": "current-password", "invalid": False}
EMAIL = {"type": "email", "label": "Email", "autocomplete": "username", "invalid": False}
OTP = {"type": "text", "label": "Verification code", "autocomplete": "one-time-code", "invalid": False}


def _snap(fields=(), errors=(), text=""):
    return {"hermes_outcome": 1, "url": "https://a.example.com/signin", "fields": list(fields),
            "errors": list(errors), "text": text}


def test_an_error_that_offers_a_code_still_blames_the_password():
    from agent.vault_outcome import classify_outcome
    out = classify_outcome(_snap([EMAIL, PW], ["Invalid credentials. Please try again or use a verification code."]),
                           ["password"])
    assert out["field"] == "password"


def test_a_code_error_after_a_code_still_blames_the_code():
    from agent.vault_outcome import classify_outcome
    out = classify_outcome(_snap([OTP], ["That verification code is not right."]), ["code"])
    assert out["field"] == "code"


def test_an_email_error_after_a_password_blames_the_email():
    from agent.vault_outcome import classify_outcome
    out = classify_outcome(_snap([EMAIL, PW], ["We couldn't find an account with that email."]), ["password"])
    assert out["field"] == "identifier"
