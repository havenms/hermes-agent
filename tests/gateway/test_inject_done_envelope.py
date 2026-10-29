"""The takeover-page "done" must cross native admission on Discord, with its bypass flag.

Regression: round 4 gave the injected "done" a metadata flag so an open login card would not
swallow it. The envelope's closed metadata contract refused any metadata off WhatsApp, so the
gateway answered "Hermes refused this message (invalid_params)" and the agent never saw "done".
"""

from types import SimpleNamespace

from gateway import session_envelope as env
from gateway.run_inbound import CLARIFY_BYPASS_KEY


def _event(platform, metadata):
    return SimpleNamespace(metadata=metadata, source=SimpleNamespace(platform=SimpleNamespace(value=platform)))


def test_key_matches_run_inbound():
    assert env._CLARIFY_BYPASS_KEY == CLARIFY_BYPASS_KEY


def test_bypass_flag_crosses_admission_on_discord():
    assert env._native_metadata(_event("discord", {CLARIFY_BYPASS_KEY: True})) == {CLARIFY_BYPASS_KEY: True}


def test_bypass_flag_must_be_true():
    assert env._native_metadata(_event("discord", {CLARIFY_BYPASS_KEY: "yes"})) is None


def test_other_keys_are_still_refused_off_whatsapp():
    assert env._native_metadata(_event("discord", {CLARIFY_BYPASS_KEY: True, "x": 1})) is None
    assert env._native_metadata(_event("discord", {"x": 1})) is None


def test_whatsapp_keys_keep_working_with_the_flag():
    out = env._native_metadata(_event("whatsapp", {CLARIFY_BYPASS_KEY: True, "whatsapp_from_owner": True}))
    assert out == {CLARIFY_BYPASS_KEY: True, "whatsapp_from_owner": True}


def test_empty_metadata_unchanged():
    assert env._native_metadata(_event("discord", {})) == {}
    assert env._native_metadata(_event("discord", None)) == {}
