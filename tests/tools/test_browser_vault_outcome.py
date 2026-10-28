"""One "credential rejected" loop for every secret the vault types.

After a fill and a submit, the vault reads the page (never a value) and decides: accepted, or
rejected with the field (password, email or username, code, an extra such as a PIN) and the reason
(wrong, expired, locked, device_check, unknown). The next card tells the client which thing did not
work. A field gets at most 2 retries; a locked sign-in or a device check goes straight to the
takeover link.
"""

import json
from types import SimpleNamespace

import pytest

from agent import vault_outcome as vo
from agent.vault_backends import unlock as vault_unlock
from gateway.vault_prompts import build_vault_prompt_callbacks
from tools import browser_vault_tool as vault

ORIGIN = "https://books.example.com"


@pytest.fixture(autouse=True)
def _clean_tracker():
    vo.TRACKER.clear()
    yield
    vo.TRACKER.clear()
    vault_unlock.set_code_prompt_callback(None)
    vault_unlock.set_save_login_prompt_callback(None)


def _snap(fields=(), errors=(), text=""):
    return {"hermes_outcome": 1, "url": ORIGIN + "/signin", "fields": list(fields), "errors": list(errors),
            "text": text}


PW = {"type": "password", "label": "Password", "autocomplete": "current-password", "invalid": False}
EMAIL = {"type": "email", "label": "Email", "autocomplete": "username", "invalid": False}
OTP = {"type": "text", "label": "Verification code", "autocomplete": "one-time-code", "invalid": False}
PIN = {"type": "password", "label": "PIN", "autocomplete": "", "invalid": False}
ANSWER = {"type": "text", "label": "Answer to your security question", "autocomplete": "", "invalid": False}


# ── classify: each field and each reason ──────────────────────────────────────────────────────

@pytest.mark.parametrize("snap, filled, field, reason, outcome", [
    (_snap([EMAIL, PW], ["Incorrect password. Try again."]), ["password"], "password", "wrong", "rejected"),
    (_snap([EMAIL, PW], ["We couldn't find an account with that email."]), ["password"], "identifier", "wrong",
     "rejected"),
    (_snap([OTP], ["That code is not right."]), ["code"], "code", "wrong", "rejected"),
    (_snap([OTP], ["This code has expired. Request a new one."]), ["code"], "code", "expired", "expired"),
    (_snap([PW, PIN], ["The PIN you entered is incorrect."]), ["password", "PIN"], "PIN", "wrong", "rejected"),
    (_snap([ANSWER], ["That security answer is wrong."]), ["Security answer"], "Security answer", "wrong",
     "rejected"),
    (_snap([EMAIL, PW], ["Too many attempts. Your account is locked for 30 minutes."]), ["password"], "password",
     "locked", "locked"),
    (_snap([], [], "Is this your security image? Confirm it's you to continue."), ["password"], "check",
     "device_check", "rejected"),
    (_snap([EMAIL, PW]), ["password"], "password", "unknown", "unknown"),
    (_snap([EMAIL, dict(PW, invalid=True)]), ["password"], "password", "wrong", "rejected"),
    (_snap([PW, dict(PIN, invalid=True)]), ["password", "PIN"], "PIN", "wrong", "rejected"),
])
def test_each_field_and_reason_is_named(snap, filled, field, reason, outcome):
    got = vo.classify_outcome(snap, filled)
    assert (got["field"], got["reason"], got["outcome"]) == (field, reason, outcome)


@pytest.mark.parametrize("text", ["To verify it's you, we sent a code to your phone.",
                                  "Locked out? Contact support.", "Codes expire after 10 minutes."])
def test_ordinary_sign_in_page_text_is_not_a_stop(text):
    got = vo.classify_outcome(_snap([OTP], [], text), ["password"])
    assert got == {"outcome": "accepted"}


def test_a_page_that_moved_on_is_accepted():
    assert vo.classify_outcome(_snap([], [], "Welcome back, Gold Lotus"), ["password"]) == {"outcome": "accepted"}
    assert vo.classify_outcome(_snap([EMAIL], []), ["code"]) == {"outcome": "accepted"}


def test_an_unreadable_page_is_no_verdict():
    assert vo.classify_outcome(None, ["password"]) is None
    assert vo.classify_outcome([{"index": 0}], ["password"]) is None


def test_the_site_text_is_trimmed():
    got = vo.classify_outcome(_snap([PW], ["Incorrect password. " + "x" * 400]), ["password"])
    assert len(got["message"]) <= 160


def test_the_snapshot_never_reads_an_input_value():
    js = vo.build_snapshot_js()
    assert ".value" not in js and "hermes_outcome" in js


# ── the plain lines ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("field, reason, line", [
    ("password", "wrong", "That password didn't work. Please check it and reply again."),
    ("identifier", "wrong", "That email or username didn't work. Please check it and reply again."),
    ("code", "wrong", "That code didn't work. Check it, or wait for a new one, and reply here."),
    ("code", "expired", "That code expired. TestCo Books is sending a new one. Reply with it here."),
    ("PIN", "wrong", "That PIN didn't work. Please check it and reply again."),
    ("Security answer", "wrong", "That Security answer didn't work. Please check it and reply again."),
    ("password", "unknown", "That didn't go through. Let's try once more."),
])
def test_retry_lines(field, reason, line):
    assert vo.retry_line(field, reason, "TestCo Books") == line


def test_locked_and_device_check_lines_stop_and_point_at_the_link():
    assert "locked" in vo.stop_line("locked", "TestCo Books") and "link" in vo.stop_line("locked", "TestCo Books")
    assert "link" in vo.stop_line("device_check", "TestCo Books")


# ── tracker: retry cap, hard stops, accepted, expiry ──────────────────────────────────────────

def _rej(field="password", reason="wrong"):
    return {"outcome": "rejected", "field": field, "reason": reason, "message": ""}


def test_a_field_gets_two_retries_then_the_takeover_link():
    t = vo.TRACKER
    assert t.record("t", ORIGIN, _rej())["retries_left"] == 2
    assert t.pending("t", ORIGIN, ["password"])["blocked"] is False
    assert t.record("t", ORIGIN, _rej())["retries_left"] == 1
    assert t.record("t", ORIGIN, _rej())["retries_left"] == 0
    assert t.pending("t", ORIGIN, ["password"])["blocked"] is True
    assert t.pending("t", ORIGIN, ["code"]) is None, "the cap is per field"


@pytest.mark.parametrize("reason", ["locked", "device_check"])
def test_a_locked_sign_in_or_a_device_check_stops_at_once(reason):
    assert vo.TRACKER.record("t", ORIGIN, _rej(reason=reason))["retries_left"] == 0
    assert vo.TRACKER.pending("t", ORIGIN, ["code"])["blocked"] is True


def test_accepted_clears_the_site_and_old_rejections_expire(monkeypatch):
    vo.TRACKER.record("t", ORIGIN, _rej())
    vo.TRACKER.record("t", ORIGIN, {"outcome": "accepted"})
    assert vo.TRACKER.pending("t", ORIGIN, ["password"]) is None
    vo.TRACKER.record("t", ORIGIN, _rej())
    now = vo.time.monotonic()
    monkeypatch.setattr(vo.time, "monotonic", lambda: now + vo.REJECTION_TTL_S + 1)
    assert vo.TRACKER.pending("t", ORIGIN, ["password"]) is None


# ── the tool: check, enter_code, save_login ───────────────────────────────────────────────────

@pytest.fixture()
def page(monkeypatch):
    state = SimpleNamespace(snap=None, prompts=[], secret_js=[], saved=[])
    controls = [{"autocomplete": "one-time-code", "formIndex": 0, "index": 0, "label": "Verification code",
                 "name": "otp", "type": "text"}]

    def eval_js(task_id, expr):
        if "hermes_outcome" in expr:
            return {"success": True, "result": json.dumps(state.snap)}
        if "document.title" == expr:
            return {"success": True, "result": "Sign in"}
        return {"success": True, "result": json.dumps(controls)}

    def eval_secret(task_id, expr):
        state.secret_js.append(expr)
        return {"success": True, "result": json.dumps({"filled": 1})}
    monkeypatch.setattr(vault, "_eval_js", eval_js)
    monkeypatch.setattr(vault, "_eval_js_secret", eval_secret)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: ORIGIN)
    monkeypatch.setattr(vault, "_page_title", lambda task_id: "")
    monkeypatch.setattr(vault, "_check_settle_s", lambda: 0.0)
    monkeypatch.setattr(vault_unlock, "can_prompt_here", lambda: True)
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda value: None)
    store = SimpleNamespace(add_item=lambda kind, label, data, origin: state.saved.append(dict(data))
                            or SimpleNamespace(id="vault_h1"))
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps(
        {"success": True, "filled_fields": 1}))
    return state


def _code_prompt(state, code="123456"):
    def prompt(site, hint, notice=""):
        state.prompts.append(notice)
        return code
    vault_unlock.set_code_prompt_callback(prompt)


def test_check_reports_the_rejected_field_without_any_value(page):
    vo.TRACKER.note_filled("t", ORIGIN, ["password"])
    page.snap = _snap([EMAIL, PW], ["Incorrect password."])
    out = json.loads(vault.browser_vault_check(task_id="t", label="TestCo Books"))
    assert out["success"] is False and out["error_type"] == "credential_rejected"
    assert (out["field"], out["reason"], out["message"]) == ("password", "wrong", "Incorrect password.")
    assert out["retries_left"] == 2 and out["tell_client"].startswith("That password didn't work")
    assert "save_login" in out["next"]


def test_check_after_a_good_sign_in_is_accepted_and_clears_the_count(page):
    vo.TRACKER.record("t", ORIGIN, _rej())
    vo.TRACKER.note_filled("t", ORIGIN, ["password"])
    page.snap = _snap([], [], "Dashboard")
    assert json.loads(vault.browser_vault_check(task_id="t"))["outcome"] == "accepted"
    assert vo.TRACKER.pending("t", ORIGIN, ["password"]) is None


def test_a_rejected_code_is_reported_and_the_next_card_says_so(page):
    _code_prompt(page, "111111")
    page.snap = _snap([OTP], ["That code is not right."])
    out = json.loads(vault.browser_vault_enter_code(task_id="t"))
    assert out["error_type"] == "credential_rejected" and out["field"] == "code" and out["reason"] == "wrong"
    assert "111111" not in json.dumps(out)
    page.snap = _snap([], [], "Welcome")
    out = json.loads(vault.browser_vault_enter_code(task_id="t"))
    assert out["success"] is True and out["outcome"] == "accepted"
    assert page.prompts == ["", "That code didn't work. Check it, or wait for a new one, and reply here."]


def test_an_expired_code_names_the_site_and_asks_for_a_resend(page):
    _code_prompt(page)
    page.snap = _snap([OTP], ["This code has expired."])
    out = json.loads(vault.browser_vault_enter_code(task_id="t"))
    assert out["reason"] == "expired" and "resend" in out["next"]
    page.snap = _snap([OTP])
    json.loads(vault.browser_vault_enter_code(task_id="t"))
    assert page.prompts[1] == "That code expired. books.example.com is sending a new one. Reply with it here."


def test_a_code_on_a_page_that_did_not_move_yet_is_left_pending(page):
    _code_prompt(page)
    page.snap = _snap([OTP])
    out = json.loads(vault.browser_vault_enter_code(task_id="t"))
    assert out["success"] is True and out["outcome"] == "pending" and "check" in out["next"]
    assert vo.TRACKER.pending("t", ORIGIN, ["code"]) is None, "pending is not a rejection"


def test_enter_code_stops_after_two_retries_and_sends_the_takeover_link(page):
    _code_prompt(page)
    page.snap = _snap([OTP], ["Invalid code."])
    results = [json.loads(vault.browser_vault_enter_code(task_id="t")) for _ in range(4)]
    assert [r.get("retries_left") for r in results[:3]] == [2, 1, 0]
    assert "takeover" in results[2]["next"]
    assert results[3]["error_type"] == "retry_limit" and "takeover" in results[3]["next"]
    assert len(page.prompts) == 3, "the fourth try never asks the client"


def _login_prompt(state):
    def prompt(origin, site, extra_fields=(), notice=""):
        state.prompts.append(notice)
        return {"identifier": "owner@example.com", "password": "pw",
                **({"extra": {lb: "4321" for lb in extra_fields}} if extra_fields else {})}
    vault_unlock.set_save_login_prompt_callback(prompt)


@pytest.mark.parametrize("field, line", [
    ("password", "That password didn't work. Please check it and reply again."),
    ("identifier", "That email or username didn't work. Please check it and reply again."),
    ("PIN", "That PIN didn't work. Please check it and reply again."),
])
def test_the_next_login_card_names_the_field_that_did_not_work(page, field, line):
    _login_prompt(page)
    vo.TRACKER.record("t", ORIGIN, _rej(field))
    out = json.loads(vault.browser_vault_save_login(label="TestCo Books", extra_fields=["PIN"], task_id="t"))
    assert out["success"] is True and page.prompts == [line]


@pytest.mark.parametrize("reason, error_type", [("locked", "account_locked"), ("device_check", "device_check")])
def test_a_locked_sign_in_or_device_check_goes_to_the_takeover_link(page, reason, error_type):
    _login_prompt(page)
    vo.TRACKER.record("t", ORIGIN, _rej("check" if reason == "device_check" else "password", reason))
    out = json.loads(vault.browser_vault_save_login(label="TestCo Books", task_id="t"))
    assert out["error_type"] == error_type and "takeover" in out["next"] and out["tell_client"]
    assert page.prompts == [] and page.saved == []


def test_a_pasted_login_also_respects_the_retry_cap(page):
    for _ in range(3):
        vo.TRACKER.record("t", ORIGIN, _rej())
    out = json.loads(vault.browser_vault_save_login(identifier="o", password="pw", task_id="t"))
    assert out["error_type"] == "retry_limit" and page.saved == []


# ── cards and schema ──────────────────────────────────────────────────────────────────────────

def test_the_cards_start_with_the_notice_and_keep_the_rest():
    asked = []

    def ask(question, **kw):
        asked.append(question)
        return "123456" if len(asked) == 1 else "owner"
    cbs = build_vault_prompt_callbacks(ask)
    cbs["code"]("TestCo Books", "", notice="That code didn't work. Check it, or wait for a new one, and reply here.")
    assert asked[0].startswith("That code didn't work.")
    assert asked[0].endswith("🔢 TestCo Books just sent a code to your phone or email.\n\nReply with it here.")
    cbs["code"]("TestCo Books", "")
    assert asked[1].startswith("🔢 TestCo Books")


def test_the_schema_tells_the_model_to_check_and_never_re_ask_silently():
    schema = vault.BROWSER_VAULT_SCHEMA
    assert "check" in schema["parameters"]["properties"]["action"]["enum"]
    text = schema["description"]
    assert "credential_rejected" in text and "Never re-ask silently" in text and "takeover link" in text
