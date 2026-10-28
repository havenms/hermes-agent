"""Logins with more than one secret field: a PIN, a security answer, a memorable word.

The local vault stores them next to the password. save_login asks for them (one numbered card
each) or takes them pasted. fill types them when a page field's label matches, and fill_field
types one named field. Every value goes through the same origin guard and redaction as the password.
"""

import json
from types import SimpleNamespace

import pytest

from agent.vault_backends import unlock as vault_unlock
from agent.vault_login_classifier import LoginControl, match_extra_field, select_extra_fills
from agent.vault_store import VaultError, VaultStore, normalize_extra_fields
from gateway.vault_prompts import build_vault_prompt_callbacks
from tools import browser_vault_tool as vault
from tools import clarify_gateway as cm


def _control(index, label="", name="", type_="text"):
    return LoginControl(autocomplete="", form_index=0, index=index, label=label, name=name, type=type_)


# ── store ──────────────────────────────────────────────────────────────────────────────────────

def test_the_local_vault_keeps_extra_values_secret_and_labels_as_metadata(tmp_path):
    store = VaultStore(tmp_path / "vault")
    meta = store.add_item("login", "Bank", {"identifier_type": "username", "identifier": "owner", "password": "pw",
                                            "extra": {"PIN": "4321", "Security answer": "rex"}},
                          origin="https://bank.example.com")
    assert meta.extra_labels == ("PIN", "Security answer")
    assert "4321" not in json.dumps(meta.to_dict()) and meta.to_dict()["extra_fields"] == ["PIN", "Security answer"]
    assert store.resolve_secret(meta.id)["extra"] == {"PIN": "4321", "Security answer": "rex"}
    assert store.get_meta(meta.id).extra_labels == ("PIN", "Security answer")


def test_a_login_without_extras_is_stored_as_before(tmp_path):
    store = VaultStore(tmp_path / "vault")
    meta = store.add_item("login", "Shop", {"identifier_type": "email", "identifier": "a@b.co", "password": "pw"},
                          origin="https://shop.example.com")
    assert meta.extra_labels == () and store.resolve_secret(meta.id) == {"password": "pw"}


@pytest.mark.parametrize("extra", [
    {"": "1"}, {"PIN": ""}, {"password": "x"}, {"PIN": "1", "pin": "2"}, {f"f{i}": "v" for i in range(5)},
    {"x" * 46: "v"},
])
def test_bad_extra_fields_are_refused(extra):
    with pytest.raises(VaultError):
        normalize_extra_fields(extra)


def test_the_local_backend_resolves_extras_and_keeps_them_out_of_resolve_secret(monkeypatch, tmp_path):
    from agent.vault_backends.local import LocalLoginBackend
    store = VaultStore(tmp_path / "vault")
    meta = store.add_item("login", "Bank", {"identifier_type": "username", "identifier": "o", "password": "pw",
                                            "extra": {"PIN": "4321"}}, origin="https://bank.example.com")
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    backend = LocalLoginBackend()
    assert backend.supports_extra_fields is True
    assert backend.resolve_extra(meta.id) == {"PIN": "4321"}
    assert "extra" not in backend.resolve_secret(meta.id)


def test_password_manager_backends_do_not_claim_extra_fields():
    from agent.vault_backends.bitwarden import BitwardenLoginBackend
    from agent.vault_backends.onepassword import OnePasswordLoginBackend
    assert OnePasswordLoginBackend.supports_extra_fields is False
    assert BitwardenLoginBackend.supports_extra_fields is False


# ── label matching ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label, control, hit", [
    ("PIN", _control(0, label="Pin code"), True),
    ("PIN", _control(0, name="pin_code"), True),
    ("PIN", _control(0, name="pinCode"), True),
    ("pin", _control(0, label="PIN"), True),
    ("PIN", _control(0, label="Loading spinner"), False),
    ("Security answer", _control(0, label="Answer to your security question"), True),
    ("Memorable word", _control(0, name="memorableword"), True),
    ("PIN", _control(0, label="Company ID"), False),
])
def test_extra_labels_match_page_fields_loosely(label, control, hit):
    assert (match_extra_field(label, control) > 0) is hit


def test_extra_fills_skip_the_password_field_and_report_unmatched():
    controls = [_control(0, label="Password", type_="password"), _control(1, label="PIN", type_="password"),
                _control(2, label="Company ID")]
    fills, unmatched = select_extra_fills(controls, {"PIN": "4321", "Memorable word": "x"}, taken={0})
    assert [(f["index"], f["label"], f["token"]) for f in fills] == [(1, "PIN", "extra")]
    assert unmatched == ["Memorable word"]


# ── save_login ─────────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def page(monkeypatch):
    saved, redacted, prompts = [], [], []
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, **k: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: "https://books.example.com")
    monkeypatch.setattr(vault, "_page_title", lambda task_id: "Sign in - Books")
    store = SimpleNamespace(add_item=lambda kind, label, data, origin: saved.append((kind, label, dict(data), origin))
                            or SimpleNamespace(id="vault_h1"))
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda value: redacted.append(value))
    monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps(
        {"success": True, "filled_fields": 2, "extra_filled": ["PIN"]}))
    monkeypatch.setattr(vault_unlock, "can_prompt_here", lambda: True)
    vault_unlock.set_pasted_secret_scrub_callback(None)
    yield SimpleNamespace(saved=saved, redacted=redacted, prompts=prompts)
    vault_unlock.set_save_login_prompt_callback(None)
    vault_unlock.set_pasted_secret_scrub_callback(None)


def test_a_prompted_login_asks_for_the_extra_fields_and_stores_them(page):
    def prompt(origin, site, extra_fields=()):
        page.prompts.append((origin, site, extra_fields))
        return {"identifier": "owner", "password": "pw", "extra": {"PIN": "4321"}}
    vault_unlock.set_save_login_prompt_callback(prompt)
    out = json.loads(vault.browser_vault_save_login(label="TestCo Books", extra_fields=["PIN"], task_id="t"))
    assert out["success"] is True and out["extra_fields"] == ["PIN"]
    assert page.prompts == [("https://books.example.com", "TestCo Books", ("PIN",))]
    assert page.saved[0][2]["extra"] == {"PIN": "4321"}
    assert "4321" in page.redacted and "4321" not in json.dumps(out)


def test_a_half_answered_login_is_not_stored(page):
    vault_unlock.set_save_login_prompt_callback(
        lambda origin, site, extra_fields=(): {"identifier": "owner", "password": "pw", "extra": {}})
    out = json.loads(vault.browser_vault_save_login(extra_fields=["PIN"], task_id="t"))
    assert out["error_type"] == "save_declined" and page.saved == []


def test_a_surface_without_extra_support_gets_a_clear_refusal(page):
    vault_unlock.set_save_login_prompt_callback(lambda origin, site: {"identifier": "o", "password": "p"})
    out = json.loads(vault.browser_vault_save_login(extra_fields=["PIN"], task_id="t"))
    assert out["error_type"] == "extra_fields_unsupported" and page.saved == []


def test_a_pasted_login_takes_extras_and_redacts_them(page):
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", extra={"PIN": "4321"},
                                                    task_id="t"))
    assert out["success"] is True and page.saved[0][2]["extra"] == {"PIN": "4321"}
    assert {"pw", "4321"} <= set(page.redacted)


def test_a_pasted_login_must_carry_a_value_for_each_named_extra(page):
    out = json.loads(vault.browser_vault_save_login(identifier="owner", password="pw", extra_fields=["PIN"],
                                                    task_id="t"))
    assert out["error_type"] == "extra_value_required" and page.saved == []


@pytest.mark.parametrize("label, title, shown", [
    ("TestCo Books", "Sign in - Books", "TestCo Books"),
    ("", "Sign in - Books", "Sign in - Books"),
    ("", "", "books.example.com"),
])
def test_the_card_names_the_site_by_label_then_title_then_host(page, monkeypatch, label, title, shown):
    monkeypatch.setattr(vault, "_page_title", lambda task_id: title)
    vault_unlock.set_save_login_prompt_callback(
        lambda origin, site: page.prompts.append(site) or {"identifier": "o", "password": "p"})
    vault.browser_vault_save_login(label=label, task_id="t")
    assert page.prompts == [shown]


# ── cards ──────────────────────────────────────────────────────────────────────────────────────

def test_the_cards_are_numbered_one_per_field_and_never_teach_skip():
    asked = []
    answers = iter(["owner", "pw", "4321", "rex"])

    def ask(question, **kw):
        asked.append((question, kw))
        return next(answers)

    got = build_vault_prompt_callbacks(ask)["save_login"]("https://x", "TestCo Books", ("PIN", "Security answer"))
    assert got == {"identifier": "owner", "password": "pw", "extra": {"PIN": "4321", "Security answer": "rex"}}
    texts = [q for q, _ in asked]
    assert ["(1/4)" in texts[0], "(2/4)" in texts[1], "(3/4)" in texts[2], "(4/4)" in texts[3]] == [True] * 4
    assert "TestCo Books" in texts[0] and "PIN" in texts[2]
    assert all("skip" not in t.lower() for t in texts)
    assert "Just tell me" in texts[1]
    assert [kw["secret"] for _, kw in asked] == [False, True, True, True]
    assert [kw["last"] for _, kw in asked] == [False, False, False, True]


def test_two_cards_without_extras_keep_the_old_shape():
    asked = []
    answers = iter(["owner", "pw"])
    got = build_vault_prompt_callbacks(lambda q, **kw: asked.append(q) or next(answers))["save_login"]("https://x", "Shop")
    assert got == {"identifier": "owner", "password": "pw"} and "(2/2)" in asked[1]


def test_a_decline_on_an_extra_card_stores_nothing():
    answers = iter(["owner", "pw", ""])
    got = build_vault_prompt_callbacks(lambda q, **kw: next(answers))["save_login"]("https://x", "Shop", ("PIN",))
    assert got is None


# ── decline words ──────────────────────────────────────────────────────────────────────────────

KEY = "agent:main:discord:thread:9:9"


@pytest.fixture()
def clean_clarify():
    def clear():
        with cm._lock:
            cm._entries.clear()
            cm._session_index.clear()
    clear()
    yield
    clear()


@pytest.mark.parametrize("word", ["skip", "cancel", "stop", "Stop."])
def test_plain_decline_words_still_work_on_a_login_card(clean_clarify, word):
    entry = cm.register("p1", KEY, "password?", None, secret=True, owner_user_id="1", chat_guard=True,
                        kind="save_login")
    assert cm.attempt_text_response_for_session(KEY, word, "1") == cm.TEXT_RESOLVED
    assert entry.response == cm.SKIPPED


@pytest.mark.parametrize("word", ["wrong", "Wrong email", "that's wrong."])
def test_wrong_email_words_go_back_and_do_not_decline(clean_clarify, word):
    entry = cm.register("p1", KEY, "password?", None, secret=True, owner_user_id="1", chat_guard=True,
                        kind="save_login")
    assert cm.attempt_text_response_for_session(KEY, word, "1") == cm.TEXT_RESOLVED
    assert entry.response == cm.WRONG_ANSWER


def test_an_ordinary_question_takes_cancel_as_an_answer(clean_clarify):
    entry = cm.register("q1", KEY, "what should the subject say?", None)
    assert cm.attempt_text_response_for_session(KEY, "cancel", "1") == cm.TEXT_RESOLVED
    assert entry.response == "cancel"


# ── fill_field ─────────────────────────────────────────────────────────────────────────────────

class _Backend:
    name, display_name, needs_unlock, supports_extra_fields = "local", "Saved logins", False, True

    def __init__(self, labels=("PIN",)):
        self.labels = labels

    def get_meta(self, handle):
        return SimpleNamespace(id=handle, kind="login", label="Bank", origin="https://bank.example.com",
                               extra_labels=self.labels, has_otp=False, allowed_origins=())

    def resolve_extra(self, handle):
        return {"PIN": "4321"}

    def resolve_password(self, handle):
        return "pw"

    def fill_context(self):
        import contextlib
        return contextlib.nullcontext()


@pytest.fixture()
def bank(monkeypatch):
    calls = SimpleNamespace(secret_js=[], redacted=[], backend=_Backend())
    monkeypatch.setattr("agent.vault_backends.backend_for_handle", lambda handle: calls.backend)
    monkeypatch.setattr(vault, "_bound_page_origin", lambda task_id, meta, kind: "https://bank.example.com")
    monkeypatch.setattr(vault, "snapshot_refusal", lambda *a: None)
    monkeypatch.setattr("agent.redact.register_vault_redaction_value", lambda v: calls.redacted.append(v))
    controls = [{"autocomplete": "", "formIndex": 0, "index": 0, "label": "Password", "name": "pw", "type": "password"},
                {"autocomplete": "", "formIndex": 0, "index": 1, "label": "Pin code", "name": "pin", "type": "password"}]

    def eval_js(task_id, expr):
        if "data-hermes-vault-slot\", nonce" in expr or "querySelectorAll(\"input, select\")" in expr:
            return {"success": True, "result": json.dumps(controls)}
        return {"success": True, "result": "1"}  # the ref probe: slot index 1
    monkeypatch.setattr(vault, "_eval_js", eval_js)

    def eval_secret(task_id, expr):
        calls.secret_js.append(expr)
        return {"success": True, "result": json.dumps({"filled": 1})}
    monkeypatch.setattr(vault, "_eval_js_secret", eval_secret)
    return calls


def test_fill_field_types_the_named_secret_into_the_matching_field(bank):
    out = json.loads(vault.browser_vault_fill_field("vault_h1", "pin", task_id="t"))
    assert out == {"success": True, "field": "PIN", "filled_fields": 1, "origin": "https://bank.example.com",
                   "backend": "local"}
    assert bank.redacted == ["4321"]
    assert '"index": 1' in bank.secret_js[0] and "https://bank.example.com" in bank.secret_js[0]
    assert "4321" not in json.dumps(out)


def test_fill_field_takes_a_css_selector(bank):
    out = json.loads(vault.browser_vault_fill_field("vault_h1", "PIN", ref="#pin", task_id="t"))
    assert out["success"] is True and '"index": 1' in bank.secret_js[0]


def test_fill_field_refuses_an_unknown_field(bank):
    out = json.loads(vault.browser_vault_fill_field("vault_h1", "Memorable word", task_id="t"))
    assert out["error_type"] == "unknown_field" and bank.secret_js == []


def test_fill_field_refuses_extras_on_a_password_manager(bank):
    bank.backend.supports_extra_fields = False
    out = json.loads(vault.browser_vault_fill_field("vault_h1", "PIN", task_id="t"))
    assert out["error_type"] == "extra_fields_unsupported" and bank.secret_js == []


def test_fill_field_obeys_the_origin_guard(bank, monkeypatch):
    monkeypatch.setattr(vault, "_bound_page_origin", lambda *a: {"success": False, "error_type": "origin_mismatch"})
    out = json.loads(vault.browser_vault_fill_field("vault_h1", "PIN", task_id="t"))
    assert out["error_type"] == "origin_mismatch" and bank.secret_js == [] and bank.redacted == []


def test_the_schema_offers_fill_field_and_extra_fields():
    props = vault.BROWSER_VAULT_SCHEMA["parameters"]["properties"]
    assert "fill_field" in props["action"]["enum"]
    assert {"extra_fields", "extra", "field", "ref"} <= set(props)
