"""Round 6, fix 5: a login is bound to the right site, and the bot can fix a wrong binding itself.

Live 2026-10-29 on the Personette bot: with several tabs open, the Zillow login was bound to the
Follow Up Boss tab in front, so every Zillow fill was refused and the bot asked the client again.
Follow Up Boss and Zillow both sign in at login.zillowpro.com, with two accounts. Fake values only.
"""

import json
from types import SimpleNamespace

import pytest

from agent.vault_backends import unlock as vault_unlock
from agent.vault_store import VaultError, VaultStore
from tools import browser_vault_tool as vault

FUB = "https://mpersone.followupboss.com"
ZPRO = "https://login.zillowpro.com"
ZILLOW = "https://www.zillow.com"


def _login(store, label, identifier, origin, password="pw", **kw):
    return store.add_item("login", label, {"identifier_type": "email", "identifier": identifier,
                                           "password": password}, origin=origin, **kw)


# ── the store ──────────────────────────────────────────────────────────────────────────────────

def test_a_login_can_hold_more_than_one_origin(tmp_path):
    store = VaultStore(tmp_path / "vault")
    meta = _login(store, "Zillow agent account", "agent@example.com", ZPRO)
    assert meta.allowed_origins == ()
    meta = store.add_origin(meta.id, ZILLOW + "/homes")
    assert meta.allowed_origins == (ZPRO, ZILLOW)
    assert store.add_origin(meta.id, ZILLOW).allowed_origins == (ZPRO, ZILLOW), "no duplicate"
    assert store.add_origin(meta.id, ZPRO).allowed_origins == (ZPRO, ZILLOW)
    assert store.get_meta(meta.id).allowed_origins == (ZPRO, ZILLOW)
    assert store.resolve_secret(meta.id) == {"password": "pw"}


def test_add_origin_refuses_an_unknown_item_or_a_card(tmp_path):
    store = VaultStore(tmp_path / "vault")
    card = store.add_item("payment", "Card", {"card_number": "4111111111111111", "exp_month": "1",
                                              "exp_year": "2030", "cvc": "123", "name": "A B"},
                          origin="https://shop.example.com")
    with pytest.raises(VaultError):
        store.add_origin(card.id, ZILLOW)
    with pytest.raises(VaultError):
        store.add_origin("vault_missing", ZILLOW)


def test_the_same_label_and_identifier_replaces_the_old_login(tmp_path):
    store = VaultStore(tmp_path / "vault")
    wrong = _login(store, "Zillow agent account", "Agent@example.com", FUB, password="old",
                   replace_same_login=True)
    store.add_origin(wrong.id, ZILLOW)
    fixed = _login(store, "zillow agent account", "agent@example.com", ZPRO, password="new",
                   replace_same_login=True)
    assert fixed.id == wrong.id and len(store.list_items()) == 1
    assert fixed.origin == ZPRO and fixed.allowed_origins == (ZPRO, ZILLOW), "the wrong tab binding is gone"
    assert store.resolve_secret(fixed.id)["password"] == "new"


def test_a_second_account_under_the_same_label_is_kept(tmp_path):
    store = VaultStore(tmp_path / "vault")
    _login(store, "Zillow", "one@example.com", ZPRO, replace_same_login=True)
    _login(store, "Zillow", "two@example.com", ZPRO, replace_same_login=True)
    assert sorted(m.identifier for m in store.list_items()) == ["one@example.com", "two@example.com"]


# ── list ───────────────────────────────────────────────────────────────────────────────────────

def test_list_names_each_account_and_every_origin(tmp_path, monkeypatch):
    from agent.vault_backends.local import LocalLoginBackend
    store = VaultStore(tmp_path / "vault")
    a = _login(store, "Zillow", "one@example.com", ZPRO)
    store.add_origin(a.id, ZILLOW)
    _login(store, "Zillow", "two@example.com", ZPRO)
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    monkeypatch.setattr("agent.vault_backends.enabled_backends", lambda: [LocalLoginBackend()])
    items = json.loads(vault.browser_vault_list())["items"]
    assert [i["account"] for i in items] == ["Zillow: one@example.com", "Zillow: two@example.com"]
    assert items[0]["origins"] == [ZPRO, ZILLOW] and items[1]["origins"] == [ZPRO]
    assert "pw" not in json.dumps(items)


# ── save_login picks the right tab ─────────────────────────────────────────────────────────────

class _Page:
    """The browser as the vault sees it: which tab the supervisor is on, and its form."""

    def __init__(self, monkeypatch, current, sign_in=True, tabs=(), fake_store=True):
        self.current, self.sign_in, self.tabs, self.focus_calls = current, sign_in, set(tabs) | {current}, []
        self.saved, self.prompted = [], []
        monkeypatch.setattr(vault, "_focus_bound_origin", self._focus)
        monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: self.current)
        monkeypatch.setattr(vault, "_is_sign_in_page", lambda task_id: self.sign_in)
        monkeypatch.setattr(vault, "_page_title", lambda task_id: "")
        store = SimpleNamespace(add_item=lambda kind, label, data, origin: self.saved.append((label, origin))
                                or SimpleNamespace(id="vault_h1"))
        if fake_store:
            monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
        monkeypatch.setattr(vault, "browser_vault_fill", lambda handle, task_id=None: json.dumps({"success": True}))
        monkeypatch.setattr(vault_unlock, "can_prompt_here", lambda: True)
        vault_unlock.set_save_login_prompt_callback(
            lambda origin, site: self.prompted.append(origin) or {"identifier": "a@example.com", "password": "pw"})

    def _focus(self, task_id, origin, kind):
        self.focus_calls.append((origin, kind))
        if origin and origin in self.tabs:
            self.current = origin
            return origin
        return None


@pytest.fixture(autouse=True)
def _reset():
    from agent.vault_outcome import TRACKER
    TRACKER.clear()
    yield
    TRACKER.clear()
    vault_unlock.set_save_login_prompt_callback(None)


def test_site_binds_the_login_to_that_tab(monkeypatch):
    page = _Page(monkeypatch, current=FUB, tabs={ZPRO})
    out = json.loads(vault.browser_vault_save_login(label="Zillow agent account", site="login.zillowpro.com",
                                                    task_id="t"))
    assert out["success"] is True and out["origin"] == ZPRO
    assert page.saved == [("Zillow agent account", ZPRO)] and page.prompted == [ZPRO]
    assert page.focus_calls[0] == (ZPRO, "login")


def test_site_with_no_open_tab_is_refused_without_asking(monkeypatch):
    page = _Page(monkeypatch, current=FUB)
    out = json.loads(vault.browser_vault_save_login(label="Zillow", site="https://login.zillowpro.com/x", task_id="t"))
    assert out["error_type"] == "site_not_open" and "login.zillowpro.com" in out["error"]
    assert page.saved == [] and page.prompted == []


def test_a_page_that_is_not_a_sign_in_page_is_refused(monkeypatch):
    page = _Page(monkeypatch, current=FUB, sign_in=False)
    out = json.loads(vault.browser_vault_save_login(label="Zillow", task_id="t"))
    assert out["error_type"] == "not_a_sign_in_page"
    assert "this page is not a sign-in page" in out["error"] and "site=" in out["error"]
    assert page.saved == [] and page.prompted == []


def test_without_site_the_agents_own_tab_wins(monkeypatch):
    page = _Page(monkeypatch, current=FUB, tabs={ZPRO})
    calls = []
    supervisor = SimpleNamespace(focus_page=lambda origin, prefer_target=None, **kw: (
        calls.append((origin, prefer_target)), setattr(page, "current", origin), {"ok": True, "url": origin})[2])
    monkeypatch.setattr(vault, "_ensure_supervisor", lambda task_id: supervisor)
    monkeypatch.setattr("tools.browser_use_cli.task_tab",
                        lambda task_id: {"target_id": "T-zillow", "url": ZPRO + "/sign-in"})
    out = json.loads(vault.browser_vault_save_login(label="Zillow", task_id="t"))
    assert out["success"] is True and out["origin"] == ZPRO
    assert calls == [(ZPRO, "T-zillow")]
    assert page.focus_calls == [], "the first tab with a password field is not used"


def test_without_a_known_tab_the_old_choice_stays(monkeypatch):
    page = _Page(monkeypatch, current=ZPRO)
    monkeypatch.setattr("tools.browser_use_cli.task_tab", lambda task_id: None)
    out = json.loads(vault.browser_vault_save_login(label="Zillow", task_id="t"))
    assert out["success"] is True and page.focus_calls == [("", "login")]


def test_a_bad_site_is_refused():
    out = json.loads(vault.browser_vault_save_login(label="Zillow", site="http://", task_id="t"))
    assert out["error_type"] == "bad_site"


# ── add_origin ─────────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def saved(tmp_path, monkeypatch):
    store = VaultStore(tmp_path / "vault")
    meta = _login(store, "Zillow agent account", "agent@example.com", FUB)
    monkeypatch.setattr("agent.vault_store.get_vault_store", lambda: store)
    return SimpleNamespace(store=store, meta=meta)


def test_add_origin_binds_the_open_site(saved, monkeypatch):
    _Page(monkeypatch, current=FUB, tabs={ZPRO}, fake_store=False)
    out = json.loads(vault.browser_vault_add_origin(handle=saved.meta.id, site="login.zillowpro.com", task_id="t"))
    assert out["success"] is True and out["origins"] == [FUB, ZPRO]
    assert saved.store.get_meta(saved.meta.id).allowed_origins == (FUB, ZPRO)


def test_add_origin_is_refused_on_a_page_of_another_host(saved, monkeypatch):
    _Page(monkeypatch, current=FUB, fake_store=False)
    out = json.loads(vault.browser_vault_add_origin(handle=saved.meta.id, site="login.zillowpro.com", task_id="t"))
    assert out["error_type"] == "site_not_open"
    assert saved.store.get_meta(saved.meta.id).allowed_origins == ()


def test_add_origin_needs_a_site_and_a_local_login(saved, monkeypatch):
    _Page(monkeypatch, current=ZPRO, fake_store=False)
    assert json.loads(vault.browser_vault_add_origin(handle=saved.meta.id, site="", task_id="t"))[
        "error_type"] == "site_required"
    assert "No vault item" in json.loads(vault.browser_vault_add_origin(handle="vault_nope", site=ZPRO))["error"]


def test_the_tool_routes_add_origin(saved, monkeypatch):
    _Page(monkeypatch, current=ZPRO, tabs={ZPRO}, fake_store=False)
    monkeypatch.setattr(vault, "_fenced_page_op", lambda tid, fn: fn())
    out = json.loads(vault._handle_vault({"action": "add_origin", "handle": saved.meta.id,
                                          "site": "login.zillowpro.com"}, task_id="t"))
    assert out["success"] is True


# ── fill on the wrong site ─────────────────────────────────────────────────────────────────────

def test_an_origin_mismatch_names_both_sides_and_the_fix(monkeypatch):
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda task_id: ZPRO)
    meta = SimpleNamespace(id="vault_z1", kind="login", origin=FUB, allowed_origins=())
    out = vault._bound_page_origin("t", meta, "login")
    assert out["error_type"] == "origin_mismatch"
    assert out["bound_origins"] == [FUB] and out["page_origin"] == ZPRO
    assert "add_origin" in out["hint"] and "handle=vault_z1" in out["hint"] and "site=login.zillowpro.com" in out["hint"]
    assert "Do not ask the client again" in out["hint"]


# ── browser_exec reports its tab ───────────────────────────────────────────────────────────────

def test_browser_exec_records_and_hides_its_tab():
    import ast
    from tools import browser_use_cli as bu
    ast.parse("print(1)" + bu._TAB_REPORT_POSTAMBLE)
    out = bu._take_tab_report("task-9", 'ok\n\n\x1ehermes-tab:{"target_id": "T1", "url": "https://login.zillowpro.com/a"}\n')
    assert out == "ok\n"
    assert bu.task_tab("task-9") == {"target_id": "T1", "url": "https://login.zillowpro.com/a"}
    assert bu._take_tab_report("task-9", "plain") == "plain"
    bu._take_tab_report("task-9", '\x1ehermes-tab:{"target_id": "T2", "url": "about:blank"}')
    assert bu.task_tab("task-9")["target_id"] == "T1", "a blank tab is not recorded"


def test_the_schema_has_site_and_add_origin():
    params = vault.BROWSER_VAULT_SCHEMA["parameters"]["properties"]
    assert "add_origin" in params["action"]["enum"] and "site" in params
    assert "add_origin" in vault.BROWSER_VAULT_SCHEMA["description"]
