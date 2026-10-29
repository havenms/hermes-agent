#!/usr/bin/env python3
"""Vault-backed model-blind browser autofill tools.

One model-facing tool, ``browser_vault``, deferred behind tool_search (only its catalog line is
paid per request) and available wherever a browser is. Its actions:

- ``list``  → handles + metadata (for logins this includes the
  identifier — it is NOT a secret; the agent types it itself). Passwords are
  never returned.
- ``fill``  → server-side fill of the CURRENT page from a vault
  handle: the password field for logins, card fields for payment items (after
  the user confirms), address fields for address items. The secret is
  resolved locally, the page origin must EXACTLY match the item's bound
  origin (pre-checked AND re-asserted synchronously inside the fill script),
  the field is chosen by the ported login-control classifier, injection runs
  exclusively over the supervisor CDP WebSocket (never argv), and the tool
  result reports only ``{filled_fields, kind, origin, success}`` — the
  password never appears in tool results, logs, or the session DB, and its
  exact bytes are registered with the browser-result redaction boundary so
  no later browser tool call can echo them back to the model.
- ``enter_code`` → a one-time code for the current page: minted from a saved
  login's authenticator key (same origin binding as ``fill``, checked before
  the code is generated) or typed by the user into their surface's prompt.
- ``check`` → after a submit: did the site take what the vault typed? One
  outcome check for every secret (see ``agent/vault_outcome.py``). A rejection
  names the field and the reason, the next card tells the client, and a third
  retry, a locked sign-in or a device check go to the takeover link.

Ported design from Merit-Systems/OpenInstinct (MIT): opaque-handle vault
autofill (kernel-login-autofill.ts / fill_from_vault.ts).
"""

from __future__ import annotations

import json
import secrets
import logging
import time
from typing import Any, Dict, Optional

from tools.browser_vault_context import plugin_errors_as_refusal, saved_origins, snapshot_refusal, write_backend_code

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _check_vault_available() -> bool:
    """Schema-gate: the vault rides with the browser. An empty vault still needs save_login so the
    agent can offer to remember a login the first time it meets a form; hiding the tool until an item
    exists meant nobody ever discovered the feature. Deferral keeps that presence nearly free."""
    from tools.browser_session_cdp import get_cdp_override_raw
    from tools.browser_use_cli import browser_exec_available
    return bool(browser_exec_available() or get_cdp_override_raw())


# ---------------------------------------------------------------------------
# JS evaluation plumbing (server-side; results never carry secret values)
# ---------------------------------------------------------------------------

def _eval_js(task_id: str, expression: str) -> dict[str, Any]:
    """Evaluate NON-SECRET JS on the current page (inspection, origin reads) over the task's CDP
    supervisor. There is no other path: without a supervisor the call reports it."""
    supervisor = _ensure_supervisor(task_id)
    if supervisor is None:
        return {"success": False, "error": "no supervised browser session for this task; open the page with "
                                           "browser_exec first"}
    sup = supervisor.evaluate_runtime(expression)
    if sup.get("ok"):
        return {"success": True, "result": sup.get("result")}
    return {"success": False, "error": str(sup.get("error") or "evaluate failed")}


def _ensure_supervisor(task_id: str):
    """The supervisor for ``task_id`` (browser_exec attaches one on every call), attaching one on demand to
    the task's session CDP endpoint when none is running. None when no endpoint is known; a fill then
    refuses rather than touching argv."""
    from tools.browser_supervisor import SUPERVISOR_REGISTRY

    supervisor = SUPERVISOR_REGISTRY.get(task_id)
    if supervisor is not None:
        return supervisor
    from tools.browser_session import session_for_task
    from tools.browser_session_cdp import get_dialog_policy_config, resolve_cdp_override

    cdp_url = str(session_for_task(task_id).get("cdp_url") or "")
    if not cdp_url:
        return None
    policy, timeout_s = get_dialog_policy_config()
    try:
        return SUPERVISOR_REGISTRY.get_or_start(task_id=task_id, cdp_url=resolve_cdp_override(cdp_url),
                                                dialog_policy=policy, dialog_timeout_s=timeout_s)
    except Exception as exc:  # health: allow BLE001 -- a failed attach is reported as supervisor_required
        logger.debug("vault fill: supervisor attach to the task's session failed (%s)", exc)
        return None


def _eval_js_secret(task_id: str, expression: str) -> dict[str, Any]:
    """Evaluate a SECRET-BEARING JS expression. Supervisor CDP-WS only.

    Fails closed: there is deliberately NO subprocess path, because that would
    place the expression — and therefore the credential bytes — in argv,
    visible to any process listing. When no supervisor session is available
    the caller gets a typed refusal (``error_type='supervisor_required'``) and
    nothing is written.
    """
    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception as exc:
        logger.debug("vault fill: supervisor unavailable (%s)", exc)
        supervisor = None

    if supervisor is None:
        return {
            "success": False,
            "error_type": "supervisor_required",
            "error": (
                "Vault fill requires the supervised browser session (direct "
                "CDP WebSocket), and this task has none. Open the page with "
                "browser_exec and retry."
            ),
        }

    # Re-admit at the WRITE. The handler-level fence (_fenced_page_op) admitted before a possibly
    # human-length prompt (enter_code waits for the user's code); a takeover during that wait must
    # refuse here, before the credential lands in a page the human is now typing into. The outer
    # epoch check only discards the result, and a fill is a side effect, not a result.
    if _bot_desktop_browser_session(task_id):
        from tools.bot_desktop import lease as _bd_lease
        try:
            _bd_lease.assert_agent_may_act()
        except _bd_lease.HumanHasControl as exc:
            return {"success": False, "error_type": "human_has_control", "error": str(exc)}

    sup = supervisor.evaluate_runtime(expression)
    if sup.get("ok"):
        return {"success": True, "result": sup.get("result")}
    return {
        "success": False,
        "error_type": "supervisor_required"
        if "supervisor" in str(sup.get("error") or "").lower()
        else "eval_failed",
        "error": str(sup.get("error") or "eval failed"),
    }


def _parse_json_result(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw
    return raw


def _current_page_origin(task_id: str) -> Optional[str]:
    res = _eval_js(task_id, "window.location.href")
    if not res.get("success"):
        return None
    href = str(res.get("result") or "").strip().strip('"').strip("'")
    if not href or href == "about:blank":
        return None
    try:
        from agent.vault_store import normalize_origin

        return normalize_origin(href)
    except Exception:
        return None


# Per kind: a JS probe that is truthy on a tab holding the form this kind fills.
_TAB_PROBES = {
    "login": "!!document.querySelector('input[type=password]')",
    "payment": "!!document.querySelector('input[autocomplete^=cc-], [name*=card i], [placeholder*=card i], [name*=cvc i], [name*=cvv i]')",
    "address": "!!document.querySelector('input[autocomplete^=address-], [autocomplete=postal-code], [name*=address i], [name*=zip i], [name*=postal i]')",
}


def _focus_bound_origin(task_id: str, origin: str, kind: str) -> Optional[str]:
    """Point the supervisor's page session at the open tab on ``origin`` that holds a ``kind`` form
    (browser_exec sessions open their own tabs, so the tab the supervisor attached to first is rarely the
    login page). Returns the origin when a tab was focused, else None (caller falls back to the current page)."""
    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception:
        supervisor = None
    if supervisor is None:
        return None
    focused = supervisor.focus_page(origin, accept=_TAB_PROBES.get(kind))
    return (origin or focused.get("url")) if focused.get("ok") else None


def _bound_page_origin(task_id: str, meta: Any, probe_kind: str) -> str | dict[str, Any]:
    """The origin guard every fill of a stored secret (password, one-time code, card, address) passes
    BEFORE the backend resolves any value: the page origin when it is one of the item's saved origins,
    else the refusal to return. Manager items may bind several websites; matching is exact and
    nothing wildcard or parent-domain is inferred. The caller hands the returned origin to ``build_fill_js``,
    which re-asserts it inside the page immediately before the write (navigation between check and fill)."""
    allowed = saved_origins(meta)
    if not allowed:
        return {"success": False, "error_type": "no_origin",
                "error": f"Vault item {meta.id!r} has no bound origin; {meta.kind} items are filled only on "
                         "the site they were saved for."}
    page_origin = next((o for o in (_focus_bound_origin(task_id, c, probe_kind) for c in allowed) if o), None)
    page_origin = page_origin or _current_page_origin(task_id)
    if not page_origin:
        return {"success": False,
                "error": "Could not determine the current page origin. Navigate to the login page first."}
    if page_origin not in allowed:
        out = {"success": False, "error_type": "origin_mismatch", "bound_origins": list(allowed),
               "page_origin": page_origin,
               "error": (f"Refused: current page origin ({page_origin}) does not match the vault item's bound "
                         f"origin(s) ({', '.join(allowed)}). Vault fills only run on the exact origin(s) the "
                         "credential was saved for.")}
        if getattr(meta, "kind", "") == "login":
            out["hint"] = (f"If this is the right login for this page, call browser_vault action=add_origin "
                           f"handle={meta.id} site={_site_of(page_origin)}, then fill again. If it is the wrong "
                           "login, use another handle from list. Do not ask the client again.")
        return out
    return page_origin


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def browser_vault_list() -> str:
    """List login handles + metadata across every enabled backend. Passwords are never included.

    A locked external manager contributes no items; instead it is reported under ``locked`` so the
    agent knows to call fill (which prompts the user to unlock) or tell the user.
    """
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here

    items, locked, errors = [], [], []
    for backend in enabled_backends():
        if backend.needs_unlock and not backend.is_unlocked():
            locked.append({"backend": backend.name, "display_name": backend.display_name,
                           "unlock": "browser_vault action=unlock" if can_prompt_here() else "unavailable_in_this_session"})
            continue
        try:
            metas = backend.list_items()
        except Exception as exc:
            errors.append({"backend": backend.name, "error": str(exc)[:200]})
            continue
        for meta in metas:
            entry = {"handle": meta.id, "backend": backend.name, "label": meta.label, "kind": meta.kind,
                     "origin": meta.origin, "available": meta.kind == "login" or bool(meta.origin)}
            if len(meta.allowed_origins) > 1:
                entry["allowed_origins"] = list(meta.allowed_origins)
            if meta.has_otp or backend.needs_unlock:
                entry["two_factor"] = "automatic" if meta.has_otp else "automatic if the manager stores a TOTP seed, else the user is asked"
            if meta.identifier:
                entry["identifier"] = meta.identifier
                entry["identifier_type"] = meta.identifier_type
            if meta.kind == "login":
                # TAPAS: two accounts can share a label or an origin; name each one by its account.
                entry["origins"] = saved_origins(meta)
                if meta.identifier:
                    entry["account"] = f"{meta.label}: {meta.identifier}"
            if getattr(meta, "extra_labels", ()):
                entry["extra_fields"] = list(meta.extra_labels)
            items.append(entry)
    out: dict[str, Any] = {"success": True, "items": items}
    if not items:
        out["hint"] = ("No saved logins. On a login page, call browser_vault action=save_login: the client gets a "
                       "login prompt (preferred). If the client already pasted a login in chat, pass it to "
                       "save_login as identifier and password, then use it. Never repeat a password back in a message.")
    if locked:
        out["locked"] = locked
    if errors:
        out["errors"] = errors
    return json.dumps(out, ensure_ascii=False)


def browser_vault_unlock(backend_name: str) -> str:
    """Ask the user (via the surface's masked prompt) to unlock an external manager for this session."""
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here, get_unlock_prompt_callback

    backend = next((b for b in enabled_backends() if b.name == backend_name and b.needs_unlock), None)
    if backend is None:
        return json.dumps({"success": False, "error": f"No unlockable vault backend named {backend_name!r}."})
    if backend.is_unlocked():
        return json.dumps({"success": True, "backend": backend.name, "already_unlocked": True})
    if not can_prompt_here():
        return json.dumps({"success": False, "error_type": "unlock_unavailable",
                           "error": (f"{backend.display_name} is locked and this session cannot prompt for the "
                                     "master password (headless/cron/API). Unlock it from an interactive Hermes "
                                     "session or the Desktop app first.")})
    prompt = get_unlock_prompt_callback()
    master = prompt(backend.name, backend.display_name) if prompt else ""
    if not master and _cancelled_by_message():
        return _cancelled_by_message_result(backend.display_name)
    if not master:
        return json.dumps({"success": False, "error_type": "unlock_cancelled",
                           "error": f"The user declined to unlock {backend.display_name}."})
    try:
        backend.unlock(master)  # type: ignore[attr-defined]
    except Exception as exc:
        return json.dumps({"success": False, "error_type": "unlock_failed", "error": str(exc)[:300]})
    finally:
        del master
    return json.dumps({"success": True, "backend": backend.name})


def browser_vault_save_login(label: str = "", task_id: Optional[str] = None,
                             identifier: str = "", password: str = "",
                             extra_fields: Any = None, extra: Any = None, site: str = "") -> str:
    """Ask the user (masked prompt on their surface) for the login of the CURRENT page, store it in the local
    vault bound to that origin, and fill the password at once. The values never enter the conversation.

    ``identifier`` alone (no ``password``): the agent already knows the email or username (it typed it on
    the page, or the client said it). Then the prompt asks only for the password and any extra fields,
    and the login is stored with that identifier. A surface whose prompt cannot take it asks for both.

    ``site`` (a host or URL): bind the login to that origin; its tab is the one filled. Without it, the
    login is bound to the tab the agent works in (the tab its last browser_exec ended on), never just
    the first tab the supervisor finds. A page with no password field and no login form is refused.

    Fallback: when the user already pasted the login in a normal chat message, the agent passes it as
    ``identifier`` + ``password``. It is stored exactly as a prompted login (same origin binding), the
    password is registered with the model-egress redaction boundary first, and the surface is asked to
    delete the user's message."""
    from agent.vault_backends.unlock import can_prompt_here, get_save_login_prompt_callback
    from agent.vault_store import get_vault_store, normalize_extra_fields

    pasted = bool(password)
    pasted_extra = dict(extra) if isinstance(extra, dict) else {}
    if pasted:
        from agent.redact import register_vault_redaction_value
        register_vault_redaction_value(password)  # before any page or result can echo it
        for value in pasted_extra.values():
            register_vault_redaction_value(str(value or ""))
        if not str(identifier or "").strip():
            return json.dumps({"success": False, "error_type": "identifier_required",
                               "error": "A pasted login needs both identifier (email or username) and password."})
    labels = _extra_labels(extra_fields, pasted_extra)
    if isinstance(labels, str):
        return json.dumps({"success": False, "error_type": "bad_extra_fields", "error": labels})
    if pasted and [lb for lb in labels if lb not in pasted_extra]:
        return json.dumps({"success": False, "error_type": "extra_value_required", "error": (
            "A pasted login with extra fields needs a value for each one in `extra`. Or omit password and "
            "extra to ask the client in a prompt.")})

    effective_task_id = task_id or "default"
    origin = _login_tab_origin(effective_task_id, site)
    if isinstance(origin, dict):
        return json.dumps(origin)
    prompt = get_save_login_prompt_callback()
    if not pasted and (prompt is None or not can_prompt_here()):
        return json.dumps({"success": False, "error_type": "prompt_unavailable",
                           "error": (f"This session cannot ask the user for a login (headless/cron/API). Tell them to run "
                                     f"`hermes vault add` or use Desktop → Settings → Passwords & Logins for {origin}.")})
    host = origin.split("://", 1)[-1]
    site = label.strip() or host
    # The prompt names the site the way the client knows it: the model's label ("TestCo Books"), then
    # the page title, and only then the host.
    shown = label.strip() or _page_title(effective_task_id) or host
    # A field the site refused before: the card says which one, and a capped field is not asked again.
    gate = _retry_gate(effective_task_id, origin, ["identifier", "password", *labels], shown)
    if isinstance(gate, dict):
        return json.dumps(gate, ensure_ascii=False)
    notice = gate
    if pasted:
        answer = {"identifier": str(identifier).strip(), "password": str(password),
                  **({"extra": {lb: str(pasted_extra[lb]) for lb in labels}} if labels else {})}
    elif labels:
        if not _accepts_extra_fields(prompt):
            return json.dumps({"success": False, "error_type": "extra_fields_unsupported", "error": (
                "This surface can only ask for an email and a password. Ask the client to send the other "
                f"fields ({', '.join(labels)}) in chat, then call save_login with identifier, password and extra.")})
        answer = prompt(origin, shown, extra_fields=tuple(labels), **_notice_kw(prompt, notice),
                        **_known_identifier_kw(prompt, identifier, effective_task_id, origin))
    else:
        answer = prompt(origin, shown, **_notice_kw(prompt, notice),
                        **_known_identifier_kw(prompt, identifier, effective_task_id, origin))
    if answer and labels and set((answer.get("extra") or {})) != set(labels):
        answer = None  # the client stopped part way: store nothing half-done
    if not answer and _cancelled_by_message():
        return _cancelled_by_message_result(shown)
    if not answer or not answer.get("password") or not answer.get("identifier"):
        return json.dumps({"success": False, "error_type": "save_declined",
                           "error": "The user chose not to save a login for this site. Do not ask again this turn."})
    identifier = str(answer["identifier"]).strip()
    id_type = "email" if "@" in identifier else ("phone" if identifier.lstrip("+").isdigit() else "username")
    try:
        payload = {"identifier_type": id_type, "identifier": identifier, "password": str(answer["password"])}
        if labels:
            payload["extra"] = normalize_extra_fields(answer["extra"])
            from agent.redact import register_vault_redaction_value
            for value in payload["extra"].values():
                register_vault_redaction_value(value)
        # A retry for the same email or username updates that login; it does not add a second one.
        store = get_vault_store()
        replace = {"replace_same_login": True} if _accepts_kw(store.add_item, "replace_same_login") else {}
        meta = store.add_item("login", site, payload, origin=origin, **replace)
    except Exception as exc:
        return json.dumps({"success": False, "error_type": "save_failed", "error": str(exc)[:200]})
    finally:
        answer.clear()
    from agent.vault_outcome import TRACKER as _tracker
    _tracker.note_saved(effective_task_id, origin, meta.id)
    filled = json.loads(browser_vault_fill(meta.id, task_id=effective_task_id))
    out = {"success": True, "handle": meta.id, "origin": origin, "identifier": identifier,
           "identifier_type": id_type, "fill": filled,
           "next": "Type the identifier into the username field if the form has one, then submit.",
           "if_rejected": _password_rejected_hint(origin)}
    if labels:
        out["extra_fields"] = list(labels)
        missing = (filled.get("extra_unmatched") if isinstance(filled, dict) else None) or list(labels)
        if missing:
            out["next"] += (f" Not typed yet: {', '.join(missing)}. When the page shows that field, call "
                            "browser_vault action=fill_field with this handle and field=<label>.")
    if not (isinstance(filled, dict) and filled.get("success")):
        out["password_typed"] = False
        out["next"] = ("The login is saved, but the password could not be typed into this page. Open the sign-in "
                       "form, then call browser_vault action=fill with this handle.")
    if pasted:
        out["source"] = "pasted"
        out["chat_message_removed"] = _scrub_pasted_message(
            (str(password), *(str(v) for v in pasted_extra.values() if v)))
        out["next"] += (" Never repeat the password in a message." if out["chat_message_removed"] else
                        " The client's message with the password is still in the chat: ask them to delete it. "
                        "Never repeat the password in a message.")
    return json.dumps(out, ensure_ascii=False)


# Truthy on a sign-in page: a password field, or a form that asks for an email or username
# (a username-first page shows the password on a second step).
_SIGN_IN_PROBE = (
    "!!(document.querySelector('input[type=password]') || document.querySelector("
    "'input[type=email], input[autocomplete~=username], input[autocomplete=email], "
    "form input[name*=user i], form input[name*=email i], form input[name*=login i], "
    "form input[id*=user i], form input[id*=email i], form input[id*=login i]'))")
_TAB_PROBES["signin"] = _SIGN_IN_PROBE


def _site_origin(site: str) -> Optional[str]:
    """The origin of ``site`` (a host such as login.zillowpro.com, or a URL); None when empty.
    Raises VaultError when it cannot be parsed."""
    from agent.vault_store import normalize_origin
    value = str(site or "").strip()
    if not value:
        return None
    return normalize_origin(value if "://" in value else f"https://{value}")


def _focus_task_tab(task_id: str) -> bool:
    """Point the supervisor at the tab the agent's last browser_exec ended on. False when that tab
    is unknown or gone; the caller then falls back to the first tab with a login form."""
    try:
        from agent.vault_store import normalize_origin
        from tools.browser_use_cli import task_tab
        tab = task_tab(task_id)
        origin = normalize_origin(tab["url"]) if tab else ""
        supervisor = _ensure_supervisor(task_id) if origin else None
    except Exception:  # health: allow BLE001 -- an unknown tab keeps the old tab choice
        return False
    if supervisor is None:
        return False
    try:
        focused = supervisor.focus_page(origin, prefer_target=tab.get("target_id") or None)
    except TypeError:  # a supervisor without prefer_target: the first tab on that origin
        focused = supervisor.focus_page(origin)
    except Exception:  # health: allow BLE001 -- as above
        return False
    return bool(isinstance(focused, dict) and focused.get("ok"))


def _is_sign_in_page(task_id: str) -> Optional[bool]:
    """True or False when the page can be read; None when it cannot (then nothing is refused)."""
    try:
        res = _eval_js(task_id, _SIGN_IN_PROBE)
    except Exception:  # health: allow BLE001 -- an unreadable page is not refused here
        return None
    if not (isinstance(res, dict) and res.get("success")):
        return None
    value = _parse_json_result(res.get("result"))
    return bool(value) and value not in ("false", "0", "null")


def _login_tab_origin(task_id: str, site: str = "") -> "str | dict":
    """The origin save_login binds, with the supervisor on that tab; else the refusal dict.

    With ``site``: the open tab on that origin (a tab with a password field first). Without it: the
    tab the agent works in (``_focus_task_tab``); only when that is unknown, the first tab with a
    password field, as before. Either way, a page with no password field and no login form is
    refused, so a login is never bound to an unrelated tab (live 2026-10-29: a Zillow login was
    bound to the Follow Up Boss tab in front)."""
    from agent.vault_store import VaultError
    try:
        wanted = _site_origin(site)
    except VaultError as exc:
        return {"success": False, "error_type": "bad_site", "error": f"site={site!r} is not a host or URL ({exc})."}
    if wanted:
        if not _focus_bound_origin(task_id, wanted, "login"):
            _focus_bound_origin(task_id, wanted, "signin")
        origin = _current_page_origin(task_id)
        if origin != wanted:
            host = _site_of(wanted)
            return {"success": False, "error_type": "site_not_open", "page_origin": origin, "error": (
                f"No open tab is on {host}. Open its sign-in page with browser_exec, then call save_login "
                f"again with site={host}. Do not ask the client yet.")}
    else:
        if not _focus_task_tab(task_id):
            # The tab of the agent is unknown: the tab with a password field, as before.
            _focus_bound_origin(task_id, "", "login")
        origin = _current_page_origin(task_id)
        if not origin:
            return {"success": False,
                    "error": "Open the site's login page first; the login is saved for that page's origin."}
    if _is_sign_in_page(task_id) is False:
        return {"success": False, "error_type": "not_a_sign_in_page", "page_origin": origin, "error": (
            f"Refused: this page is not a sign-in page ({_site_of(origin)}): it has no password field and no "
            "login form. Bring the service's sign-in tab to the front with browser_exec, or pass site=<its "
            "host>, then call save_login again. Do not ask the client yet.")}
    return origin


def browser_vault_add_origin(handle: str = "", site: str = "", task_id: Optional[str] = None) -> str:
    """Bind one more origin to a saved login, so the bot can fix a wrong or missing binding itself
    (a service that signs in on another host, or lives on two hosts) without asking the client again.
    Refused unless an open tab is on ``site``: the page shows the host."""
    from agent.vault_backends import backend_for_handle
    from agent.vault_store import VaultError, get_vault_store
    effective_task_id = task_id or "default"
    backend = backend_for_handle(handle)
    meta = backend.get_meta(handle) if backend is not None else None
    if meta is None:
        return json.dumps({"success": False, "error": f"No vault item with handle {handle!r}. Use browser_vault action=list."})
    if backend.name != "local" or meta.kind != "login":
        return json.dumps({"success": False, "error_type": "add_origin_unsupported", "error": (
            "add_origin works only for logins saved here with save_login. A password manager item keeps "
            "the websites its manager stores.")})
    try:
        wanted = _site_origin(site)
    except VaultError as exc:
        return json.dumps({"success": False, "error_type": "bad_site", "error": f"site={site!r} is not a host or URL ({exc})."})
    if not wanted:
        return json.dumps({"success": False, "error_type": "site_required",
                           "error": "Pass site=<host> of the page this login is for, e.g. site=login.zillowpro.com."})
    _focus_bound_origin(effective_task_id, wanted, "")
    page_origin = _current_page_origin(effective_task_id)
    if page_origin != wanted:
        shown = _site_of(page_origin) if page_origin else "no site"
        return json.dumps({"success": False, "error_type": "site_not_open", "page_origin": page_origin, "error": (
            f"Refused: the page is on {shown}, not on {_site_of(wanted)}. Open {_site_of(wanted)} with "
            "browser_exec, then call add_origin again.")})
    try:
        updated = get_vault_store().add_origin(handle, wanted)
    except VaultError as exc:
        return json.dumps({"success": False, "error_type": "add_origin_failed", "error": str(exc)[:200]})
    return json.dumps({"success": True, "handle": handle, "origins": saved_origins(updated),
                       "next": "Call browser_vault action=fill with this handle on that page."}, ensure_ascii=False)


def _password_rejected_hint(origin: str) -> str:
    """What the bot does when the site refuses the password, in words it can pass to the client."""
    host = str(origin or "").split("://", 1)[-1] or "the site"
    return (f"After you submit, call browser_vault action=check. If it says credential_rejected, or the page "
            f"shows an error such as a wrong password, THE PASSWORD DID NOT WORK on {host}. Tell the client "
            "which thing did not work, in plain words (check gives the line). Then call save_login again. "
            "Never re-ask silently. Never repeat the password.")


def _accepts_kw(fn: Any, name: str) -> bool:
    """True when ``fn`` takes the keyword ``name`` (or any keyword)."""
    import inspect
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _notice_kw(prompt: Any, notice: str) -> dict:
    """``{"notice": ...}`` for a prompt that can show the "that did not work" line, else ``{}``."""
    return {"notice": notice} if notice and _accepts_kw(prompt, "notice") else {}


def _known_identifier_kw(prompt: Any, identifier: str, task_id: str, origin: str) -> dict:
    """``{"identifier": ...}`` when the agent already knows the email or username and the surface's
    prompt can take it, so only the password (and any extra field) is asked. Empty when the site
    refused that identifier last time: then the client is asked for it again."""
    known = str(identifier or "").strip()
    if not known or not _accepts_kw(prompt, "identifier"):
        return {}
    from agent.vault_outcome import TRACKER
    pending = TRACKER.pending(task_id, origin, ["identifier"])
    if pending is not None and pending.get("field") == "identifier":
        return {}
    return {"identifier": known}


def _retry_gate(task_id: str, origin: str, fields: list, site: str) -> "str | dict":
    """Before a card asks again: the refusal dict when the field hit the retry cap (or the site locked
    the sign-in or wants a device check), else the plain line the card starts with ("" = none)."""
    from agent.vault_outcome import TRACKER, blocked_result, retry_line
    pending = TRACKER.pending(task_id, origin, fields)
    if pending is None:
        return ""
    if pending["blocked"]:
        return blocked_result(pending, site)
    return retry_line(pending["field"], pending["reason"], site)


def _check_settle_s() -> float:
    """Seconds the outcome check waits for the page to settle (``browser.vault_check_settle``)."""
    try:
        from tools.browser_session_cloud import browser_cfg
        value = float(browser_cfg("vault_check_settle", 6.0, float))
    except Exception:  # health: allow BLE001 -- a config read failure keeps the default wait
        return 6.0
    return max(0.0, min(value, 20.0)) if value == value else 6.0


def _page_verdict(task_id: str, filled: list, settle: float) -> Optional[dict]:
    """Read the page (no values) until it shows an outcome or ``settle`` seconds pass. None when the
    page cannot be read. An ``unknown`` verdict means the same form is still there with no error."""
    from agent.vault_outcome import build_snapshot_js, classify_outcome
    deadline = time.monotonic() + max(0.0, settle)
    while True:
        res = _eval_js(task_id, build_snapshot_js())
        snap = _parse_json_result(res.get("result")) if isinstance(res, dict) and res.get("success") else None
        if isinstance(snap, str):
            snap = _parse_json_result(snap)
        verdict = classify_outcome(snap, filled)
        if verdict is None or verdict["outcome"] != "unknown" or time.monotonic() >= deadline:
            return verdict
        time.sleep(0.5)


def _site_of(origin: str) -> str:
    return str(origin or "").split("://", 1)[-1] or "the site"


@plugin_errors_as_refusal
def browser_vault_check(task_id: Optional[str] = None, label: str = "") -> str:
    """After a submit: did the site accept what the vault typed last (password, extras, code)?

    One result shape for every secret, never with a value: ``{"success": true, "outcome":
    "accepted"}``, or ``{"success": false, "error_type": "credential_rejected", "field", "reason",
    "message", "retries_left", "tell_client", "next"}``. The rejection is kept for the next card."""
    from agent.vault_outcome import TRACKER, rejected_result

    effective_task_id = task_id or "default"
    origin, filled = TRACKER.last_filled(effective_task_id)
    origin = origin or _current_page_origin(effective_task_id) or ""
    verdict = _page_verdict(effective_task_id, filled, _check_settle_s())
    if verdict is None:
        return json.dumps({"success": False, "error_type": "page_unreadable",
                           "error": "Could not read the page. Look at it with the browser tools."})
    if verdict["outcome"] == "unknown":
        # The same form is still there with no error: the page may still be loading (a slow SSO
        # hop). That is not a rejection, and it does not use up a retry.
        return json.dumps({"success": True, "outcome": "pending", "origin": origin,
                           "next": ("The page has not moved on yet. Wait a few seconds, then call browser_vault "
                                    "action=check again. Do not ask the client again yet.")})
    record = TRACKER.record(effective_task_id, origin, verdict)
    if verdict["outcome"] == "accepted":
        TRACKER.take_saved(effective_task_id, origin)
        return json.dumps({"success": True, "outcome": "accepted", "origin": origin,
                           "next": "The site took it. Carry on, and prove it works on a page that shows data."})
    out = rejected_result(verdict, record, label.strip() or _site_of(origin))
    if verdict.get("reason") == "wrong" and verdict.get("field") not in ("code", "check"):
        # The login save_login stored in this task did not work: remove it, so a later session
        # does not pick the wrong one. The retry saves the corrected login.
        handle = TRACKER.take_saved(effective_task_id, origin)
        if handle:
            try:
                from agent.vault_store import get_vault_store
                out["rejected_login_removed"] = bool(get_vault_store().remove_item(handle))
            except Exception:  # health: allow BLE001 -- a failed cleanup must not hide the rejection
                logger.debug("Could not remove the rejected login", exc_info=True)
                out["rejected_login_removed"] = False
    return json.dumps(out, ensure_ascii=False)


def _extra_labels(extra_fields: Any, pasted_extra: dict) -> list[str] | str:
    """The extra secret field labels for save_login, or an error string."""
    from agent.vault_store import MAX_EXTRA_FIELDS, VaultError, normalize_extra_fields

    raw = extra_fields if isinstance(extra_fields, (list, tuple)) else ([extra_fields] if extra_fields else [])
    labels = [" ".join(str(x or "").split()) for x in raw]
    labels = [lb for lb in labels if lb]
    for lb in pasted_extra:
        lb = " ".join(str(lb or "").split())
        if lb and lb.lower() not in [x.lower() for x in labels]:
            labels.append(lb)
    if not labels:
        return []
    try:
        if len({lb.lower() for lb in labels}) != len(labels):
            raise VaultError("extra field labels must be different")
        normalize_extra_fields({lb: "x" for lb in labels})
    except VaultError as exc:
        return f"{exc}. Use at most {MAX_EXTRA_FIELDS} short labels, as the page shows them (for example PIN)."
    return labels


def _accepts_extra_fields(prompt: Any) -> bool:
    """True when the surface's save-login prompt can ask for extra fields."""
    import inspect
    try:
        params = inspect.signature(prompt).parameters
    except (TypeError, ValueError):
        return False
    return "extra_fields" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _page_title(task_id: str) -> str:
    """The current page title, short, or "" (a read-only probe; never fails the caller)."""
    try:
        res = _eval_js(task_id, "document.title")
    except Exception:  # health: allow BLE001 -- the title only names the site on a card
        return ""
    title = res.get("result") if isinstance(res, dict) and res.get("success") else ""
    title = " ".join(str(title or "").split())
    return title[:60] if title and not title.lower().startswith(("http://", "https://")) else ""


def _scrub_pasted_message(values: tuple = ()) -> bool:
    """Ask the surface to delete the user's message that carried the pasted login (best effort).

    ``values`` are the pasted secrets. A surface that takes them deletes the turn's message only when
    that message holds one of them, so "True" means the password is really gone from the chat."""
    from agent.vault_backends.unlock import get_pasted_secret_scrub_callback
    scrub = get_pasted_secret_scrub_callback()
    if scrub is None:
        return False
    try:
        return bool(scrub(values) if values and _accepts_kw(scrub, "values") else scrub())
    except Exception:  # health: allow BLE001 -- the login is saved; a failed delete only keeps the message
        logger.debug("pasted-login message scrub failed", exc_info=True)
        return False


_TAB_PROBES["otp"] = ("!!document.querySelector('input[autocomplete=one-time-code], input[name*=otp i], input[name*=code i], "
                      "input[id*=otp i], input[id*=code i], input[name*=totp i], input[aria-label*=code i]')")


def _saved_login(handle: str) -> tuple[Any, Any]:
    """(backend, meta) for a vault handle, or (None, None) when nothing is saved under it (or its manager is
    locked): enter_code then asks the user instead of minting a code."""
    from agent.vault_backends import UnlockRequired, backend_for_handle

    backend = backend_for_handle(handle) if handle else None
    if backend is None:
        return None, None
    try:
        return backend, backend.get_meta(handle)
    except UnlockRequired:
        return backend, None


@plugin_errors_as_refusal
def browser_vault_enter_code(handle: str = "", task_id: Optional[str] = None) -> str:
    """Second factor: fill the one-time code the CURRENT page asks for. If the saved login (``handle``) has an
    authenticator seed, the code is minted server-side and nobody is asked; otherwise the user is prompted on
    their surface for the code their phone/email/app shows. The code goes into the page over the supervisor
    socket and never enters the conversation. A saved login's code is only minted on its saved origin(s)."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_backends.unlock import can_prompt_here, get_code_prompt_callback
    from agent.vault_login_classifier import LoginControl, build_fill_js, build_inspection_js, build_otp_fills, classify_otp_controls

    effective_task_id = task_id or "default"
    backend, meta = _saved_login(handle)
    if meta is not None:
        bound = _bound_page_origin(effective_task_id, meta, "otp")
        if isinstance(bound, dict):
            if bound.get("error_type") == "origin_mismatch":
                bound["next"] = ("If this page asks for the code of a different account, call enter_code without a "
                                 "handle so the user is asked.")
            return json.dumps(bound)
        origin = bound
    else:
        _focus_bound_origin(effective_task_id, "", "otp")
        origin = _current_page_origin(effective_task_id)
        if not origin:
            return json.dumps({"success": False, "error": "No page with a code field is open."})
    site = origin.split("://", 1)[-1]
    shown = (getattr(meta, "label", "") or "").strip() or site
    gate = _retry_gate(effective_task_id, origin, ["code"], shown)
    if isinstance(gate, dict):
        return json.dumps(gate, ensure_ascii=False)

    nonce = secrets.token_hex(8)
    inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
    raw_controls = _parse_json_result(inspect.get("result")) if inspect.get("success") else None
    if isinstance(raw_controls, str):
        raw_controls = _parse_json_result(raw_controls)
    otp_controls = classify_otp_controls([LoginControl.from_dict(r) for r in (raw_controls or []) if isinstance(r, dict)])
    if not otp_controls:
        return json.dumps({"success": False, "error_type": "no_code_field",
                           "error": ("No one-time-code field on the current page. If the site wants a passkey, hardware key or "
                                     "an approval tap in an app, tell the user to complete it on their device and wait for the page to move on.")})

    def write(code: str, source: str) -> str:
        register_vault_redaction_value(code)
        fills = build_otp_fills(otp_controls, code)
        result = _eval_js_secret(effective_task_id, build_fill_js(fills, expected_origin=origin, nonce=nonce))
        del code
        if not result.get("success"):
            return json.dumps({"success": False, "error": str(result.get("error") or "fill failed")[:200]})
        parsed = _parse_json_result(result.get("result"))
        if isinstance(parsed, str):
            parsed = _parse_json_result(parsed)
        if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
            return json.dumps({"success": False, "error_type": "origin_changed", "error": "The page navigated before the code could be entered. Nothing was written."})
        filled = int(parsed.get("filled", 0)) if isinstance(parsed, dict) else 0
        out = {"success": bool(filled), "filled_fields": filled, "origin": origin, "source": source,
               "next": "Submit the form (many sites auto-submit when the last digit lands), then call "
                       "browser_vault action=check."}
        if filled:
            out.update(_after_code(origin))
        return json.dumps(out, ensure_ascii=False)

    def _after_code(origin: str) -> dict:
        """Many sites submit the code by themselves: look once the page settles. A rejection replaces
        the result; a page that did not move on yet leaves the check to the model."""
        from agent.vault_outcome import TRACKER, rejected_result
        TRACKER.note_filled(effective_task_id, origin, ["code"])
        verdict = _page_verdict(effective_task_id, ["code"], _check_settle_s())
        if verdict is None:
            return {}
        if verdict["outcome"] == "unknown":
            return {"outcome": "pending"}
        record = TRACKER.record(effective_task_id, origin, verdict)
        if verdict["outcome"] == "accepted":
            return {"outcome": "accepted", "next": "The site took the code. Carry on."}
        return rejected_result(verdict, record, shown)

    if meta is not None:  # a saved login on its bound origin: mint + write inside the backend's fill_context
        written = write_backend_code(backend, handle, meta, origin, lambda code: write(code, backend.name))
        if written is not None:
            return written
    prompt = get_code_prompt_callback()
    if prompt is None or not can_prompt_here():
        return json.dumps({"success": False, "error_type": "prompt_unavailable",
                           "error": (f"{site} asks for a one-time code and this session cannot ask the user (headless/cron/API). "
                                     "Save an authenticator key for this login so codes can be generated automatically.")})
    code = (prompt(site, "", **_notice_kw(prompt, gate)) or "").strip().replace(" ", "").replace("-", "")
    if not code and _cancelled_by_message():
        return _cancelled_by_message_result(site)
    if not code:
        return json.dumps({"success": False, "error_type": "code_declined",
                           "error": "The user did not enter a code. Do not ask again this turn."})
    return write(code, "user")


def _cancelled_by_message() -> bool:
    try:
        from tools.clarify_gateway import pop_cancelled_by_message
    except Exception:
        return False
    return pop_cancelled_by_message()


def _cancelled_by_message_result(site: str) -> str:
    """The client sent another message while the card waited. No value is in this result."""
    return json.dumps({"success": False, "error_type": "prompt_cancelled_by_client_message", "error": (
        "The client sent a different message while the login card was open, so the card was closed. "
        "Their message comes to you next as a normal message. Answer it first. Then offer the login again "
        f"once, in one short line (for example: \"Whenever you're ready, I still need your {site} login. "
        "Here's the button.\") and call the same action again. The browser tab is unchanged, so carry on "
        "from where it stopped. Do not offer it more than once unless the client asks.")})


@plugin_errors_as_refusal
def browser_vault_fill(handle: str, task_id: Optional[str] = None) -> str:
    """Fill the current page's password field from a vault handle.

    Password-only: the identifier is agent-visible metadata (see
    browser_vault_list) and is typed by the agent via normal input tools.
    The password is resolved server-side and injected via in-page JS over
    the supervisor CDP WebSocket; the result reports only counts/metadata.
    """
    from agent.vault_backends import UnlockRequired, backend_for_handle

    effective_task_id = task_id or "default"
    backend = backend_for_handle(handle)
    if backend is not None and backend.needs_unlock and not backend.is_unlocked():
        unlocked = json.loads(browser_vault_unlock(backend.name))
        if not unlocked.get("success"):
            return json.dumps(unlocked)

    try:
        meta = backend.get_meta(handle) if backend is not None else None
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault action=unlock."})
    if meta is None:
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"No vault item with handle {handle!r}. Use browser_vault action=list. "
                    "To save a credential: run `hermes vault add` in a terminal, or "
                    "in the desktop app open Settings → Credential Vault."
                ),
            }
        )
    # Origin binding pre-check (the authoritative re-check runs inside the fill script), before the user is
    # asked to confirm a card, before the backend's fill_context is entered and before any value is resolved.
    page_origin = _bound_page_origin(effective_task_id, meta, meta.kind)
    if isinstance(page_origin, dict):
        return json.dumps(page_origin)
    if meta.kind == "payment" and not _confirm_payment_fill(meta.label, page_origin):
        return json.dumps({"success": False, "error_type": "payment_declined",
                           "error": "The user did not confirm filling this payment card. Do not retry; ask them instead."})

    with backend.fill_context():
        refusal = snapshot_refusal(backend, handle, meta, page_origin)
        if refusal is not None:
            return json.dumps(refusal)
        return _fill_bound_page(backend, handle, meta, page_origin, effective_task_id)


def _fill_bound_page(backend: Any, handle: str, meta: Any, page_origin: str, effective_task_id: str) -> str:
    """Inspect the page, resolve the item's secret and write it; runs inside the backend's fill_context
    after the origin guard passed."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import (
        ClassifiedLoginControl,
        LoginControl,
        build_fill_js,
        build_inspection_js,
        classify_checkout_control,
        classify_login_control,
        select_checkout_fills,
        select_extra_fills,
        select_password_fill,
    )
    from agent.vault_backends import UnlockRequired
    from agent.vault_store import ADDRESS_FIELDS, PAYMENT_FIELDS, scrub_secret_from_text

    # ── Inspect + classify page controls ────────────────────────────────────
    nonce = secrets.token_hex(8)  # binds this fill to THIS inspection's stamps
    inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
    if not inspect.get("success"):
        return json.dumps(
            {"success": False, "error": f"Could not inspect page inputs: {inspect.get('error', 'eval failed')}"}
        )
    raw_controls = _parse_json_result(inspect.get("result"))
    if isinstance(raw_controls, str):
        raw_controls = _parse_json_result(raw_controls)
    if not isinstance(raw_controls, list):
        return json.dumps({"success": False, "error": "Page input inspection returned no usable controls."})

    classify = classify_login_control if meta.kind == "login" else classify_checkout_control
    classified: list[ClassifiedLoginControl] = []
    for raw in raw_controls:
        if not isinstance(raw, dict):
            continue
        result = classify(LoginControl.from_dict(raw))
        if result is not None:
            classified.append(result)
    if not classified and not (meta.kind == "login" and getattr(meta, "extra_labels", ())):
        return json.dumps({"success": False, "error": f"No {meta.kind} form fields were found on the current page."})

    # ── Resolve secret and fill (secret never enters any logged string) ─────
    try:
        extra_unmatched: list[str] = []
        if meta.kind == "login":
            secret = {"password": backend.resolve_password(handle)}
            fills = select_password_fill(classified, secret["password"])
            extras = backend.resolve_extra(handle) if getattr(meta, "extra_labels", ()) else {}
            if extras:
                secret["extra"] = extras
                controls = [LoginControl.from_dict(r) for r in raw_controls if isinstance(r, dict)]
                extra_fills, extra_unmatched = select_extra_fills(controls, extras, {f["index"] for f in fills})
                fills = fills + extra_fills
        else:
            secret = backend.resolve_secret(handle)
            fills = select_checkout_fills(classified, secret, PAYMENT_FIELDS if meta.kind == "payment" else ADDRESS_FIELDS)
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault action=unlock."})
    if not fills:
        return json.dumps(
            {"success": False, "error": f"No fillable {meta.kind} field matched the saved item on this page."}
        )

    # Register the secret bytes with the model-egress redaction boundary
    # BEFORE they touch the page: any later browser_* result (including
    # browser_cdp Runtime.evaluate reads) that echoes them is scrubbed.
    # Address values are not secrets but the card fields are: register every payment value.
    for value in (secret.values() if meta.kind == "payment" else [secret.get("password", "")]):
        register_vault_redaction_value(value)
    for value in (secret.get("extra") or {}).values():
        register_vault_redaction_value(value)

    try:
        fill_result = _eval_js_secret(
            effective_task_id, build_fill_js(fills, expected_origin=page_origin, nonce=nonce)
        )
    except Exception as exc:  # health: allow BLE001 -- any CDP failure becomes a typed result; its text is scrubbed of the secret
        return json.dumps(
            {"success": False, "error": scrub_secret_from_text(str(exc), secret)}
        )
    if not fill_result.get("success"):
        err = scrub_secret_from_text(str(fill_result.get("error") or "fill failed"), secret)
        out = {"success": False, "error": err}
        if fill_result.get("error_type"):
            out["error_type"] = fill_result["error_type"]
        return json.dumps(out)

    parsed = _parse_json_result(fill_result.get("result"))
    if isinstance(parsed, str):
        parsed = _parse_json_result(parsed)
    if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
        return json.dumps(
            {
                "success": False,
                "error_type": "origin_changed",
                "error": (
                    "Refused: the page navigated away from the bound origin "
                    f"({page_origin}) before the fill could run "
                    f"(now on {parsed.get('found') or 'unknown'}). "
                    "Nothing was written."
                ),
            }
        )
    filled = parsed.get("filled", 0) if isinstance(parsed, dict) else 0

    out = {"success": bool(filled), "filled_fields": int(filled), "backend": backend.name,
           "kind": meta.kind, "origin": page_origin}
    if meta.kind == "login" and secret.get("extra"):
        out["extra_filled"] = [f["label"] for f in fills if f.get("token") == "extra"]
        if extra_unmatched:
            out["extra_unmatched"] = extra_unmatched
            out["extra_hint"] = ("No field on this page matched " + ", ".join(extra_unmatched) + ". When it shows, call "
                                 "browser_vault action=fill_field with this handle, field=<label> and ref=<CSS selector>.")
    if meta.kind == "login":
        if filled:
            from agent.vault_outcome import TRACKER
            TRACKER.note_filled(effective_task_id, page_origin,
                                ["password", *[f["label"] for f in fills if f.get("token") == "extra"]])
        out["next"] = ("Submit, then call browser_vault action=check to see if the site took it. If the site then asks "
                       "for a verification code, call browser_vault action=enter_code with this handle"
                       + (" (a code will be generated automatically)." if meta.has_otp else "."))
        out["if_rejected"] = _password_rejected_hint(page_origin)
    elif not filled:
        out["error"] = "The saved value could not be typed into this page: no matching field was found."
    if meta.kind != "login":
        out["fields"] = sorted(f["token"] for f in fills)  # which controls were targeted, never the values
    return json.dumps(out)


@plugin_errors_as_refusal
def browser_vault_fill_field(handle: str, field: str, ref: str = "", task_id: Optional[str] = None) -> str:
    """Fill ONE page control from a named secret of a saved login (an extra field such as "PIN", or
    "password"). Same path as ``fill``: exact-origin guard before and inside the write, the value
    registered for redaction first, written over the supervisor CDP socket, never returned."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_backends import UnlockRequired, backend_for_handle
    from agent.vault_login_classifier import LoginControl, build_fill_js, build_inspection_js, match_extra_field
    from agent.vault_store import scrub_secret_from_text

    effective_task_id = task_id or "default"
    want = " ".join(str(field or "").split())
    if not want:
        return json.dumps({"success": False, "error": "fill_field needs field=<label>, for example field=\"PIN\"."})
    backend = backend_for_handle(handle)
    if backend is not None and backend.needs_unlock and not backend.is_unlocked():
        unlocked = json.loads(browser_vault_unlock(backend.name))
        if not unlocked.get("success"):
            return json.dumps(unlocked)
    try:
        meta = backend.get_meta(handle) if backend is not None else None
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault action=unlock."})
    if meta is None or meta.kind != "login":
        return json.dumps({"success": False, "error": f"No saved login with handle {handle!r}. Use browser_vault action=list."})
    is_password = want.lower() == "password"
    labels = {lb.lower(): lb for lb in getattr(meta, "extra_labels", ())}
    if not is_password and not getattr(backend, "supports_extra_fields", False):
        return json.dumps({"success": False, "error_type": "extra_fields_unsupported", "error": (
            f"{backend.display_name} logins have no extra fields here. Ask the client for that field with "
            "save_login on the local vault, or let them type it on the takeover page.")})
    if not is_password and want.lower() not in labels:
        return json.dumps({"success": False, "error_type": "unknown_field", "error": (
            f"This login has no field {want!r}. Its fields: " + ", ".join(["password", *labels.values()]) + ".")})
    page_origin = _bound_page_origin(effective_task_id, meta, "login")
    if isinstance(page_origin, dict):
        return json.dumps(page_origin)

    with backend.fill_context():
        refusal = snapshot_refusal(backend, handle, meta, page_origin)
        if refusal is not None:
            return json.dumps(refusal)
        nonce = secrets.token_hex(8)
        inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
        raw = _parse_json_result(inspect.get("result")) if inspect.get("success") else None
        if isinstance(raw, str):
            raw = _parse_json_result(raw)
        if not isinstance(raw, list):
            return json.dumps({"success": False, "error": "Could not inspect the page's input fields."})
        controls = [LoginControl.from_dict(r) for r in raw if isinstance(r, dict)]
        target: Optional[int] = None
        if ref:
            probe = _eval_js(effective_task_id, (
                "(() => { let el = null; try { el = document.querySelector(" + json.dumps(ref) + "); } catch (e) { return 'bad'; }"
                " const s = el && el.getAttribute('data-hermes-vault-slot'); if (!s) return 'none';"
                " const [n, i] = s.split(':'); return n === " + json.dumps(nonce) + " ? i : 'none'; })()"))
            found = str(probe.get("result") or "") if probe.get("success") else ""
            if found.isdigit() and any(c.index == int(found) for c in controls):
                target = int(found)
            else:
                return json.dumps({"success": False, "error_type": "field_not_found", "error": (
                    f"ref {ref!r} does not point at a visible text field. Pass a CSS selector such as "
                    "#pin or input[name=pin], or omit ref to match the field by its label.")})
        else:
            scored = sorted(((match_extra_field(want, c), c.index) for c in controls), key=lambda s: (-s[0], s[1]))
            if is_password:
                scored = [(90, c.index) for c in controls if c.type == "password"][:1]
            if scored and scored[0][0] > 0:
                target = scored[0][1]
        if target is None:
            return json.dumps({"success": False, "error_type": "field_not_found", "error": (
                f"No field labelled like {want!r} is on this page. Pass ref=<CSS selector> for the field.")})
        try:
            value = backend.resolve_password(handle) if is_password else backend.resolve_extra(handle).get(labels[want.lower()], "")
        except UnlockRequired:
            return json.dumps({"success": False, "error_type": "unlock_required",
                               "error": f"{backend.display_name} locked again; call browser_vault action=unlock."})
        if not value:
            return json.dumps({"success": False, "error": f"The saved login has no value for {want!r}."})
        register_vault_redaction_value(value)
        secret = {"value": value}
        try:
            result = _eval_js_secret(effective_task_id, build_fill_js(
                [{"index": target, "token": "extra", "value": value}], expected_origin=page_origin, nonce=nonce))
        except Exception as exc:  # health: allow BLE001 -- a CDP failure becomes a typed result, scrubbed of the value
            return json.dumps({"success": False, "error": scrub_secret_from_text(str(exc), secret)})
        finally:
            value = ""
        if not result.get("success"):
            return json.dumps({"success": False, "error": scrub_secret_from_text(str(result.get("error") or "fill failed"), secret)})
        parsed = _parse_json_result(result.get("result"))
        if isinstance(parsed, str):
            parsed = _parse_json_result(parsed)
        if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
            return json.dumps({"success": False, "error_type": "origin_changed", "error": (
                f"Refused: the page left {page_origin} before the fill ran. Nothing was written.")})
        filled = int(parsed.get("filled", 0)) if isinstance(parsed, dict) else 0
        if filled:
            from agent.vault_outcome import TRACKER
            TRACKER.note_filled(effective_task_id, page_origin, [labels.get(want.lower(), "password")])
        return json.dumps({"success": bool(filled), "field": labels.get(want.lower(), "password"),
                           "filled_fields": filled, "origin": page_origin, "backend": backend.name})


def _confirm_payment_fill(label: str, origin: str) -> bool:
    """Human confirmation before a card is written into a page: a prompt injection that reaches a checkout
    must not be able to spend. Routes through the approval surface of the active session (gateway button
    round-trip or CLI panel); headless sessions cannot confirm and the fill is refused."""
    from tools.approval_prompt import request_elicitation_consent

    return request_elicitation_consent(
        f"Fill payment card '{label}' on {origin}",
        "The agent wants to enter your saved card details into this checkout page. The card number and "
        "CVC never enter the conversation. Approve only if you intend to pay here.",
        surface="vault-payment", title="Confirm payment card fill?") == "accept"


# ---------------------------------------------------------------------------
# Schemas + registration
# ---------------------------------------------------------------------------

BROWSER_VAULT_SCHEMA = {
    "name": "browser_vault",
    "description": (
        "Fill saved logins, 2FA codes, cards and addresses on the CURRENT browser page. Saved secrets never "
        "enter the conversation. "
        "Actions: list (call first: saved logins/cards/addresses as handles; logins carry the identifier you type "
        "yourself with the browser's input tool; locked password managers appear under `locked`); fill (handle: "
        "the password for a login, card fields after the user confirms, address fields; refused unless the page "
        "origin matches the item); save_login (nothing saved for this site: the client enters it in a login prompt, "
        "Hermes saves and fills it. If you already know the username, pass identifier= and only the password is "
        "asked. Before save_login, bring the service's sign-in tab to the front, or pass site=<its host>; the "
        "login is bound to that tab's site. Fallback: if the client already pasted the login in chat, pass identifier and "
        "password and it is saved the same way; when the form also asks for another secret such as a PIN or a "
        "security answer, pass its page label in extra_fields and the client is asked for it too); fill_field "
        "(handle, field, optional ref: type one named secret of a saved login, e.g. field=PIN, into one page "
        "field; fill already types extras whose label matches a field); enter_code (a one-time/2FA code after the password: generated from a saved "
        "authenticator key or asked of the user; no_code_field means approve on their device); unlock (backend: "
        "ask the user to unlock 1Password/Bitwarden); check (after EVERY submit of a form the vault filled: did the "
        "site take it? enter_code checks by itself); add_origin (handle, site: also bind a saved login to this "
        "site, for a service that signs in on another host; the page must be on that site). If fill says "
        "origin_mismatch and it is the right login, call add_origin; do not ask the client again. "
        "On credential_rejected, tell the client in plain words WHICH "
        "thing did not work (use tell_client), then ask again for just that thing (save_login for a password, "
        "email or extra field, enter_code for a code); the next card says it too. Never re-ask silently. On "
        "retry_limit, account_locked, device_check or retries_left=0, stop and send the takeover link. "
        "Prefer the login prompt over asking in chat. If the client "
        "already pasted a login, save it with save_login and use it; do not refuse. Never repeat a password, card "
        "number, CVC or code back in a message. Stop on save_declined; never retry payment_declined. On "
        "prompt_cancelled_by_client_message, answer the client's message first, then offer the login once more."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["list", "fill", "fill_field", "save_login", "enter_code", "check",
                                                  "unlock", "add_origin"]},
            "handle": {"type": "string", "description": "fill / fill_field / enter_code / add_origin: a handle from list."},
            "site": {"type": "string", "description": (
                "save_login / add_origin: the host (or URL) of the sign-in page, e.g. login.zillowpro.com. "
                "save_login binds the login to it; without it, to the tab you work in.")},
            "extra_fields": {"type": "array", "items": {"type": "string"}, "description": (
                "save_login only: labels of other SECRET fields the form asks for, as the page shows them "
                "(e.g. [\"PIN\", \"Security answer\"]; at most 4). Type non-secret fields yourself.")},
            "extra": {"type": "object", "additionalProperties": {"type": "string"}, "description": (
                "save_login fallback only: {label: value} of extra secret fields the client already pasted in chat.")},
            "field": {"type": "string", "description": "fill_field only: the field label, e.g. PIN, or password."},
            "ref": {"type": "string", "description": (
                "fill_field only: CSS selector of the page field (e.g. #pin). Omit to match by label.")},
            "backend": {"type": "string", "enum": ["onepassword", "bitwarden"], "description": "unlock only."},
            "label": {"type": "string", "description": "save_login / check: short site name (default: the host)."},
            "identifier": {"type": "string", "description": (
                "save_login only: the email or username you already know (you typed it on the page, or the "
                "client said it). Alone, the client is asked only for the password. With password: the "
                "login the client already pasted in chat.")},
            "password": {"type": "string", "description": (
                "save_login fallback only: the password the client already pasted in chat. Omit both to "
                "ask the client in a prompt (preferred).")},
        },
        "required": ["action"],
    },
}


def _bot_desktop_browser_session(task_id: Optional[str]) -> bool:
    from tools.browser_session import session_for_task, shares_bot_desktop_browser
    return shares_bot_desktop_browser(session_for_task(task_id))


def _fenced_page_op(task_id: Optional[str], fn) -> str:
    """Vault operations focus, inspect and fill the page over the supervisor socket, bypassing
    browser_exec; they must honour the Bot Desktop lease like every other page access, or a human
    typing a credential on the taken-over screen could be read or written to."""
    from tools.browser_session import run_fenced, session_for_task

    res = run_fenced(session_for_task(task_id), lambda: {"raw": fn()})
    return res["raw"] if "raw" in res else json.dumps(res)


def _handle_vault(args: dict[str, Any], **kwargs) -> str:
    tid = kwargs.get("task_id")
    action = str(args.get("action") or "")
    handle, label = str(args.get("handle") or ""), str(args.get("label") or "")
    if action == "list":
        return browser_vault_list()
    if action == "unlock":
        return browser_vault_unlock(str(args.get("backend") or ""))
    page_ops = {
        "fill": lambda: browser_vault_fill(handle=handle, task_id=tid),
        "save_login": lambda: browser_vault_save_login(
            label=label, task_id=tid, identifier=str(args.get("identifier") or ""),
            password=str(args.get("password") or ""), extra_fields=args.get("extra_fields"),
            extra=args.get("extra"), site=str(args.get("site") or "")),
        "add_origin": lambda: browser_vault_add_origin(
            handle=handle, site=str(args.get("site") or ""), task_id=tid),
        "fill_field": lambda: browser_vault_fill_field(
            handle=handle, field=str(args.get("field") or ""), ref=str(args.get("ref") or ""), task_id=tid),
        "enter_code": lambda: browser_vault_enter_code(handle=handle, task_id=tid),
        "check": lambda: browser_vault_check(task_id=tid, label=label),
    }
    if action not in page_ops:
        return json.dumps({"success": False, "error": f"Unknown action {action!r}; use list, fill, fill_field, save_login, "
                                                       "enter_code, check, unlock or add_origin."})
    # The tool executor already holds the task's browser; hold it here too, so a direct caller
    # (plugin, test, other executor) never loses the login page while the user is asked.
    from tools.browser_session_holds import hold_browser_for_task
    with hold_browser_for_task(tid):
        return _fenced_page_op(tid, page_ops[action])


from tools.registry import no_cache_check_fn, registry

_check_vault_available = no_cache_check_fn(_check_vault_available)

registry.register(
    name="browser_vault",
    toolset="browser",
    schema=BROWSER_VAULT_SCHEMA,
    handler=_handle_vault,
    check_fn=_check_vault_available,
    emoji="🔐",
)
