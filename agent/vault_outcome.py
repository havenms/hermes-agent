"""Did the site accept the login? One check for every secret the vault types.

After the vault fills a credential (password, email or username, an extra field such as a PIN, a
one-time code) and the form is submitted, :func:`build_snapshot_js` reads the page without reading
any input value, and :func:`classify_outcome` decides one of:

* accepted: the field the vault filled is gone and no error shows.
* rejected: the same field came back, or an error shows near it. ``reason`` is ``wrong``,
  ``expired``, ``locked``, ``device_check`` or ``unknown``, and ``field`` names the thing that
  did not work (``password``, ``identifier``, ``code`` or an extra label such as ``PIN``).

:class:`OutcomeTracker` keeps the rejections per task and site for 15 minutes. The next card for
that field starts with a plain line ("That code didn't work..."), and the tool refuses a third
retry, a locked account and a device check: those go to the takeover link instead.

No value is ever read, kept or returned. The site's own error text is returned, trimmed.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Iterable, Optional

# At most this many retries per field. The first try plus 2 retries, then the takeover link.
MAX_RETRIES = 2
# A rejection older than this is forgotten: the client is on a new attempt.
REJECTION_TTL_S = 15 * 60

REASONS = ("wrong", "expired", "locked", "device_check", "unknown")

_LOCKED = re.compile(r"\b(?:locked|too many (?:attempts|tries|requests|failed)|temporarily (?:blocked|disabled|"
                     r"unavailable)|suspended|account (?:is )?disabled|try again (?:later|in \d+))\b", re.I)
_DEVICE = re.compile(r"\b(?:security (?:image|picture|phrase)|unrecogni[sz]ed (?:device|browser)|new device|"
                     r"verify (?:it'?s|that it'?s) you|confirm (?:it'?s|that it'?s) you|not a robot|captcha|"
                     r"unusual (?:activity|sign-in)|suspicious)\b", re.I)
_EXPIRED = re.compile(r"\b(?:expired|has expired|no longer valid|timed out|request a new (?:code|one))\b", re.I)
_WRONG = re.compile(r"(?:\b(?:not right|incorrect|invalid|wrong|not found|no account|doesn'?t match|did ?n[o']t "
                    r"match|does not match|not recogni[sz]ed|couldn'?t find|could not find|try again|isn'?t "
                    r"right|is not correct|not valid|failed)\b)", re.I)

# Page text (not an error element) counts only with these narrower phrases: a sign-in page often
# says "verify it's you, we sent a code" or "Locked out? Contact us" with nothing wrong.
_DEVICE_PAGE = re.compile(r"\b(?:security (?:image|picture|phrase)|unrecogni[sz]ed (?:device|browser)|"
                          r"not a robot|captcha)\b", re.I)
_LOCKED_PAGE = re.compile(r"\b(?:too many (?:attempts|tries|failed)|(?:has been|is|temporarily) locked|"
                          r"been suspended)\b", re.I)
_EXPIRED_PAGE = re.compile(r"\b(?:code (?:has )?expired|expired code|code is no longer valid)\b", re.I)

_FIELD_WORDS = (
    ("code", re.compile(r"\b(?:code|otp|passcode|verification|one[- ]time)\b", re.I)),
    ("password", re.compile(r"\bpass(?:word|phrase)?\b", re.I)),
    ("identifier", re.compile(r"\b(?:e-?mail|username|user name|user id|user|account|phone|login id)\b", re.I)),
)
_OTP_HINT = re.compile(r"\b(?:code|otp|passcode|verification|one[- ]time|2fa|mfa|token)\b", re.I)
_ID_HINT = re.compile(r"\b(?:e-?mail|username|user|login|phone)\b", re.I)


def build_snapshot_js() -> str:
    """A read-only page probe: visible fields (type, label, aria-invalid), visible error texts and a
    short page text. It never reads an input's value."""
    return _SNAPSHOT_JS


_SNAPSHOT_JS = r"""(() => {
  const vis = (el) => { try { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; } catch (e) { return false; } };
  const txt = (el) => String((el && (el.innerText || el.textContent)) || '').replace(/\s+/g, ' ').trim().slice(0, 240);
  const labelOf = (el) => { const parts = [el.getAttribute('aria-label'), el.getAttribute('placeholder'), el.title,
    el.labels && el.labels[0] ? txt(el.labels[0]) : '', el.name, el.id];
    return parts.filter(Boolean).join(' ').slice(0, 120); };
  const fields = []; const errors = [];
  for (const el of document.querySelectorAll('input, select, textarea')) {
    const type = String(el.type || '').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'image', 'reset'].includes(type) || !vis(el)) continue;
    const invalid = el.getAttribute('aria-invalid') === 'true';
    fields.push({type, label: labelOf(el), autocomplete: String(el.autocomplete || '').toLowerCase(), invalid});
    if (invalid) { for (const id of String(el.getAttribute('aria-describedby') || el.getAttribute('aria-errormessage') || '').split(/\s+/)) {
      const d = id && document.getElementById(id); const t = d && txt(d); if (t && !errors.includes(t)) errors.push(t); } }
    if (fields.length >= 30) break;
  }
  const sel = '[role=alert], [aria-live=assertive], .error, .errors, .alert-danger, .alert-error, .invalid-feedback, '
    + '[class*=error i], [class*=invalid i], [id*=error i], [data-error]';
  for (const el of document.querySelectorAll(sel)) {
    if (errors.length >= 8) break;
    if (el.matches('input, select, textarea') || !vis(el)) continue;
    const t = txt(el); if (t && t.length >= 4 && !errors.includes(t)) errors.push(t);
  }
  const text = document.body ? String(document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 3000) : '';
  return JSON.stringify({hermes_outcome: 1, url: String(location.href || ''), fields, errors, text});
})()"""


def _words(text: str) -> set[str]:
    from agent.vault_login_classifier import _words as words
    return set(words(text))


def _is_otp(field: dict) -> bool:
    return field.get("autocomplete") == "one-time-code" or bool(_OTP_HINT.search(str(field.get("label") or "")))


def _is_identifier(field: dict) -> bool:
    return (field.get("type") in ("email", "tel") or field.get("autocomplete") in ("username", "email", "tel")
            or bool(_ID_HINT.search(str(field.get("label") or ""))))


def _matches_label(label: str, field: dict) -> bool:
    want = _words(label) - {"your", "the", "a", "enter"}
    return bool(want) and want <= _words(str(field.get("label") or ""))


def _field_present(name: str, fields: list[dict]) -> bool:
    if name == "password":
        return any(f.get("type") == "password" and not _is_otp(f) for f in fields)
    if name == "code":
        return any(_is_otp(f) for f in fields)
    if name == "identifier":
        return any(_is_identifier(f) and f.get("type") != "password" for f in fields)
    return any(_matches_label(name, f) for f in fields)


def _field_of(f: dict, filled: list[str]) -> Optional[str]:
    for name in filled:
        if name not in ("password", "code", "identifier") and _matches_label(name, f):
            return name
    if _is_otp(f):
        return "code"
    if f.get("type") == "password":
        return "password"
    if _is_identifier(f):
        return "identifier"
    return None


def _field_from_text(text: str, filled: list[str]) -> Optional[str]:
    for name in filled:  # an extra label named in the message ("That PIN is not right")
        if name not in ("password", "code", "identifier") and _words(name) and _words(name) <= _words(text):
            return name
    for name, pattern in _FIELD_WORDS:
        if pattern.search(text):
            return name
    return None

def _trim(text: str, limit: int = 160) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def classify_outcome(snapshot: Any, filled: Iterable[str] = ()) -> Optional[dict]:
    """``{"outcome", "field", "reason", "message"}`` for a page snapshot, or None when the snapshot
    is not one (the page could not be read). ``filled`` names what the vault typed last."""
    if not isinstance(snapshot, dict) or not snapshot.get("hermes_outcome"):
        return None
    filled = [str(x) for x in filled if str(x or "").strip()]
    fields = [f for f in snapshot.get("fields") or [] if isinstance(f, dict)]
    errors = [str(e) for e in snapshot.get("errors") or [] if str(e or "").strip()]
    text = str(snapshot.get("text") or "")
    still = [name for name in filled if _field_present(name, fields)]
    on_form = bool(still) if filled else any(f.get("type") == "password" or _is_otp(f) for f in fields)

    def first(pattern, texts):
        return next((t for t in texts if pattern.search(t)), "")

    message, reason = "", ""
    has_otp = any(_is_otp(f) for f in fields)
    if first(_DEVICE, errors) or (not has_otp and _DEVICE_PAGE.search(text)):
        message, reason = first(_DEVICE, errors) or _snippet(_DEVICE_PAGE, text), "device_check"
    elif first(_LOCKED, errors) or (on_form and _LOCKED_PAGE.search(text)):
        message, reason = first(_LOCKED, errors) or _snippet(_LOCKED_PAGE, text), "locked"
    elif first(_EXPIRED, errors) or (on_form and _EXPIRED_PAGE.search(text)):
        message, reason = first(_EXPIRED, errors) or _snippet(_EXPIRED_PAGE, text), "expired"
    elif first(_WRONG, errors):
        message, reason = first(_WRONG, errors), "wrong"
    invalid = [f for f in fields if f.get("invalid")]
    if not reason and invalid:
        message, reason = (errors[0] if errors else ""), "wrong"
    if not reason and not on_form:
        return {"outcome": "accepted"}
    if not reason:
        reason = "unknown"
    field = "check" if reason == "device_check" else None
    if field is None and message and reason != "locked":  # "your account is locked" names no field
        field = _field_from_text(message, filled)
    if field is None:
        field = next((n for n in (_field_of(f, filled) for f in invalid) if n), None)
    if field is None:
        field = (still or filled or ["password"])[-1] if (still or filled) else "password"
    outcome = {"wrong": "rejected", "device_check": "rejected"}.get(reason, reason)
    return {"outcome": outcome, "field": field, "reason": reason, "message": _trim(message)}


def _snippet(pattern, text: str) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, text.rfind(".", 0, m.start()) + 1)
    end = text.find(".", m.end())
    return text[start: end + 1 if end != -1 else m.end() + 60].strip()


def field_name(field: str) -> str:
    """The field the way the client knows it."""
    return {"password": "password", "identifier": "email or username", "code": "code"}.get(field, field)


def retry_line(field: str, reason: str, site: str) -> str:
    """The plain line the next card starts with. Never names a value."""
    if reason == "expired" and field == "code":
        return f"That code expired. {site} is sending a new one. Reply with it here."
    if reason == "unknown" or reason == "expired":
        return "That didn't go through. Let's try once more."
    if field == "code":
        return "That code didn't work. Check it, or wait for a new one, and reply here."
    return f"That {field_name(field)} didn't work. Please check it and reply again."


def stop_line(reason: str, site: str) -> str:
    """What the bot tells the client when it stops retrying (the takeover link follows)."""
    if reason == "locked":
        return (f"{site} has locked the sign-in for a short time after too many tries. We can try again later, "
                "or you can sign in yourself with a link I'll send you.")
    if reason == "device_check":
        return f"{site} wants a quick check that it's you. I'll send you a link to do it."
    return f"That still didn't work. I'll send you a link so you can sign in to {site} yourself."


TAKEOVER_NEXT = ("Stop retrying. Send the client the takeover link (skill client-login-handoff, step 7: run "
                 "takeover-link with the terminal tool) so they finish this step by hand.")


class OutcomeTracker:
    """Rejections per (task, site origin, field), kept for :data:`REJECTION_TTL_S`. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._filled: dict[str, tuple[str, list[str], float]] = {}  # task -> (origin, fields, at)
        self._rejects: dict[tuple[str, str], dict[str, dict]] = {}
        self._saved: dict[str, tuple[str, str, float]] = {}  # task -> (origin, vault handle, at)

    def _key(self, task_id: Optional[str], origin: str) -> tuple[str, str]:
        return (str(task_id or "default"), str(origin or ""))

    def note_filled(self, task_id: Optional[str], origin: str, fields: Iterable[str]) -> None:
        """Remember what the vault typed last in this task, and on which site. A site often moves to
        another origin after a good sign-in, so the check reads this, not the current page origin."""
        with self._lock:
            self._filled[str(task_id or "default")] = (str(origin or ""), [str(f) for f in fields if f],
                                                       time.monotonic())

    def note_saved(self, task_id: Optional[str], origin: str, handle: str) -> None:
        """Remember the login that save_login stored in this task, so a rejected one can be removed."""
        with self._lock:
            self._saved[str(task_id or "default")] = (str(origin or ""), str(handle or ""), time.monotonic())

    def take_saved(self, task_id: Optional[str], origin: str) -> str:
        """The handle save_login stored in this task for ``origin`` (forgotten once taken), or ""."""
        with self._lock:
            got = self._saved.get(str(task_id or "default"))
            if not got or got[0] != str(origin or "") or time.monotonic() - got[2] >= REJECTION_TTL_S:
                return ""
            self._saved.pop(str(task_id or "default"), None)
            return got[1]

    def last_filled(self, task_id: Optional[str]) -> tuple[str, list[str]]:
        """``(origin, fields)`` of the last fill in this task, or ``("", [])``."""
        with self._lock:
            got = self._filled.get(str(task_id or "default"))
            if got and time.monotonic() - got[2] < REJECTION_TTL_S:
                return got[0], list(got[1])
            return "", []

    def _live(self, key) -> dict[str, dict]:
        now = time.monotonic()
        rejects = {f: r for f, r in (self._rejects.get(key) or {}).items() if now - r["at"] < REJECTION_TTL_S}
        if rejects:
            self._rejects[key] = rejects
        else:
            self._rejects.pop(key, None)
        return rejects

    def record(self, task_id: Optional[str], origin: str, result: dict) -> dict:
        """Store a rejection; returns ``{"count", "retries_left"}``. ``accepted`` clears the site."""
        key = self._key(task_id, origin)
        with self._lock:
            if result.get("outcome") == "accepted":
                self._rejects.pop(key, None)
                return {"count": 0, "retries_left": MAX_RETRIES}
            rejects = self._live(key)
            field = str(result.get("field") or "password")
            prior = rejects.get(field, {}).get("count", 0)
            entry = {"count": prior + 1, "reason": result.get("reason") or "unknown", "at": time.monotonic()}
            self._rejects.setdefault(key, {})[field] = entry
            hard = entry["reason"] in ("locked", "device_check")
            return {"count": entry["count"], "retries_left": 0 if hard else max(0, MAX_RETRIES - prior)}

    def pending(self, task_id: Optional[str], origin: str, fields: Iterable[str]) -> Optional[dict]:
        """The live rejection among ``fields`` (or a site-wide stop), as
        ``{"field", "reason", "count", "blocked"}``; None when there is none."""
        key = self._key(task_id, origin)
        wanted = [str(f) for f in fields]
        with self._lock:
            rejects = self._live(key)
            for field, r in rejects.items():
                if r["reason"] in ("locked", "device_check"):
                    return {"field": field, "reason": r["reason"], "count": r["count"], "blocked": True}
            for field in wanted:
                r = rejects.get(field)
                if r:
                    return {"field": field, "reason": r["reason"], "count": r["count"],
                            "blocked": r["count"] > MAX_RETRIES}
        return None

    def clear(self, task_id: Optional[str] = None, origin: str = "") -> None:
        with self._lock:
            if task_id is None:
                self._filled.clear()
                self._rejects.clear()
                self._saved.clear()
                return
            self._filled.pop(str(task_id or "default"), None)
            self._saved.pop(str(task_id or "default"), None)
            self._rejects.pop(self._key(task_id, origin), None)


TRACKER = OutcomeTracker()


def rejected_result(verdict: dict, record: dict, site: str) -> dict:
    """The tool result for a rejection: no value, the site's text, and what to do next."""
    field, reason = verdict["field"], verdict["reason"]
    out = {"success": False, "error_type": "credential_rejected", "outcome": verdict["outcome"],
           "field": field, "reason": reason, "message": verdict.get("message", ""),
           "retries_left": record["retries_left"]}
    if record["retries_left"] <= 0:
        out["tell_client"] = stop_line(reason, site)
        out["next"] = TAKEOVER_NEXT
        return out
    out["tell_client"] = retry_line(field, reason, site)
    if field == "code":
        resend = (" First press the page's resend link or button so the site sends a new code."
                  if reason == "expired" else "")
        out["next"] = ("Tell the client which thing did not work (tell_client)." + resend + " Then call "
                       "browser_vault action=enter_code again. The new card starts with that line.")
    else:
        out["next"] = ("Tell the client which thing did not work (tell_client), then call browser_vault "
                       "action=save_login again with the same label and extra_fields. The new card starts "
                       "with that line.")
    return out


def blocked_result(pending: dict, site: str) -> dict:
    """The refusal when a field hit the retry cap, or the site locked the sign-in or wants a check."""
    reason = pending["reason"]
    error_type = {"locked": "account_locked", "device_check": "device_check"}.get(reason, "retry_limit")
    return {"success": False, "error_type": error_type, "field": pending["field"], "reason": reason,
            "tell_client": stop_line(reason if reason in ("locked", "device_check") else "", site),
            "next": TAKEOVER_NEXT}
