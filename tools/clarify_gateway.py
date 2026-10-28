"""Gateway-side clarify primitive (blocking event-based queue). The agent runs on a worker
thread while the event loop handles the user's reply, so a pending clarify is stored
module-level (same shape as ``tools.approval``) and the agent thread blocks on an ``Event``
until an adapter button callback or the gateway text-intercept resolves it, or the timeout
fires. Adapters render inline buttons (an "Other" row flips the entry into text-capture
mode) or a numbered-list text fallback."""

from __future__ import annotations
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class _ClarifyEntry:
    """One pending clarify request inside a gateway session."""
    clarify_id: str
    session_key: str
    question: str
    choices: Optional[list[str]]
    multi_select: bool = False
    # A prompt whose answer is a secret (vault master password, saved login,
    # one-time code). The reply is still read normally, but the adapter deletes
    # the user's own message once it has been consumed, so the secret does not
    # sit in the chat scrollback after the agent has it.
    secret: bool = False
    # The platform user id of the person the prompt asks. Set for vault prompts: in a shared
    # session (a Discord thread, or a group with ``group_sessions_per_user: false``) any member's
    # next message would otherwise answer it, so another member could supply the credential.
    # None keeps the shared behaviour for ordinary clarify questions.
    owner_user_id: Optional[str] = None
    # Regex a typed reply to an open-ended prompt must fully match to count as the answer
    # (``skip`` always counts). A vault prompt can wait for hours; without this the first
    # unrelated message after the wait would be taken as the username or the one-time code.
    answer_pattern: Optional[str] = None
    # A typed reply to a password prompt that reads like chat ("hey did that work?") is never
    # taken as the password (see :func:`looks_like_chat`). The private form path skips this.
    chat_guard: bool = False
    # What the prompt asks for (vault prompts: "save_login", "code", "unlock"); lets an adapter
    # word its private-entry hint. Empty for ordinary clarify questions.
    kind: str = ""
    # One private form that answers a whole sequence of prompts at once (the vault login: email,
    # password, extra fields). Each item: {"key", "label", "secret", "pattern"?}. The form answer
    # resolves this entry with FORM_ANSWER_PREFIX + a JSON object of key -> value. None = no form.
    form_fields: Optional[list[dict]] = None
    created_at: float = field(default_factory=time.monotonic)
    event: threading.Event = field(default_factory=threading.Event)
    response: Optional[str] = None
    awaiting_text: bool = False  # set when user picked "Other" or clarify is open-ended


_lock = threading.RLock()
_entries: dict[str, _ClarifyEntry] = {}  # clarify_id -> entry (button callbacks)
_session_index: dict[str, list[str]] = {}  # session_key -> [clarify_id] FIFO (text intercept, cleanup)
# Per-session notify callbacks (gateway -> adapter bridge); mirrors tools.approval. Tests clear it.
_notify_cbs: dict[str, Callable[[_ClarifyEntry], None]] = {}

# Outcomes for typed clarify replies. Gateway cancels the pending prompt on
# free prose (deadlock break) but keeps it armed for a retryable bad selection.
TEXT_RESOLVED = "resolved"
TEXT_REJECTED_PROSE = "rejected_prose"
TEXT_REJECTED_SELECTION = "rejected_selection"
TEXT_NO_PENDING = "no_pending"
TEXT_NOT_OWNER = "not_owner"
TEXT_NOT_AN_ANSWER = "not_an_answer"
TEXT_LOOKS_LIKE_CHAT = "looks_like_chat"  # kept for callers; the gateway now holds such a reply
# A typed reply to a password card that is not clearly a password: the gateway holds it in memory
# (see :func:`hold_reply`) and asks with two buttons whether it was the password.
TEXT_HELD = "held"
# A typed "yes" or "no" while a held reply waits for its buttons: never the password, never chat.
TEXT_HOLD_PENDING = "hold_pending"

# After this many seconds a typed password reply must be one token: a client who comes back
# hours later usually types chat first.
CHAT_GUARD_STALE_AFTER_S = 15 * 60
_CHAT_OPENERS = ("hi", "hey", "hello", "ok", "okay", "thanks", "did", "is", "are", "can", "what",
                 "why", "how", "when", "where", "any update", "still")
# One-word chat replies. Never a password, whatever the card asks.
CHAT_WORDS = frozenset({
    "yes", "yep", "yeah", "yea", "ya", "yup", "y", "no", "nope", "nah", "n", "ok", "okay", "k", "kk",
    "hi", "hey", "hello", "thanks", "thank you", "thx", "ty", "sure", "done", "wait", "sorry", "lol",
    "great", "cool", "nice", "good", "fine", "please", "help", "what", "why", "how", "hmm", "huh",
    "correct", "right", "true", "false", "agreed", "confirm", "confirmed", "sent", "there", "here",
})
_YES_NO_WORDS = frozenset({"yes", "yep", "yeah", "yea", "ya", "yup", "y", "no", "nope", "nah", "n",
                           "yes it is", "yes it was", "no it is not", "no it was not", "it was", "it is"})


def _norm_word(text: str) -> str:
    return " ".join(str(text or "").casefold().replace("\u2019", "'").split()).strip(".!?,")


def looks_like_chat(text: str, *, stale: bool = False) -> bool:
    """True when a typed reply to a password prompt reads like a chat message, not a password:
    3 or more words, a "?" in a reply with a space, a one-word chat reply, or a common opener.
    ``stale`` (the card is older than ``CHAT_GUARD_STALE_AFTER_S``) also flags any reply with
    whitespace. A single token with "?" ("Summer2024?") is a normal password."""
    stripped = str(text or "").strip()
    if not stripped:
        return False
    has_space = any(ch.isspace() for ch in stripped)
    if stale and has_space:
        return True
    lowered = stripped.casefold()
    if ("?" in stripped and has_space) or len(stripped.split()) >= 3:
        return True
    if _norm_word(stripped) in CHAT_WORDS or _norm_word(stripped) in _CHAT_OPENERS:
        return True
    return any(lowered.startswith(w + " ") or lowered.startswith(w + ",")
               or lowered.startswith(w + "!") or lowered.startswith(w + ".") for w in _CHAT_OPENERS)


_EMAIL_SHAPE = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")
_TRAILING_PUNCT = ".!?,"


def looks_like_secret(text: str) -> bool:
    """True when a typed reply to a password card is clearly a password, so the gateway may use it
    without asking. One token of 6 to 256 characters, not a chat word, not an email or a link,
    with a letter and a digit or an inner symbol ("Summer2024?", "pa$$word"). Anything else is held
    and the client confirms it with a button."""
    s = str(text or "").strip()
    if not s or any(ch.isspace() for ch in s) or not 6 <= len(s) <= 256:
        return False
    if _norm_word(s) in CHAT_WORDS or _EMAIL_SHAPE.fullmatch(s) or "://" in s or s.casefold().startswith("www."):
        return False
    core = s.rstrip(_TRAILING_PUNCT) or s
    has_letter = any(ch.isalpha() for ch in s)
    has_digit = any(ch.isdigit() for ch in s)
    inner_symbol = any(not ch.isalnum() and ch != "'" for ch in core)
    return has_letter and (has_digit or inner_symbol)


# --- Held replies -------------------------------------------------------------------------------
# A typed reply to a password card that is not clearly a password. The gateway keeps it here, in
# memory only: it is not logged, not passed to the model and not added to history. Two buttons
# decide: "Yes, that was my password" answers the card with it; "No, that was a message" releases
# it to the agent as normal chat (``release``, set by the gateway). A typed "yes" never uses it.
HELD_REPLY_MAX_AGE_S = 4 * 3600


@dataclass
class HeldReply:
    hold_id: str
    clarify_id: str
    session_key: str
    owner_user_id: Optional[str]
    text: str = field(repr=False)
    release: Optional[Callable[[], object]] = field(default=None, repr=False)
    created_at: float = field(default_factory=time.monotonic)


_held: dict[str, HeldReply] = {}
HOLD_USED = "used"
HOLD_RELEASED = "released"
HOLD_PROMPT_CLOSED = "prompt_closed"
HOLD_GONE = "gone"
HOLD_NOT_OWNER = "not_owner"


def _drop_old_holds_locked() -> None:
    now = time.monotonic()
    for hid in [h for h, r in _held.items() if now - r.created_at > HELD_REPLY_MAX_AGE_S]:
        _held.pop(hid, None)


def hold_reply(entry: "_ClarifyEntry", text: str, release: Optional[Callable[[], object]] = None) -> str:
    """Keep a typed reply to ``entry`` in memory until its buttons decide; returns the hold id."""
    import uuid
    hold_id = uuid.uuid4().hex[:16]
    with _lock:
        _drop_old_holds_locked()
        _held[hold_id] = HeldReply(hold_id, entry.clarify_id, entry.session_key, entry.owner_user_id,
                                   str(text), release)
    return hold_id


def has_open_hold(clarify_id: str) -> bool:
    with _lock:
        _drop_old_holds_locked()
        return any(r.clarify_id == clarify_id for r in _held.values())


def get_hold(hold_id: str) -> Optional[HeldReply]:
    with _lock:
        _drop_old_holds_locked()
        return _held.get(hold_id)


def answer_held_reply(hold_id: str, use: bool, responder_id: Optional[str] = None) -> tuple[str, Optional[HeldReply]]:
    """The owner's button on a held reply. ``use=True`` answers the password card with the held text
    (``HOLD_USED``, or ``HOLD_PROMPT_CLOSED`` when the card already ended: the text is dropped).
    ``use=False`` returns ``HOLD_RELEASED`` with the hold: the caller runs ``hold.release()``."""
    with _lock:
        _drop_old_holds_locked()
        held = _held.get(hold_id)
        if held is None:
            return HOLD_GONE, None
        if held.owner_user_id and str(responder_id or "") != held.owner_user_id:
            return HOLD_NOT_OWNER, None
        _held.pop(hold_id, None)
    if not use:
        return HOLD_RELEASED, held
    entry = get_pending(held.clarify_id)
    if entry is None:
        return HOLD_PROMPT_CLOSED, None
    coerced, _reason = _coerce_text_response_detailed(entry, held.text)
    ok = coerced is not None and resolve_gateway_clarify(held.clarify_id, coerced)
    return (HOLD_USED, held) if ok else (HOLD_PROMPT_CLOSED, None)


def drop_holds_for_session(session_key: str) -> int:
    with _lock:
        ids = [h for h, r in _held.items() if r.session_key == session_key]
        for h in ids:
            _held.pop(h, None)
    return len(ids)


SKIP_WORD = "skip"
# Typed words that decline a prompt bound to one user (vault prompts). The cards say "just tell
# me" instead of teaching a command; these keep working without being shown.
DECLINE_WORDS = frozenset({"skip", "cancel", "stop", "never mind", "nevermind", "forget it"})
# Typed words that say the email or username was wrong. On a vault login card they go back to the
# email or username card (``WRONG_ANSWER``); they do not decline the login.
WRONG_WORDS = frozenset({"wrong", "wrong email", "wrong username", "wrong user", "wrong login", "wrong account",
                         "that's wrong", "thats wrong", "it's wrong", "its wrong", "that is wrong",
                         "wrong email address", "that's the wrong email", "that is the wrong email",
                         "not my email", "not my username", "that's not my email", "change email",
                         "change the email", "different email", "use a different email"})


def _is_decline(entry: "_ClarifyEntry", text: str) -> bool:
    word = _norm_word(text)
    return word == SKIP_WORD or (entry.owner_user_id is not None and word in DECLINE_WORDS)


def _is_wrong(entry: "_ClarifyEntry", text: str) -> bool:
    return entry.owner_user_id is not None and _norm_word(text) in WRONG_WORDS


SKIPPED = "\x00skipped"
# The client said the email or username was wrong (``WRONG_WORDS``): the vault login goes back to it.
WRONG_ANSWER = "\x00wrong"
# Marks a response that came from one private form (see ``_ClarifyEntry.form_fields``).
FORM_ANSWER_PREFIX = "\x00form:"
CANCELLED = "\x00cancelled"


def register(clarify_id: str, session_key: str, question: str, choices: Optional[list[str]],
             multi_select: bool = False, secret: bool = False,
             owner_user_id: Optional[str] = None, answer_pattern: Optional[str] = None,
             chat_guard: bool = False, kind: str = "",
             form_fields: Optional[list[dict]] = None) -> _ClarifyEntry:
    """Register a pending clarify request; caller then blocks on ``wait_for_response``.
    Open-ended (no choices) entries start in text mode: the next message IS the response.
    ``secret`` marks an answer the adapter should delete from the chat once read.
    ``owner_user_id`` lets only that user answer (see :func:`may_answer`); ``answer_pattern`` is
    the shape a typed answer to an open-ended prompt must have."""
    entry = _ClarifyEntry(clarify_id, session_key, question, list(choices) if choices else None,
                          bool(multi_select) and bool(choices), secret=bool(secret),
                          owner_user_id=str(owner_user_id) if owner_user_id else None,
                          answer_pattern=answer_pattern or None, chat_guard=bool(chat_guard), kind=kind or "",
                          form_fields=[dict(f) for f in form_fields] if form_fields else None,
                          awaiting_text=not bool(choices))
    with _lock:
        _entries[clarify_id] = entry
        _session_index.setdefault(session_key, []).append(clarify_id)
    return entry


def wait_for_response(clarify_id: str, timeout: float) -> Optional[str]:
    """Block until the entry resolves or ``timeout`` (``<= 0`` = unlimited) elapses; None on
    timeout/unknown id. Polls in 1s slices so the inactivity heartbeat keeps firing (a
    single long ``Event.wait`` would let the gateway watchdog kill a live prompt)."""
    with _lock:
        entry = _entries.get(clarify_id)
    if entry is None:
        return None
    try:
        from tools.environments.base import touch_activity_if_due
    except Exception:  # pragma: no cover - optional
        touch_activity_if_due = None
    from tools.interrupt import is_interrupted
    deadline = None if timeout is None or float(timeout) <= 0.0 else time.monotonic() + float(timeout)
    activity_state = {"last_touch": time.monotonic(), "start": time.monotonic()}
    while True:
        remaining = 1.0 if deadline is None else deadline - time.monotonic()
        if remaining <= 0 or entry.event.wait(timeout=min(1.0, remaining)):
            break
        if is_interrupted():
            # /stop or gateway shutdown on this turn's thread: withdraw the prompt the way the
            # approval wait does, or a planned stop sits out the whole clarify timeout and the
            # turn is left started (unknown after restart). A real answer that won the race stays.
            with _lock:
                if not entry.event.is_set():
                    entry.response = CANCELLED
            break
        # Periodic activity touch so the gateway's inactivity timeout doesn't kill the agent during long
        # code execution (#10807).
        if touch_activity_if_due is not None:
            touch_activity_if_due(activity_state, "waiting for user clarify response")
    with _lock:
        _entries.pop(clarify_id, None)  # regardless of outcome
        entry.event.set()  # Timeout also retires shared projections of this waiter.
        ids = _session_index.get(entry.session_key) or []
        if clarify_id in ids:
            ids.remove(clarify_id)
            if not ids:
                _session_index.pop(entry.session_key, None)
    return entry.response


def resolve_gateway_clarify(clarify_id: str, response: str) -> bool:
    """Unblock the waiter on ``clarify_id``; False if already resolved/expired/unknown."""
    with _lock:
        entry = _entries.get(clarify_id)
        if entry is None or entry.event.is_set():
            return False
        entry.response = str(response) if response is not None else ""
        entry.event.set()
        return True


def get_pending(clarify_id: str) -> Optional[_ClarifyEntry]:
    """The entry for ``clarify_id`` while it is still awaiting an answer, else None (unknown,
    answered, timed out or cleared). Read-only: adapters rendering native choice cards compare it
    by identity with the entry they rendered and read ``session_key`` / ``choices`` /
    ``multi_select`` from it; answering goes through ``resolve_gateway_clarify``."""
    with _lock:
        entry = _entries.get(clarify_id)
        return entry if entry is not None and not entry.event.is_set() else None


def get_pending_for_session(session_key: str, *, include_choice_prompts: bool = False) -> Optional[_ClarifyEntry]:
    """Oldest pending entry awaiting free text (open-ended, or after "Other");
    ``include_choice_prompts=True`` returns the oldest unresolved entry of any kind (user
    typed at an active choice prompt: resolve it rather than queue a follow-up turn)."""
    with _lock:
        for cid in _session_index.get(session_key) or []:
            entry = _entries.get(cid)
            if entry is not None and (include_choice_prompts or entry.awaiting_text):
                return entry
        return None


def may_answer(entry: Optional[_ClarifyEntry], responder_id: Optional[str]) -> bool:
    """True when ``responder_id`` may answer ``entry``: anyone in the session for an ordinary
    prompt, only the asked user for a prompt with an ``owner_user_id``."""
    if entry is None or not entry.owner_user_id:
        return True
    return bool(responder_id) and str(responder_id) == entry.owner_user_id


def _match_label(text: str, choices: list[str]) -> Optional[str]:
    """Stripped choice text matching ``text`` case-insensitively, ignoring the '(Recommended)'
    suffix the first choice carries by the time it reaches adapters; None if no match."""
    from tools.clarify_tool import strip_recommended
    wanted = strip_recommended(text).casefold()
    for choice in choices:
        if strip_recommended(str(choice)).casefold() == wanted:
            return str(choice).strip()
    return None


def _split_tokens(text: str) -> Optional[list[str]]:
    """Comma-separated tokens, or space-separated all-numeric tokens ("1 3"); else None."""
    if "," in text:
        return [t.strip() for t in text.split(",") if t.strip()]
    parts = text.split()
    return parts if len(parts) > 1 and all(p.isdigit() for p in parts) else None


def _is_int(text: str) -> bool:
    try:
        int(text)
        return True
    except ValueError:
        return False


def _selection_attempt_tokens(text: str, choices: Optional[list[str]] = None) -> Optional[list[str]]:
    """Tokens when ``text`` looks like a typed selection (bare int, comma list,
    all-numeric space list); None for free prose so the gateway can release the
    clarify. Comma-list labels may span up to the longest choice's word count."""
    stripped = str(text).strip()
    if not stripped:
        return None
    tokens = _split_tokens(stripped)
    if tokens is None:
        digits = stripped.removeprefix("-")
        return [stripped] if digits.isdigit() or _is_int(stripped) else None
    if "," not in stripped or not tokens:
        return tokens or None
    max_words = max(1, max((len(str(c).split()) for c in choices or []), default=1))
    return tokens if all(t.isdigit() or len(t.split()) <= max_words for t in tokens) else None


def _coerce_text_response(entry: _ClarifyEntry, response: str) -> Optional[str]:
    """Accepted value for a typed reply, or None on any rejection."""
    return _coerce_text_response_detailed(entry, response)[0]


def _coerce_text_response_detailed(entry: _ClarifyEntry, response: str) -> tuple[Optional[str], Optional[str]]:
    """Map a typed reply to ``(value, None)`` or ``(None, reason)``: ``"invalid_selection"``
    (selection-shaped but out of range/unrecognised — keep the clarify armed for a retry) or
    ``"prose"`` (free text on a native choice prompt — the gateway may cancel and route normally
    so a redirect-to-steer path cannot deadlock behind the waiting tool). Open-ended entries and
    ``awaiting_text`` accept any text; numeric picks and exact labels always resolve; multi-select
    returns a JSON array string (decoded tool-side); one bad token rejects the whole reply."""
    text = str(response).strip()
    is_skip = _is_decline(entry, text)
    if not entry.choices:
        if is_skip:
            return SKIPPED, None
        if _is_wrong(entry, text):
            return WRONG_ANSWER, None
        if entry.answer_pattern and not re.fullmatch(entry.answer_pattern, text):
            return None, "not_an_answer"
        return text, None
    if entry.multi_select:
        coerced = _coerce_multi_select_text(entry, text)
        selection_shaped = _selection_attempt_tokens(text, entry.choices) is not None
    else:
        # Out-of-range / non-canonical integer is a failed selection, not prose.
        selection_shaped = _is_int(text)
        idx = int(text) - 1 if selection_shaped else -1
        coerced = entry.choices[idx] if 0 <= idx < len(entry.choices) else _match_label(text, entry.choices)
    if coerced is not None:
        return coerced, None
    if is_skip:
        return SKIPPED, None
    if entry.awaiting_text:
        return text, None
    return None, "invalid_selection" if selection_shaped else "prose"


def _coerce_multi_select_text(entry: _ClarifyEntry, text: str) -> Optional[str]:
    """Parse "1,3" / "1 3" / "staging, prod" into a JSON array of choice labels;
    None when any token is out of range or unrecognised (reject the whole reply)."""
    choices, selected = entry.choices or [], []
    if not text:
        return None
    tokens = _split_tokens(text)
    for token in [text] if tokens is None else tokens:
        if token.isdigit():
            idx = int(token) - 1
            label = str(choices[idx]).strip() if 0 <= idx < len(choices) else None
        else:
            label = _match_label(token, choices)
        if label is None:
            return None
        if label not in selected:
            selected.append(label)
    return json.dumps(selected, ensure_ascii=False) if selected else None


def attempt_text_response_for_session(session_key: str, response: str,
                                      responder_id: Optional[str] = None) -> str:
    """Try to resolve the oldest pending clarify from typed text; returns a TEXT_* outcome.
    ``TEXT_NOT_OWNER`` when the prompt belongs to another user (the entry stays armed)."""
    entry = get_pending_for_session(session_key, include_choice_prompts=True)
    if entry is None:
        return TEXT_NO_PENDING
    return _attempt_text_response(entry, response, responder_id)


def attempt_text_response_for_entry(clarify_id: str, response: str,
                                    responder_id: Optional[str] = None) -> str:
    """Same as :func:`attempt_text_response_for_session` for one known prompt: an answer typed
    into a platform form for that card (the Discord secret-input modal), not into the chat."""
    entry = get_pending(clarify_id)
    if entry is None:
        return TEXT_NO_PENDING
    return _attempt_text_response(entry, response, responder_id, private_form=True)


def attempt_form_response_for_entry(clarify_id: str, values: dict,
                                    responder_id: Optional[str] = None) -> str:
    """Answer a prompt with its one private form (``form_fields``): every field must have a value of
    the right shape. Returns a TEXT_* outcome. The values are never logged."""
    entry = get_pending(clarify_id)
    if entry is None:
        return TEXT_NO_PENDING
    if not may_answer(entry, responder_id):
        return TEXT_NOT_OWNER
    if not entry.form_fields:
        return TEXT_NOT_AN_ANSWER
    answer: dict[str, str] = {}
    for item in entry.form_fields:
        key = str(item.get("key") or "")
        raw = str((values or {}).get(key) or "")
        # One rule on every path: the typed reply and the single private box strip spaces too.
        value = raw.strip()
        if not value.strip():
            return TEXT_NOT_AN_ANSWER
        pattern = item.get("pattern")
        if pattern and not re.fullmatch(pattern, value.strip()):
            return TEXT_NOT_AN_ANSWER
        answer[key] = value
    if resolve_gateway_clarify(clarify_id, FORM_ANSWER_PREFIX + json.dumps(answer, ensure_ascii=False)):
        return TEXT_RESOLVED
    return TEXT_NO_PENDING


def _attempt_text_response(entry: _ClarifyEntry, response: str, responder_id: Optional[str],
                           private_form: bool = False) -> str:
    if not may_answer(entry, responder_id):
        return TEXT_NOT_OWNER
    text = str(response).strip()
    if entry.chat_guard and not private_form and not _is_decline(entry, text) and not _is_wrong(entry, text):
        # A password card takes a typed reply only when it is clearly a password. Anything else is
        # held by the gateway and the client confirms with a button. A typed "yes" never counts.
        if has_open_hold(entry.clarify_id) and _norm_word(text) in _YES_NO_WORDS:
            return TEXT_HOLD_PENDING
        if not looks_like_secret(text):
            return TEXT_HELD
    coerced, reason = _coerce_text_response_detailed(entry, response)
    if coerced is None:
        if reason == "not_an_answer":
            return TEXT_NOT_AN_ANSWER
        return TEXT_REJECTED_SELECTION if reason == "invalid_selection" else TEXT_REJECTED_PROSE
    if resolve_gateway_clarify(entry.clarify_id, coerced):
        return TEXT_RESOLVED
    return TEXT_NO_PENDING  # lost a race with a button/callback resolution — no work left


def resolve_text_response_for_session(session_key: str, response: str) -> bool:
    """True only when the typed reply was accepted and the waiter unblocked."""
    return attempt_text_response_for_session(session_key, response) == TEXT_RESOLVED


def mark_awaiting_text(clarify_id: str) -> bool:
    """Flip an entry into text-capture mode (user picked 'Other'); False if unknown."""
    with _lock:
        entry = _entries.get(clarify_id)
        if entry is not None:
            entry.awaiting_text = True
        return entry is not None


def has_pending_owner_prompt(session_key: str) -> bool:
    """True while the session has an unanswered prompt bound to one user (a vault prompt)."""
    with _lock:
        return any(e is not None and e.owner_user_id and not e.event.is_set()
                   for e in (_entries.get(cid) for cid in _session_index.get(session_key) or []))


def has_pending(session_key: str) -> bool:
    """True when this session has at least one pending clarify entry."""
    with _lock:
        return any(_entries.get(cid) is not None for cid in _session_index.get(session_key) or [])


def clear_session(session_key: str) -> int:
    """Drop every pending clarify for a session (``/new``, shutdown, cached-agent eviction) so
    blocked agent threads don't outlive it; returns how many were cancelled. First-writer-wins: an already-set entry was answered for
    real, so it is dropped but its response preserved. The loop stays inside the lock so a button
    callback cannot slip between pop and check; entries go regardless of state so a cleared
    session is never resurrected by late callbacks."""
    with _lock:
        cancelled = 0
        for entry in (_entries.pop(cid, None) for cid in list(_session_index.pop(session_key, []) or [])):
            if entry is None or entry.event.is_set():
                continue
            entry.response = CANCELLED
            entry.event.set()
            cancelled += 1
        for hid in [h for h, r in _held.items() if r.session_key == session_key]:
            _held.pop(hid, None)
    return cancelled


def resolve_clarify_timeout(config: dict) -> int:
    """Clarify timeout (seconds): legacy ``clarify.timeout`` if explicitly set, else
    ``agent.clarify_timeout``, else 3600 — the single source of truth for every surface
    (gateway, CLI, TUI). ``<= 0`` is kept verbatim (unlimited); non-numeric -> 3600."""
    raw = (config.get("clarify") or {}).get("timeout")
    if raw is None:
        raw = (config.get("agent") or {}).get("clarify_timeout", 3600)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 3600


def get_clarify_timeout() -> int:
    """Clarify timeout from config.yaml; 0/negative = unlimited. Default 3600: long enough
    that a user who stepped away still finds a live entry when they tap, short enough that
    an abandoned prompt eventually unblocks the agent thread instead of pinning the guard.

    The old 600s default evicted the entry mid-think, so a late tap landed on a dead entry and the agent
    hung on ``running: clarify`` (#32762).
    """
    try:
        from hermes_cli.config import load_config
        return resolve_clarify_timeout(load_config() or {})
    except Exception:
        return 3600
