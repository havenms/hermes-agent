"""Vault secret prompts for messaging surfaces.

The vault tools (unlock, save-login, one-time code) obtain secrets through
callbacks registered on :mod:`agent.vault_backends.unlock`. The CLI and the
TUI/Desktop gateway register them; the messaging gateway did not, so on Telegram
(and every other chat platform) ``can_prompt_here()`` was always False and every
vault tool could only answer ``prompt_unavailable`` — the user had no way to hand
the agent a password at all.

This module builds those three callbacks over the gateway's existing synchronous
clarify bridge. Reusing that bridge is deliberate: it already renders a prompt on
any platform (native card, plus a plain-text fallback), blocks the agent thread on
an event, and — the part that matters here — intercepts the user's reply in the
inbound path, so the answer is handed straight to the callback and never becomes a
conversation message. A secret typed in answer to one of these prompts therefore
never reaches session history, memory, or the model.

The prompts are marked secret so the adapter deletes the user's own message once
the secret has been read, on platforms that support deletion.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Optional

from tools.clarify_gateway import FORM_ANSWER_PREFIX, WRONG_ANSWER
from agent.vault_backends.unlock import (
    set_code_prompt_callback,
    set_pasted_secret_scrub_callback,
    set_save_login_prompt_callback,
    set_unlock_prompt_callback,
)

logger = logging.getLogger(__name__)

# Discord shows at most 5 text inputs in one form. A login with more fields asks card by card.
MAX_FORM_FIELDS = 5

# A surface's blocking ask: (question, secret, last, kind, answer_pattern, chat_guard) -> the reply,
# "" when unanswered. ``last`` tells the surface whether another question follows in this
# sequence, so it can hold the stream/typing re-arm for the final one (same contract as the
# clarify batch). ``kind`` picks the wait (:func:`vault_prompt_timeout`). ``answer_pattern`` is a
# regex a typed reply must fully match to count as the answer (see ``tools.clarify_gateway``).
VaultAsk = Callable[..., str]

# How long each prompt waits for the user, in seconds (``browser.vault_<kind>_timeout``; 0 or
# less = no limit). The wait blocks one tool call, not the gateway: the call keeps the turn's
# activity clock fresh, so no watchdog ends it, and the browser idle reaper skips a browser
# whose task has a call in flight. The limits are about the user, not the machinery:
#   save_login: a client often reads the card hours later. The value is stored even when the
#     login page went stale meanwhile, so a long wait still saves the login.
#   code: sites expire one-time codes in minutes; after 30 minutes the bot asks for a new code.
#   unlock: a password-manager unlock is asked when the bot is about to use it.
VAULT_PROMPT_TIMEOUT_DEFAULTS = {"save_login": 4 * 3600, "code": 30 * 60, "unlock": 30 * 60}

# A TYPED reply must not be clearly chat, or the prompt stays open and the user gets a hint.
# Without this, the first unrelated message after a long wait ("are you there?") would be
# stored as the username or typed into the page as the code. The private form takes any value
# (``tools.clarify_gateway``): the client typed it into a labeled box on purpose.
# TAPAS: clients are beginners and services use odd usernames ("MICHAEL PERSONETTE"). A typed reply
# is the email or username unless it is clearly chat: it ends with "?", or it is only greeting or
# filler words ("hi", "ok thanks", "what's up"). Spaces, capitals, digits, dots and underscores are
# fine. The next card names the identifier, so two more replies are not taken: an email together
# with more words, and several words with a password-shaped word in them ("jsmith Pass1234").
_CHAT_TOKEN = (r"(?:what['’]?s\s+up|wh?assup|sup|thank\s+you|thank\s+u|no\s+problem|got\s+it|all\s+good|"
               r"hold\s+on|one\s+moment|"
               r"yes|yep|yeah|yup|ya|no|nope|nah|ok|okay|k|kk|hi|hey|hello|hiya|yo|thanks|thx|ty|np|sure|done|"
               r"wait|sorry|lol|haha|brb|great|cool|nice|good|fine|please|help|what|why|how|hmm|huh|here|"
               r"there|one|sec|min|later|soon|cheers|bye|morning|afternoon|evening|night|welcome|again|"
               r"still|now)")
_SEP = r"[\s,.!]"
IDENTIFIER_PATTERN = (
    r"(?is)(?!.*\?$)"
    rf"(?!{_SEP}*{_CHAT_TOKEN}(?:{_SEP}+{_CHAT_TOKEN})*{_SEP}*$)"
    r"(?!(?=.*\s)(?=.*[^@\s]+@[^@\s]+\.[A-Za-z]{2,}))"
    r"(?!(?=.*\s)(?=.*(?<!\S)(?=\S*[A-Za-z])(?=\S*\d)\S{6,}(?!\S)))"
    r".{1,254}")
# The password card's way back. A typed "wrong", "wrong email" or "not my email" goes back to the
# email or username card (``tools.clarify_gateway.WRONG_WORDS``). "skip", "cancel" and "stop" still
# decline the login (``DECLINE_WORDS``).
WRONG_LOGIN_LINE = "Wrong email or username? Just tell me."
# How many times one save_login may go back to the email or username card.
MAX_IDENTIFIER_REDO = 3

# A typed one-time code: one token of 3 to 12 characters with at least one digit ("123456",
# "G-123456", "AB12CD", "X7K-9PQ"), or digit groups split by spaces ("123 456"). ``code_prompt``
# removes the spaces from digit groups. Chat with spaces, such as "wait 5 min" or "give me 2",
# never matches.
CODE_PATTERN = r"(?=\S*\d)\S{3,12}|(?=(?:\D*\d){3})(?=.{3,24}$)\d+(?: +\d+)+"
_SPACED_DIGITS = re.compile(r"\d+(?:\s+\d+)+")


def vault_prompt_timeout(kind: str) -> float:
    """Seconds a vault prompt of ``kind`` waits (``browser.vault_<kind>_timeout``); 0 = no limit."""
    default = VAULT_PROMPT_TIMEOUT_DEFAULTS.get(kind, VAULT_PROMPT_TIMEOUT_DEFAULTS["code"])
    try:
        from tools.browser_session_cloud import browser_cfg
        value = float(browser_cfg(f"vault_{kind}_timeout", default, float))
    except Exception:  # health: allow BLE001 -- a config read failure keeps the default wait
        logger.debug("vault prompt timeout read failed; using %ss", default, exc_info=True)
        return float(default)
    return max(0.0, value) if value == value else float(default)  # NaN -> default


def _clean(value: Optional[str]) -> str:
    """The typed value, or "" for no answer. A "wrong email" reply on a card that cannot go back
    (code, unlock, the email card itself) is a decline, as before."""
    if value == WRONG_ANSWER:
        return ""
    return (value or "").strip()


def _clean_secret(value: Optional[str]) -> str:
    """Same as :func:`_clean` for a password: the value as typed. Spaces at the ends stay."""
    if value == WRONG_ANSWER:
        return ""
    value = value or ""
    return value if value.strip() else ""


def _clean_code(value: Optional[str]) -> str:
    """The code without spaces at the ends, and without the spaces in digit groups ("123 456")."""
    value = _clean(value)
    return re.sub(r"\s+", "", value) if _SPACED_DIGITS.fullmatch(value) else value


def build_vault_prompt_callbacks(ask: VaultAsk) -> dict[str, Callable]:
    """Build the three vault prompt callbacks on top of ``ask``.

    ``ask(question, secret=True)`` must block until the user answers and return
    their reply, or "" when none arrived. Each callback returns the shape its
    caller in :mod:`agent.vault_backends.unlock` documents, and answers "" / None
    on a decline so the calling tool reports a cancellation instead of storing an
    empty secret.
    """

    def _need(text: str) -> dict:
        """``need=`` for a surface whose ask takes it (the gateway names it on a reply that does not match)."""
        return {"need": text} if _takes(ask, "need") else {}

    def unlock_prompt(backend: str, display_name: str) -> str:
        """Master password for an external password manager. Consumed by the
        manager's CLI to mint a session token; never written to disk."""
        name = display_name or backend
        return _clean_secret(ask(
            f"🔐 To use the passwords you keep in {name}, I need its main password.\n\n"
            "Reply with it here. I use it once to open it, I do not keep it, and I remove your message.",
            secret=True, last=True, kind="unlock", chat_guard=True,
            **_need(f"the main password for {name}"),
        ))

    def save_login_prompt(origin: str, site_label: str,
                          extra_fields: tuple = (), notice: str = "") -> Optional[dict]:
        """Identifier + password (+ any extra secret fields) for the page currently open. Stored in
        the local vault bound to ``origin`` and filled into the page at once.

        One card per field, numbered (1/3), (2/3)...: a bare "Now the password" read as the first
        prompt repeating, and an unanswered first card left the caller looking like it had hung on a
        prompt the user never saw. The second card names the identifier it will save, so a wrong one
        is caught before the password is sent (the identifier is not a secret: browser_vault list
        shows it). ``site_label`` is the name the client knows (the model's label, the page title,
        then the host). A decline at any card stores nothing.

        ``notice`` is the plain line from the last rejection ("That password didn't work..."); the
        first card starts with it. On a surface with a private form (Discord), the first card also
        offers ONE form with every field; its answer completes the whole sequence at once."""
        site = site_label or origin
        extras = [str(x) for x in (extra_fields or ()) if str(x or "").strip()]
        total = 2 + len(extras)
        lead = f"{notice}\n\n" if notice else ""
        form = _login_form_fields(extras) if total <= MAX_FORM_FIELDS and _takes_form(ask) else None
        for _redo in range(MAX_IDENTIFIER_REDO + 1):
            first = ask(
                f"{lead}🔑 To get into {site} for you, I need your login (1/{total}).\n\n"
                "Reply with the email or username you use there.",
                secret=False, last=False, kind="save_login", answer_pattern=IDENTIFIER_PATTERN,
                **_need(f"your email or username for {site}"),
                **({"form_fields": form} if form else {}),
            )
            if form and str(first or "").startswith(FORM_ANSWER_PREFIX):
                return _form_answer(str(first), extras)
            identifier = _clean(first)
            if not identifier:
                return None
            answer: Optional[dict] = _ask_secrets(identifier, site, extras, total)
            if answer is not _GO_BACK:
                return answer
            # "Wrong email": ask card 1 again, with a plain line on top.
            lead = "No problem. Let's fix the email or username first.\n\n"
        return None

    def _ask_secrets(identifier: str, site: str, extras: list, total: int):
        """Cards 2..N. ``_GO_BACK`` when the client says the email or username was wrong."""
        password = ask(
            f"🔑 Thanks! Now I need the password for {identifier} (2/{total}).\n\n"
            "You can also reply here with just the password. I'll type it in and remove your message. "
            f"{WRONG_LOGIN_LINE}",
            secret=True, last=not extras, kind="save_login", chat_guard=True,
            **_need(f"your password for {site}"),
        )
        if password == WRONG_ANSWER:
            return _GO_BACK
        if not password:
            return None
        answer: dict = {"identifier": identifier, "password": password}
        if extras:
            answer["extra"] = {}
            for n, label in enumerate(extras, start=3):
                value = ask(
                    f"🔑 {site} also asks for your {label} ({n}/{total}).\n\n"
                    "Reply here with just that. I'll type it in and remove your message.",
                    secret=True, last=n == total, kind="save_login", chat_guard=True,
                    **_need(f"your {label} for {site}"),
                )
                if value == WRONG_ANSWER:
                    return _GO_BACK
                if not value:
                    return None
                answer["extra"][label] = value
        return answer

    def code_prompt(site: str, hint: str, notice: str = "") -> str:
        """One-time code the site just sent, for a login with no stored seed. ``notice`` is the plain
        line from the last rejection ("That code didn't work..."); the card starts with it."""
        detail = f"\n\n{hint}" if hint else ""
        lead = f"{notice}\n\n" if notice else ""
        return _clean_code(ask(
            f"{lead}🔢 {site} just sent a code to your phone or email.\n\nReply with it here.{detail}",
            secret=True, last=True, kind="code", answer_pattern=CODE_PATTERN,
            **_need(f"the code {site} sent you"),
        ))

    return {
        "unlock": unlock_prompt,
        "save_login": save_login_prompt,
        "code": code_prompt,
    }


_GO_BACK = object()  # sentinel: the client said the email or username was wrong


def _takes(ask: VaultAsk, name: str) -> bool:
    """True when the surface's ask takes the keyword ``name`` (or any keyword)."""
    import inspect
    try:
        params = inspect.signature(ask).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _takes_form(ask: VaultAsk) -> bool:
    """True when the surface's ask can show one private form (``form_fields``)."""
    return _takes(ask, "form_fields")


def _login_form_fields(extras: list) -> list[dict]:
    """The fields of the one private login form: key, label as the client reads it and
    the secret flag. Discord has no hidden text input, so a secret field says so in its label. No field
    has a shape check: the client typed each value into a labeled box on purpose."""
    fields = [{"key": "identifier", "label": "Email or username", "secret": False},
              {"key": "password", "label": "Password (secret)", "secret": True}]
    fields += [{"key": f"extra:{label}", "label": f"{label} (secret)", "secret": True} for label in extras]
    return fields


def _form_answer(raw: str, extras: list) -> Optional[dict]:
    """The save_login answer from one form submit, or None when a field is missing."""
    import json
    try:
        values = json.loads(raw[len(FORM_ANSWER_PREFIX):])
    except (TypeError, ValueError):
        return None
    if not isinstance(values, dict):
        return None
    identifier = _clean(values.get("identifier"))
    password = str(values.get("password") or "")
    extra = {label: str(values.get(f"extra:{label}") or "") for label in extras}
    if not identifier or not password or not all(extra.values()):
        return None
    answer: dict = {"identifier": identifier, "password": password}
    if extras:
        answer["extra"] = extra
    return answer


def install_vault_prompt_callbacks(ask: VaultAsk, scrub: Optional[Callable[[], bool]] = None) -> None:
    """Register all three callbacks for the CURRENT thread.

    ``agent.vault_backends.unlock`` stores its callbacks in a thread-local, so this
    must run on the thread that will execute the tools — the gateway wires it
    alongside ``agent.clarify_callback`` for exactly that reason.
    """
    callbacks = build_vault_prompt_callbacks(ask)
    set_unlock_prompt_callback(callbacks["unlock"])
    set_save_login_prompt_callback(callbacks["save_login"])
    set_code_prompt_callback(callbacks["code"])
    set_pasted_secret_scrub_callback(scrub)


def clear_vault_prompt_callbacks() -> None:
    """Drop the callbacks after a turn so a reused worker thread never keeps
    prompting for a session that has ended."""
    set_unlock_prompt_callback(None)
    set_save_login_prompt_callback(None)
    set_code_prompt_callback(None)
    set_pasted_secret_scrub_callback(None)
