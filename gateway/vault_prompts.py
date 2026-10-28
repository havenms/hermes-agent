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
from typing import Callable, Optional

from agent.vault_backends.unlock import (
    set_code_prompt_callback,
    set_pasted_secret_scrub_callback,
    set_save_login_prompt_callback,
    set_unlock_prompt_callback,
)

logger = logging.getLogger(__name__)

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

# A typed reply must look like the answer, or the prompt stays open and the user gets a hint.
# Without this, the first unrelated message after a long wait ("are you there?") would be
# stored as the username or typed into the page as the code.
IDENTIFIER_PATTERN = r"\S{1,254}"  # email, phone or username: one token, no spaces
# The password card's way out. A typed "skip", "wrong", "cancel" or "stop" still declines
# (``tools.clarify_gateway.DECLINE_WORDS``); the card does not teach a command word.
WRONG_LOGIN_LINE = "Wrong email or username? Just tell me."

CODE_PATTERN = r"(?=.{4,})(?=[^0-9]*[0-9])[A-Za-z0-9]{1,8}(?:[ -]?[A-Za-z0-9]{1,8}){0,2}"  # 123456, 123 456, G-123456


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
    return (value or "").strip()


def build_vault_prompt_callbacks(ask: VaultAsk) -> dict[str, Callable]:
    """Build the three vault prompt callbacks on top of ``ask``.

    ``ask(question, secret=True)`` must block until the user answers and return
    their reply, or "" when none arrived. Each callback returns the shape its
    caller in :mod:`agent.vault_backends.unlock` documents, and answers "" / None
    on a decline so the calling tool reports a cancellation instead of storing an
    empty secret.
    """

    def unlock_prompt(backend: str, display_name: str) -> str:
        """Master password for an external password manager. Consumed by the
        manager's CLI to mint a session token; never written to disk."""
        name = display_name or backend
        return _clean(ask(
            f"🔐 To use the passwords you keep in {name}, I need its main password.\n\n"
            "Reply with it here. I use it once to open it, I do not keep it, and I remove your message.",
            secret=True, last=True, kind="unlock", chat_guard=True,
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
        first card starts with it."""
        site = site_label or origin
        extras = [str(x) for x in (extra_fields or ()) if str(x or "").strip()]
        total = 2 + len(extras)
        lead = f"{notice}\n\n" if notice else ""
        identifier = _clean(ask(
            f"{lead}🔑 To get into {site} for you, I need your login (1/{total}).\n\n"
            "Reply with the email or username you use there.",
            secret=False, last=False, kind="save_login", answer_pattern=IDENTIFIER_PATTERN,
        ))
        if not identifier:
            return None
        password = ask(
            f"🔑 Thanks! Now I need the password for {identifier} (2/{total}).\n\n"
            "You can also reply here with just the password. I'll type it in and remove your message. "
            f"{WRONG_LOGIN_LINE}",
            secret=True, last=not extras, kind="save_login", chat_guard=True,
        )
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
                )
                if not value:
                    return None
                answer["extra"][label] = value
        return answer

    def code_prompt(site: str, hint: str, notice: str = "") -> str:
        """One-time code the site just sent, for a login with no stored seed. ``notice`` is the plain
        line from the last rejection ("That code didn't work..."); the card starts with it."""
        detail = f"\n\n{hint}" if hint else ""
        lead = f"{notice}\n\n" if notice else ""
        return _clean(ask(
            f"{lead}🔢 {site} just sent a code to your phone or email.\n\nReply with it here.{detail}",
            secret=True, last=True, kind="code", answer_pattern=CODE_PATTERN,
        ))

    return {
        "unlock": unlock_prompt,
        "save_login": save_login_prompt,
        "code": code_prompt,
    }


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
