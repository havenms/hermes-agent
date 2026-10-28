"""The Discord card for a secret prompt (vault password, master password, one-time code).

A typed reply to a secret prompt lands in the channel first. The gateway deletes it once read, but
only with Manage Messages, and never in a DM. This view adds a "Enter privately" button that opens a
Discord modal with one text input. The modal answer goes from Discord to the bot only: it never
appears in the channel, so nothing needs to be deleted. The typed reply still works as a fallback.

A login with several fields (email, password, a PIN) gets ONE form on its first card: one text input
per field (Discord allows 5), labels from the page, the secret ones marked "(secret)" because Discord
has no hidden input. Its answer completes the whole sequence, so the client fills in one form, not
one per card (``tools.clarify_gateway.attempt_form_response_for_entry``).

The button and the modal answer the same gateway clarify entry as a typed reply
(``tools.clarify_gateway.attempt_text_response_for_entry``), so the owner check, the answer shape
check and the "skip" word behave the same on every path.

Built by ``build_secret_prompt_view`` from ``adapter._define_discord_view_classes``, because discord.py
can be installed lazily after the adapter module is imported.
"""
import logging
from typing import Optional

from agent.i18n import t

logger = logging.getLogger(__name__)

# Discord limits: modal title and text-input label <= 45 characters.
_MODAL_TEXT_LIMIT = 45
_ANSWER_MAX_LENGTH = 512
_FORM_MAX_FIELDS = 5  # Discord: at most 5 text inputs in one modal


def _short(text: str) -> str:
    return text if len(text) <= _MODAL_TEXT_LIMIT else text[: _MODAL_TEXT_LIMIT - 1] + "…"


def build_secret_prompt_view(discord, base, *, unauthorized):
    """Return the ``SecretPromptView`` class on ``base`` (the adapter's shared ``_HermesView``)."""

    def _modal_for(view):
        """The modal class is built on first use: discord.ui.Modal exists only in a real discord.py
        (the shared test stub has no Modal), and the button view must build without it."""

        class SecretAnswerModal(discord.ui.Modal):
            """One text input. Discord has no password field type; the value stays private because
            a modal submission is never posted to the channel."""

            def __init__(self):
                super().__init__(title=_short(t("platform.discord.prompt.secret_modal_title")), timeout=600)
                self.answer = discord.ui.TextInput(
                    label=_short(t("platform.discord.prompt.secret_input_label")),
                    style=discord.TextStyle.short, required=True, max_length=_ANSWER_MAX_LENGTH,
                )
                self.add_item(self.answer)

            async def on_submit(self, interaction) -> None:
                await view.submit(interaction, str(self.answer.value or ""))

        return SecretAnswerModal()

    def _form_modal_for(view):
        """One modal with a text input per login field. Values go to the bot only, never the chat."""

        class LoginFormModal(discord.ui.Modal):
            def __init__(self):
                super().__init__(title=_short(t("platform.discord.prompt.login_form_title")), timeout=600)
                self.inputs = []
                for item in view.form_fields[:_FORM_MAX_FIELDS]:
                    box = discord.ui.TextInput(
                        label=_short(str(item.get("label") or item.get("key") or "")),
                        style=discord.TextStyle.short, required=True, max_length=_ANSWER_MAX_LENGTH,
                    )
                    self.inputs.append((str(item.get("key") or ""), box))
                    self.add_item(box)

            async def on_submit(self, interaction) -> None:
                await view.submit_form(interaction, {key: str(box.value or "") for key, box in self.inputs})

        return LoginFormModal()

    class SecretPromptView(base):
        """``🔒 Enter privately`` button for one secret clarify entry. Only the prompt's owner may
        open the modal (plus the adapter's allowlist). Single use: retired by the adapter's
        ``retire_clarify_card`` when the prompt ends any other way."""

        def __init__(self, clarify_id: str, owner_user_id: Optional[str], allowed_user_ids: set,
                     allowed_role_ids: Optional[set] = None, *, timeout: Optional[float] = None,
                     form_fields: Optional[list] = None):
            super().__init__(allowed_user_ids, allowed_role_ids, timeout=timeout)
            self.clarify_id = clarify_id
            # A login form (several fields in one modal); None = one answer box.
            self.form_fields = [dict(f) for f in form_fields][:_FORM_MAX_FIELDS] if form_fields else None
            self.owner_user_id = str(owner_user_id) if owner_user_id else None
            self.on_closed = None  # the adapter's hook to forget this view
            button = discord.ui.Button(
                label=t("platform.discord.prompt.secret_button"), style=discord.ButtonStyle.primary,
                custom_id=f"vault-secret:{clarify_id}",
            )
            button.callback = self._on_click
            self.add_item(button)

        def _is_owner(self, interaction) -> bool:
            if not self.owner_user_id:
                return True
            return str(getattr(getattr(interaction, "user", None), "id", "") or "") == self.owner_user_id

        async def _ephemeral(self, interaction, text: str) -> None:
            try:
                await interaction.response.send_message(text, ephemeral=True)
            except Exception:  # health: allow BLE001 -- an expired interaction token must not break the view
                logger.debug("Discord secret prompt: ephemeral reply failed (id=%s)", self.clarify_id, exc_info=True)

        async def _on_click(self, interaction) -> None:
            from tools.clarify_gateway import get_pending
            if self.resolved or get_pending(self.clarify_id) is None:
                await self._ephemeral(interaction, t("platform.discord.prompt.clarify_already_answered"))
                return
            if not self._check_auth(interaction) or not self._is_owner(interaction):
                await self._ephemeral(interaction, t("platform.discord.prompt.secret_not_owner"))
                return
            await interaction.response.send_modal(_form_modal_for(self) if self.form_fields else _modal_for(self))

        async def submit(self, interaction, value: str) -> None:
            """Hand the modal answer to the waiting tool. The value is never logged or echoed."""
            from tools import clarify_gateway as clarify_mod
            responder = str(getattr(getattr(interaction, "user", None), "id", "") or "")
            if not self._check_auth(interaction):
                await self._ephemeral(interaction, unauthorized())
                return
            outcome = clarify_mod.attempt_text_response_for_entry(self.clarify_id, value, responder_id=responder)
            logger.info("Discord secret prompt modal answer (id=%s, outcome=%s)", self.clarify_id, outcome)
            await self._finish(interaction, outcome)

        async def submit_form(self, interaction, values: dict) -> None:
            """Hand the whole login form to the waiting tool at once. Values are never logged."""
            from tools import clarify_gateway as clarify_mod
            responder = str(getattr(getattr(interaction, "user", None), "id", "") or "")
            if not self._check_auth(interaction):
                await self._ephemeral(interaction, unauthorized())
                return
            outcome = clarify_mod.attempt_form_response_for_entry(self.clarify_id, values, responder_id=responder)
            logger.info("Discord login form answer (id=%s, fields=%d, outcome=%s)", self.clarify_id, len(values), outcome)
            await self._finish(interaction, outcome)

        async def _finish(self, interaction, outcome: str) -> None:
            from tools import clarify_gateway as clarify_mod
            if outcome == clarify_mod.TEXT_NOT_AN_ANSWER:
                await self._ephemeral(interaction, t("gateway.clarify.not_an_answer"))
                return
            if outcome == clarify_mod.TEXT_NOT_OWNER:
                await self._ephemeral(interaction, t("platform.discord.prompt.secret_not_owner"))
                return
            if outcome != clarify_mod.TEXT_RESOLVED:
                await self._ephemeral(interaction, t("platform.discord.prompt.clarify_already_answered"))
                return
            await self._ephemeral(interaction, t("platform.discord.prompt.secret_received"))
            await self.close(t("gateway.clarify.answered_secret"), discord.Color.green())

        async def close(self, footer: str, color) -> None:
            """Disable the button, stamp the card, release the view (idempotent)."""
            if self.resolved:
                return
            self.resolved = True
            self._disable_all()
            msg = self._message
            try:
                if msg is not None:
                    embed = self._first_embed(msg)
                    if embed:
                        embed.color = color
                        embed.set_footer(text=footer)
                    await msg.edit(embed=embed, view=self)
            except Exception:  # health: allow BLE001 -- message deleted or too old to edit
                logger.debug("Discord secret prompt: card edit failed (id=%s)", self.clarify_id, exc_info=True)
            finally:
                self.stop()
                if callable(self.on_closed):
                    self.on_closed()

        async def on_timeout(self):
            await super().on_timeout()
            if callable(self.on_closed):
                self.on_closed()

    return SecretPromptView
