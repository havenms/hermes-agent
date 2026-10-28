"""Client-facing text never names the product; the clarify card uses the bot name."""

import re
from types import SimpleNamespace

import pytest

from agent.i18n import t

pytest.importorskip("discord")
from plugins.platforms.discord.adapter import DiscordAdapter  # noqa: E402

CLIENT_KEYS = [
    "platform.discord.prompt.clarify_title",
    "platform.discord.approval.question",
    "platform.discord.thread.seed_message",
    "platform.discord.thread.default_name",
    "platform.discord.thread.handoff_seed",
    "platform.discord.thread.auto_create_failed",
    "platform.discord.command.reset.description",
    "platform.discord.command.status.description",
    "platform.discord.command.stop.description",
    "platform.discord.command.restart.description",
    "platform.discord.command.thread.description",
    "platform.discord.command.thread.arg_message",
    "platform.discord.command.skill.description",
    "gateway.exec_approval.header",
    "gateway.progress.task_card_title",
    "gateway.progress.quiet_working",
]


@pytest.mark.parametrize("key", CLIENT_KEYS)
def test_client_strings_do_not_say_hermes(key):
    text = t(key, name="x")
    assert text != key
    assert not re.search(r"hermes", text, re.I), text


def _bare_adapter(user=None):
    adapter = DiscordAdapter.__new__(DiscordAdapter)
    adapter._client = SimpleNamespace(user=user)
    return adapter


def test_card_title_uses_guild_nickname_first():
    adapter = _bare_adapter(SimpleNamespace(display_name="Diana Bot", name="diana"))
    channel = SimpleNamespace(guild=SimpleNamespace(me=SimpleNamespace(display_name="Diana")))
    assert adapter._clarify_card_title(channel) == "Diana needs your input"


def test_card_title_uses_account_name_in_a_dm():
    adapter = _bare_adapter(SimpleNamespace(display_name="Diana", name="diana"))
    assert adapter._clarify_card_title(SimpleNamespace()) == "Diana needs your input"


def test_card_title_is_neutral_without_a_name():
    assert _bare_adapter(None)._clarify_card_title(None) == "Quick question"
