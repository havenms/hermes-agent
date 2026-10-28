"""HERMES_CRON_PROFILES limits which profiles a gateway's cron ticker visits (TAPAS patch).

The srijit dev gateway must never run jane's, sophias-assistant's or default's cron jobs with dev
code. Upstream ticks every profile from every gateway and relies on the tick lock.
"""

from pathlib import Path
from types import SimpleNamespace

from gateway import run

HOMES = (("default", Path("/h")), ("jane", Path("/h/profiles/jane")), ("srijit", Path("/h/profiles/srijit")))


def _config():
    return SimpleNamespace(_runtime_profile_homes=HOMES)


def test_unset_keeps_the_upstream_set(monkeypatch):
    monkeypatch.delenv("HERMES_CRON_PROFILES", raising=False)
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile_name", lambda: "srijit")
    assert [n for n, _ in run._cron_tick_profile_homes(_config())] == ["default", "jane", "srijit"]


def test_the_env_var_limits_the_tick_to_the_named_profiles(monkeypatch):
    monkeypatch.setenv("HERMES_CRON_PROFILES", "srijit")
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile_name", lambda: "srijit")
    assert run._cron_tick_profile_homes(_config()) == [("srijit", Path("/h/profiles/srijit"))]


def test_a_list_with_spaces_works(monkeypatch):
    monkeypatch.setenv("HERMES_CRON_PROFILES", " jane , srijit ")
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile_name", lambda: "srijit")
    assert [n for n, _ in run._cron_tick_profile_homes(_config())] == ["jane", "srijit"]
