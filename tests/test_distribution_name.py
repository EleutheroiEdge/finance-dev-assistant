"""The installed distribution identity is separate from the public import/command."""

from importlib import metadata
import json

import pytest
import test_dashboard

import finassist
from finassist.cli import main


dashboard = test_dashboard.dashboard


@pytest.fixture
def installed_metadata(monkeypatch):
    calls = []

    def version(name):
        calls.append(name)
        assert name == "finledgerpoli", "runtime lookup used the old distribution name"
        return "9.8.7"

    monkeypatch.setattr(metadata, "version", version)
    return calls


def test_cli_version_uses_renamed_installed_metadata(installed_metadata, capsys):
    with pytest.raises(SystemExit) as result:
        main(["--version"])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == "9.8.7"
    assert installed_metadata == ["finledgerpoli"]


def test_doctor_uses_renamed_installed_metadata(installed_metadata, capsys):
    assert main(["doctor"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == "9.8.7"
    assert installed_metadata and set(installed_metadata) == {"finledgerpoli"}


def test_dashboard_health_uses_renamed_installed_metadata(dashboard, installed_metadata):
    _, _, request = dashboard
    status, data, _ = request("GET", "/api/health")
    assert status == 200 and data["doctor"]["version"] == "9.8.7"
    assert installed_metadata and set(installed_metadata) == {"finledgerpoli"}


def test_uninstalled_source_version_does_not_probe_the_old_distribution(monkeypatch):
    calls = []

    def missing(name):
        calls.append(name)
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "version", missing)
    assert finassist.installed_version() == finassist.__version__
    assert calls == ["finledgerpoli"]
