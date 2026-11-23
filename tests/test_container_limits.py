"""A recipe container's limits are settings with the old values as defaults. A fake container tool; nothing runs."""

from dataclasses import replace
import subprocess

import pytest

from finassist.config import Config, config_hash, config_identity
from finassist.errors import AssistantError
from finassist.runner import run_recipe

IMAGE = "sha256:" + "a" * 64
LIMITS = ("runner_memory_mb", "runner_cpus", "runner_pids", "runner_tmp_mb")


def _argv(tmp_path, monkeypatch, **settings) -> list[str]:
    seen = []
    monkeypatch.setattr("finassist.platform_support.locate_tool", lambda _: "/usr/bin/docker")

    def supervise(argv, **_):
        seen.append(argv)
        return {"passed": True, "output": "synthetic", "exit_code": 0}

    def command(argv, **_):
        return subprocess.CompletedProcess(argv, 1 if "inspect" in argv else 0, b"", b"")
    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr("finassist.runner.subprocess.run", command)
    run_recipe(replace(Config(), runner_image=IMAGE, recipes={"unit": ["python", "-V"]}, **settings), "unit", tmp_path)
    return seen[0]


def test_the_defaults_are_the_old_limits(tmp_path, monkeypatch):
    argv = _argv(tmp_path, monkeypatch)
    for flag in ("--memory=1024m", "--cpus=2", "--pids-limit=128", "--tmpfs=/tmp:rw,nosuid,nodev,size=256m"):
        assert flag in argv
    assert "--read-only" in argv and "--network=none" in argv  # the other isolation flags are unchanged


def test_settings_set_the_container_limits(tmp_path, monkeypatch):
    argv = _argv(tmp_path, monkeypatch, runner_memory_mb=4096, runner_cpus=4, runner_pids=512, runner_tmp_mb=1024)
    for flag in ("--memory=4096m", "--cpus=4", "--pids-limit=512", "--tmpfs=/tmp:rw,nosuid,nodev,size=1024m"):
        assert flag in argv


@pytest.mark.parametrize("option,value", [
    ("runner_memory_mb", 63), ("runner_memory_mb", 65_537), ("runner_cpus", 0), ("runner_cpus", 65),
    ("runner_pids", 15), ("runner_pids", 4097), ("runner_tmp_mb", 15), ("runner_tmp_mb", 16_385),
    ("runner_cpus", True), ("runner_memory_mb", 1024.0), ("runner_pids", "128"),
])
def test_an_out_of_range_or_wrong_typed_limit_is_refused(option, value):
    with pytest.raises(AssistantError, match="^invalid_limit$") as refused:
        replace(Config(), **{option: value}).validate()
    assert refused.value.public_details["option"] == option


def test_at_their_defaults_the_limits_leave_the_hash_as_it_was():
    identity = config_identity(Config())
    assert not set(LIMITS) & set(identity)
    changed = replace(Config(), runner_cpus=4)
    assert "runner_cpus" in config_identity(changed) and config_hash(changed) != config_hash(Config())
