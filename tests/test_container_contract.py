from dataclasses import replace
import subprocess

import pytest

from finassist.config import Config
from finassist.runner import run_recipe


@pytest.mark.parametrize("raises", [False, True])
def test_container_flags_and_cleanup_on_supervisor_failure(tmp_path, monkeypatch, raises):
    commands = []
    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: "/usr/bin/docker")

    def supervise(argv, **kwargs):
        commands.append(argv)
        assert "--network=none" in argv and "--read-only" in argv and "--cap-drop=ALL" in argv
        assert "--pull=never" in argv and "--user=65534:65534" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert argv[argv.index(config.runner_image) - 1] == "--"
        assert "OPENAI_API_KEY" not in kwargs["env"]
        if raises:
            raise RuntimeError("fictional supervisor failure")
        return {"passed": True, "output": "fictional", "exit_code": 0}

    def command(argv, **_):
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 1 if "inspect" in argv else 0, b"", b"")

    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr("finassist.runner.subprocess.run", command)
    config = replace(Config(), runner_image="sha256:" + "a" * 64, recipes={"unit": ["python", "-V"]})
    if raises:
        with pytest.raises(RuntimeError, match="fictional supervisor failure"):
            run_recipe(config, "unit", tmp_path)
    else:
        assert run_recipe(config, "unit", tmp_path)["receipt"]["cleanup_verified"]
    assert commands[-2][1:3] == ["rm", "--force"]
    assert commands[-1][1:3] == ["container", "inspect"]
    assert commands[-2][-1] == commands[-1][-1] == commands[0][3]
