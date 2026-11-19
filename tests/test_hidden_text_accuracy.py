"""Gate A10 stays met: every payload refused, no ordinary text refused, the stated trade-off unchanged."""

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "hidden_text_accuracy.py"


def test_the_hidden_character_gate_is_met(capsys):
    spec = importlib.util.spec_from_file_location("hidden_text_accuracy", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main([]) == 0, capsys.readouterr().out
    assert len(module.PAYLOADS) >= 20 and len(module.ORDINARY) >= 15
