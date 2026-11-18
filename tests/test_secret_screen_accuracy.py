"""Gate A9 stays met: the credential screen's recall and precision on the labelled synthetic corpus."""

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "secret_screen_accuracy.py"


def load():
    spec = importlib.util.spec_from_file_location("secret_screen_accuracy", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_corpus_meets_the_bar(capsys):
    assert load().main(["--per-cell", "5", "--seed", "3"]) == 0
    assert "A9 met" in capsys.readouterr().out


def test_the_corpus_holds_both_kinds_and_every_format():
    module = load()
    import random

    found = {name for name, _kind, _path, _text in module.positives(random.Random(1), 1)}
    assert len(found) == len(module.FORMATS) + 2  # with the connection string and the private key
    assert sum(1 for _ in module.negatives(random.Random(1), 1)) >= 15
