"""The seeded figure-source corpus script (release gate A8) on a small run. Every value is made up."""

import importlib.util
from pathlib import Path
import re
import sys

import pytest

from finassist import figure_sources

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("figure_source_corpus", ROOT / "scripts/figure_source_corpus.py")
corpus = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))  # it imports its edge rows from its own folder
sys.modules["figure_source_corpus"] = corpus  # its dataclasses look their module up by name
SPEC.loader.exec_module(corpus)


def test_a_small_corpus_lists_every_figure_and_prints_only_counts(capsys):
    assert corpus.main(["--files", "60", "--seed", "7"]) == 0
    shown = capsys.readouterr().out
    for mode in ("read every way", "declared"):
        line = next(line for line in shown.splitlines() if line.startswith(mode + ":"))
        assert "files missing a figure 0" in line and "unexpected refusals 0" in line, line
        assert "own spellings not refused 0" in line, line
    # Counts, codes, kinds and the corpus fingerprint only: no number with a decimal mark, no path.
    assert not re.search(r"\d[.,]\d", shown) and "figure-corpus-" not in shown and "export-" not in shown


def test_the_same_seed_writes_the_same_corpus(capsys):
    corpus.main(["--files", "20", "--seed", "11"])
    first = capsys.readouterr().out.splitlines()[-1]
    corpus.main(["--files", "20", "--seed", "11", "--automatic-only"])
    assert capsys.readouterr().out.splitlines()[-1] == first  # one corpus, whichever modes run


def test_the_gate_fails_when_the_screen_drops_a_figure(capsys, monkeypatch):
    real = figure_sources._source_figures

    def dropping(raw, min_digits, layout=None, round_figures=False):
        values, forms, rounds = real(raw, min_digits, layout, round_figures)
        return set(sorted(values)[1:]), forms, rounds

    monkeypatch.setattr(figure_sources, "_source_figures", dropping)
    assert corpus.main(["--files", "20", "--seed", "7"]) == 1
    assert "files missing a figure 0" not in capsys.readouterr().out


def _run(capsys, *options, files="60"):
    code = corpus.main(["--files", files, "--seed", "7", *options])
    lines = capsys.readouterr().out.splitlines()
    assert lines[-2].startswith("settings: ") and "generator " in lines[-2]
    return code, lines[-1], "\n".join(lines)


def test_each_profile_writes_its_own_corpus_and_passes_in_each_setting(capsys):
    default = _run(capsys)
    assert default[0] == 0
    corpora = {}
    for options in (["--round-amounts"], ["--round-amounts", "--round-figures", "list"], ["--cut-cell-amounts"],
                    ["--cut-cell-amounts", "--round-figures", "list"], ["--cut-cell-amounts", "--match", "digits"],
                    ["--match", "digits"]):
        code, fingerprint, _ = _run(capsys, *options)
        assert code == 0, options
        corpora[tuple(options)] = fingerprint
    assert corpora[("--match", "digits")] == default[1]  # the match mode screens; it writes nothing else
    assert corpora[("--cut-cell-amounts", "--match", "digits")] == corpora[("--cut-cell-amounts",)]
    assert len({default[1], corpora[("--round-amounts",)], corpora[("--cut-cell-amounts",)]}) == 3
    assert _run(capsys)[1] == default[1]  # a profile's draws are made only when it is set
    edge = _run(capsys, "--edge-spellings")
    assert edge[0] == 0 and edge[1] != default[1] and "edge shape accepted 0" in edge[2]
    hidden = _run(capsys, "--hidden-marks")
    assert hidden[0] == 0 and hidden[1] != default[1] and "hidden mark accepted 0" in hidden[2]


def _capped_runs(amount, most=7):  # every run of at most `most` cut pieces, none longer
    pieces = amount.split(",")
    return ["".join(pieces[first:last]) for first in range(len(pieces))
            for last in range(first + 2, min(first + most, len(pieces)) + 1) if last - first < len(pieces)]


@pytest.mark.parametrize("defect", ["longest-join-only", "silent-cap"])
def test_the_cut_cell_profile_catches_both_earlier_readings_and_the_default_corpus_does_not(capsys, monkeypatch,
                                                                                            defect):
    if defect == "longest-join-only":  # a cut amount read whole, no shorter run of its cells listed
        monkeypatch.setattr(figure_sources, "_cut_runs", lambda amount: [])
    else:  # runs of up to seven cells listed, a longer cut amount read anyway, its longer runs dropped
        monkeypatch.setattr(figure_sources, "_MAX_RUN_PIECES", 10 ** 6)
        monkeypatch.setattr(figure_sources, "_cut_runs", _capped_runs)
    assert _run(capsys, files="240")[0] == 0
    code, _, shown = _run(capsys, "--cut-cell-amounts", files="240")
    assert code == 1 and "files missing a figure 0" not in shown


@pytest.mark.parametrize("defect", ["footnote", "date", "encoding", "look-alike"])
def test_the_edge_spelling_profile_catches_each_earlier_reading(capsys, monkeypatch, defect):
    import codecs

    from finassist import figure_source_marks
    if defect == "footnote":  # `(98 765 432)` read as `(98 765` and a footnote
        monkeypatch.setattr(figure_sources, "_SPACED_NOTE", figure_sources.re.compile(r"(?!)"))
    elif defect == "date":  # every whole number of eight digits that names a day left out, however written
        real = figure_sources._classify
        monkeypatch.setattr(figure_sources, "_classify", lambda readings, min_digits, values, forms, rounds, bare=False:
                            real(readings, min_digits, values, forms, rounds, True))
    elif defect == "encoding":  # any file that is not UTF-8 read as Windows-1252
        def decode(raw):
            if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                return raw.decode("utf-16", errors="replace")
            try:
                return raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                return raw.decode("cp1252", errors="replace")
        monkeypatch.setattr(figure_sources, "decode_source", decode)
    else:  # a look-alike of a mark read as a letter
        monkeypatch.setattr(figure_source_marks, "_look_alike", lambda character: False)
    code, _, shown = _run(capsys, "--edge-spellings", files="240")
    assert code == 1, defect
