import json

from finassist.cli import main
from finassist.render import report_html


def test_demo_doctor_and_configuration(tmp_path, capsys):
    assert main(["demo"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    assert main(["doctor"]) == 0
    assert json.loads(capsys.readouterr().out)["provider"] == "offline"
    config = tmp_path / "config.json"
    assert main(["init", "--output", str(config)]) == 0
    assert config.exists()
    assert main(["init", "--output", str(config)]) == 2


def test_plan_and_offline_review_are_distinct_from_test_success(repository, tmp_path, capsys):
    repo, base, head = repository
    packet = tmp_path / "packet.json"
    report = tmp_path / "report.json"
    assert main(["plan", "--repo", str(repo), "--base", base, "--head", head, "--output", str(packet)]) == 0
    capsys.readouterr()
    assert main(["review", "--packet", str(packet), "--output", str(report)]) == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["status"] == "offline-analysis" and not result["merge_authority"]


def test_html_escapes_model_markup():
    rendered = report_html({"summary": "<script>alert('fictional')</script>"})
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "Content-Security-Policy" in rendered
