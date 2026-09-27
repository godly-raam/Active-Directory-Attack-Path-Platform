import json

from ap_engine.cli import main


def test_cli_offline_json(bloodhound_dir, tmp_path, capsys):
    code = main(["analyze", "-b", bloodhound_dir, "--offline", "--out", str(tmp_path), "-f", "json"])
    assert code == 0
    report = tmp_path / "attack-path-report.json"
    assert report.exists()
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["llm_used"] is False
    assert "ranked_paths" in data


def test_cli_default_formats(bloodhound_dir, tmp_path):
    code = main(["analyze", "-b", bloodhound_dir, "--offline", "--out", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "attack-path-report.md").exists()
    assert (tmp_path / "attack-path-report.html").exists()


def test_cli_owned_filter(bloodhound_dir, tmp_path):
    code = main(
        [
            "analyze",
            "-b",
            bloodhound_dir,
            "--offline",
            "--owned",
            "carolclark",
            "--out",
            str(tmp_path),
            "-f",
            "markdown",
        ]
    )
    assert code == 0
    body = (tmp_path / "attack-path-report.md").read_text(encoding="utf-8")
    assert "carolclark" in body


def test_cli_print_to_stdout(bloodhound_dir, tmp_path, capsys):
    code = main(
        ["analyze", "-b", bloodhound_dir, "--offline", "--out", str(tmp_path), "-f", "markdown", "--print"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "# Active Directory Attack-Path Analysis" in out
    assert "[ap-engine]" in out


def test_cli_top_n_override(bloodhound_dir, tmp_path):
    code = main(
        ["analyze", "-b", bloodhound_dir, "--offline", "--out", str(tmp_path), "-f", "json", "--top-n", "1"]
    )
    assert code == 0
    data = json.loads((tmp_path / "attack-path-report.json").read_text(encoding="utf-8"))
    assert len(data["ranked_paths"]) <= 1
