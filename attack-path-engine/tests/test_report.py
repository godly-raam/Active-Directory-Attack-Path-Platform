import json

import pytest

from ap_engine.analyze import analyze
from ap_engine.config import Config
from ap_engine.report import render, write_reports


def _result(bloodhound_dir):
    return analyze(bloodhound_dir, Config(offline=True))


def test_markdown_report(bloodhound_dir):
    markdown = render(_result(bloodhound_dir), "markdown")
    assert markdown.startswith("# Active Directory Attack-Path Analysis")
    assert "## Ranked escalation paths" in markdown
    assert "## Supporting misconfiguration findings" in markdown
    assert "MITRE ATT&CK" in markdown


def test_html_report(bloodhound_dir):
    html = render(_result(bloodhound_dir), "html")
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "Active Directory Attack-Path Analysis" in html
    assert "</html>" in html


def test_json_report(bloodhound_dir):
    data = json.loads(render(_result(bloodhound_dir), "json"))
    assert data["summary"]["nodes"] > 0
    assert "ranked_paths" in data
    assert data["llm_used"] is False


def test_write_reports_all_formats(bloodhound_dir, tmp_path):
    written = write_reports(_result(bloodhound_dir), str(tmp_path), ["markdown", "html", "json"])
    names = {path.name for path in written}
    assert names == {"attack-path-report.md", "attack-path-report.html", "attack-path-report.json"}
    assert all(path.exists() and path.stat().st_size > 0 for path in written)


def test_unsupported_format_raises(bloodhound_dir):
    with pytest.raises(ValueError):
        render(_result(bloodhound_dir), "pdf")
