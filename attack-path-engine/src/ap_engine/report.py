"""Render analysis results to Markdown and HTML."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .analyze import AnalysisResult

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(result: AnalysisResult, fmt: str = "markdown") -> str:
    env = _environment()
    if fmt in ("markdown", "md"):
        return env.get_template("report.md.j2").render(result=result)
    if fmt == "html":
        return env.get_template("report.html.j2").render(result=result)
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2)
    raise ValueError(f"Unsupported format: {fmt}")


_EXTENSIONS = {"markdown": "md", "md": "md", "html": "html", "json": "json"}


def write_reports(result: AnalysisResult, outdir: str, formats: list[str]) -> list[Path]:
    target = Path(outdir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        content = render(result, fmt)
        path = target / f"attack-path-report.{_EXTENSIONS[fmt]}"
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
