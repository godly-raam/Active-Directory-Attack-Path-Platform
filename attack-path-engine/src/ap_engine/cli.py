"""Command-line entry point for the attack-path engine."""

from __future__ import annotations

import argparse
import sys

from .analyze import analyze
from .config import Config
from .report import render, write_reports


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ap-engine",
        description="Ingest BloodHound JSON and rank AD escalation paths.",
    )
    parser.add_argument("--version", action="version", version="ap-engine 0.1.0")

    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="Analyze a BloodHound export.")
    analyze_cmd.add_argument(
        "--bloodhound", "-b", required=True,
        help="Path to a SharpHound zip, a directory of JSON, or a single JSON file.",
    )
    analyze_cmd.add_argument(
        "--owned", "-o", default="",
        help="Comma-separated SAM names to treat as already compromised. "
             "Defaults to every enabled non-admin user.",
    )
    analyze_cmd.add_argument("--out", default="reports", help="Output directory (default: reports).")
    analyze_cmd.add_argument(
        "--format", "-f", default="markdown,html",
        help="Comma-separated output formats: markdown,html,json (default: markdown,html).",
    )
    analyze_cmd.add_argument("--top-n", type=int, default=None, help="Max ranked paths to keep.")
    analyze_cmd.add_argument("--max-depth", type=int, default=None, help="Max path length in hops.")
    analyze_cmd.add_argument("--offline", action="store_true", help="Skip the LLM; deterministic ranking only.")
    analyze_cmd.add_argument("--print", dest="print_report", action="store_true",
                             help="Also print the Markdown report to stdout.")
    analyze_cmd.add_argument("--env-file", default=None, help="Path to a .env file.")
    return parser


def _run_analyze(args: argparse.Namespace) -> int:
    config = Config.from_env(args.env_file)
    if args.offline:
        config.offline = True
    if args.top_n is not None:
        config.top_n = args.top_n
    if args.max_depth is not None:
        config.max_depth = args.max_depth

    owned = _split_csv(args.owned)
    result = analyze(args.bloodhound, config, owned=owned or None)

    formats = _split_csv(args.format) or ["markdown"]
    written = write_reports(result, args.out, formats)

    if args.print_report:
        print(render(result, "markdown"))

    print(
        f"[ap-engine] {result.summary['nodes']} nodes, {result.summary['edges']} edges, "
        f"{result.summary['high_value']} high-value targets"
    )
    print(f"[ap-engine] {len(result.ranked)} ranked path(s), {len(result.findings)} finding(s)")
    print(f"[ap-engine] ranking: {result.llm_model}")
    for path in written:
        print(f"[ap-engine] wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _run_analyze(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
