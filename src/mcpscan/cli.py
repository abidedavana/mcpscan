"""Command-line interface.

    mcpscan scan --config claude_desktop_config.json
    mcpscan scan --config .mcp.json --server files --json
    mcpscan checks

Exit codes follow linter convention so the scanner drops into CI unchanged:
0 = no FAIL findings, 1 = at least one FAIL, 2 = usage or config error.
INFO findings do not affect the exit code — they are review flags, not
verdicts, and failing CI on heuristics teaches people to ignore the tool.
"""

from __future__ import annotations

import argparse
import sys

from . import SPEC_VERSION, __version__
from .checks import all_checks
from .findings import Verdict
from .report import render_console, to_json
from .runner import scan
from .target import ConfigError, load_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description="Defensive posture scanner for MCP servers — detection and remediation only.",
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__} (spec {SPEC_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan the servers in a client-style JSON config")
    scan_p.add_argument("--config", required=True, help="path to a config with an mcpServers mapping")
    scan_p.add_argument("--server", action="append", default=None, help="only scan this server name (repeatable)")
    scan_p.add_argument("--json", action="store_true", dest="as_json", help="emit a machine-readable JSON report")
    scan_p.add_argument("--all", action="store_true", dest="show_all", help="also show NA findings in console output")

    sub.add_parser("checks", help="list the implemented checks")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        targets = load_targets(args.config)
    except (ConfigError, OSError) as e:
        print(f"mcpscan: {e}", file=sys.stderr)
        return 2
    if args.server:
        unknown = set(args.server) - {t.name for t in targets}
        if unknown:
            print(f"mcpscan: no such server(s) in config: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        targets = [t for t in targets if t.name in set(args.server)]

    findings = scan(targets)
    print(to_json(findings) if args.as_json else render_console(findings, show_all=args.show_all))
    return 1 if any(f.verdict is Verdict.FAIL for f in findings) else 0


def _cmd_checks() -> int:
    # ASCII only: console output must survive Windows codepages and log pipelines.
    print(f"mcpscan {__version__} - implemented checks (catalogue: CHECKS-v0.1.md, spec {SPEC_VERSION})\n")
    for c in all_checks():
        transports = "/".join(c.applies_to)
        print(f"  {c.id}")
        print(f"      {c.title}")
        print(f"      severity: {c.severity.value} | transports: {transports} | grounding: {c.grounding.value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    return _cmd_checks()


def main_entry() -> None:  # console-script wrapper
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
