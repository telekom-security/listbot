from __future__ import annotations

import argparse
from pathlib import Path

from rich.align import Align
from rich import box
from rich.console import Console
from rich.console import Group
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .feeds import DEFAULT_SURICATA_VERSION
from .generators import BuildResult, build_all_maps, build_cve_map, build_iprep_map, run_all


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    try:
        _print_banner(console)

        if args.command == "gen-iprep":
            with _progress(console) as progress:
                result = build_iprep_map(
                    Path(args.output_dir),
                    workers=args.workers,
                    timeout=args.timeout,
                    progress=progress,
                )
            _print_iprep_summary(console, result)
            return 0

        if args.command == "gen-cve":
            with _progress(console) as progress:
                result = build_cve_map(
                    Path(args.output_dir),
                    url=args.cve_url,
                    suricata_version=args.suricata_version,
                    timeout=args.timeout,
                    progress=progress,
                )
            _print_cve_summary(console, result)
            return 0

        if args.command == "gen-all":
            with _progress(console) as progress:
                cve_result, iprep_result = build_all_maps(
                    Path(args.output_dir),
                    workers=args.workers,
                    timeout=args.timeout,
                    suricata_version=args.suricata_version,
                    cve_url=args.cve_url,
                    progress=progress,
                )
            _print_cve_summary(console, cve_result)
            _print_iprep_summary(console, iprep_result)
            return 0

        if args.command == "run":
            with _progress(console) as progress:
                cve_result, iprep_result, message, ok = run_all(
                    Path(args.output_dir),
                    workers=args.workers,
                    timeout=args.timeout,
                    suricata_version=args.suricata_version,
                    cve_url=args.cve_url,
                    min_cve=args.min_cve,
                    min_iprep=args.min_iprep,
                    publish_dir=Path(args.publish_dir) if args.publish_dir else None,
                    git_push=args.git_push,
                    git_remote=args.git_remote,
                    pushover_token=args.pushover_token,
                    pushover_user=args.pushover_user,
                    log_dir=Path(args.log_dir) if args.log_dir else None,
                    progress=progress,
                )
            console.print(_panel(message, title="Run Status", style="cyan" if ok else "red"))
            _print_cve_summary(console, cve_result)
            _print_iprep_summary(console, iprep_result)
            return 0 if ok else 1

    except KeyboardInterrupt:
        Console(stderr=True).print("[yellow]Interrupted.[/yellow]")
        return 130
    except Exception as exc:
        Console(stderr=True).print(f"[bold red]ERROR:[/bold red] {exc}")
        return 1

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="listbot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    iprep = subparsers.add_parser("gen-iprep", help="Generate iprep.yaml and iprep.yaml.bz2")
    _add_output_arg(iprep)
    _add_network_args(iprep)

    cve = subparsers.add_parser("gen-cve", help="Generate cve.yaml and cve.yaml.bz2")
    _add_output_arg(cve)
    _add_cve_args(cve)
    cve.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")

    all_maps = subparsers.add_parser("gen-all", help="Generate cve.yaml and iprep.yaml")
    _add_output_arg(all_maps)
    _add_network_args(all_maps)
    _add_cve_args(all_maps)

    run = subparsers.add_parser("run", help="Generate both maps and optionally publish them")
    _add_output_arg(run)
    _add_network_args(run)
    _add_cve_args(run)
    run.add_argument("--min-cve", type=int, default=5_000, help="Minimum CVE mappings for a successful run")
    run.add_argument("--min-iprep", type=int, default=200_000, help="Minimum IP reputation mappings for a successful run")
    run.add_argument("--publish-dir", help="Directory that receives generated YAML and bz2 files after a successful run")
    run.add_argument("--git-push", action="store_true", help="Commit and push files in --publish-dir")
    run.add_argument("--git-remote", default="origin", help="Git remote to push when --git-push is set")
    run.add_argument("--pushover-token", help="Pushover token; defaults to PUSHOVER_TOKEN")
    run.add_argument("--pushover-user", help="Pushover user key; defaults to PUSHOVER_USER")
    run.add_argument("--log-dir", help="Directory for run.log/error.log; defaults to --output-dir")

    return parser


def _add_output_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", default=".", help="Directory for generated map files")


def _add_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workers", type=int, default=8, help="Concurrent feed downloads")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")


def _add_cve_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--suricata-version",
        default=DEFAULT_SURICATA_VERSION,
        help="Emerging Threats Open Suricata ruleset version",
    )
    parser.add_argument("--cve-url", help="Override URL for sid-msg.map")


def _progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def _print_banner(console: Console) -> None:
    art = r"""
    __    _      __  __          __
   / /   (_)____/ /_/ /_  ____  / /_
  / /   / / ___/ __/ __ \/ __ \/ __/
 / /___/ (__  ) /_/ /_/ / /_/ / /_
/_____/_/____/\__/_.___/\____/\__/
""".strip("\n")
    subtitle = Text("CVE and IP reputation maps", style="bold green")
    panel = Panel(
        Group(Align.center(Text(art, style="bold cyan")), Align.center(subtitle)),
        border_style="cyan",
        padding=(1, 2),
        expand=True,
    )
    console.print(panel)


def _panel(renderable, *, title: str, style: str = "cyan") -> Panel:
    return Panel(
        renderable,
        title=title,
        border_style=style,
        box=box.ROUNDED,
        expand=True,
    )


def _print_cve_summary(console: Console, result: BuildResult) -> None:
    body = (
        f"[bold green]{result.count:,}[/bold green] CVE IDs mapped\n"
        f"[dim]YAML:[/dim] {result.output}\n"
        f"[dim]BZ2 :[/dim] {result.compressed_output}"
    )
    console.print(_panel(body, title="CVE Map"))


def _print_iprep_summary(console: Console, result: BuildResult) -> None:
    ok = sum(1 for stat in result.stats if stat.status == "ok")
    errors = [stat for stat in result.stats if stat.status != "ok"]
    body = (
        f"[bold green]{result.count:,}[/bold green] IP reputations mapped\n"
        f"[dim]Feeds:[/dim] {ok} ok, {len(errors)} failed\n"
        f"[dim]YAML :[/dim] {result.output}\n"
        f"[dim]BZ2  :[/dim] {result.compressed_output}"
    )
    console.print(_panel(body, title="IP Reputation Map", style="green" if not errors else "yellow"))

    top = sorted((stat for stat in result.stats if stat.status == "ok"), key=lambda stat: stat.added, reverse=True)[:12]
    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, title=None)
    table.add_column("Feed", style="cyan", no_wrap=True)
    table.add_column("Tag", style="magenta")
    table.add_column("Extracted", justify="right")
    table.add_column("Added", justify="right", style="green")
    for stat in top:
        table.add_row(stat.name, stat.tag, f"{stat.extracted:,}", f"{stat.added:,}")
    console.print(_panel(table, title="Top Feed Contributions"))

    if errors:
        error_table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, title=None)
        error_table.add_column("Feed", style="red", no_wrap=True)
        error_table.add_column("Error")
        for stat in errors:
            error_table.add_row(stat.name, stat.error or "unknown error")
        console.print(_panel(error_table, title="Failed Feeds", style="red"))


if __name__ == "__main__":
    raise SystemExit(main())
