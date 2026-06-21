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

from .config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_MAX_AGE,
    DEFAULT_CONFIG_PATH,
    ConfigError,
    RunConfig,
    VALID_FEED_USAGE_PROFILES,
    enabled_iprep_feeds,
    load_run_config,
    merge_run_config,
    parse_cache_max_age,
)
from .feeds import DEFAULT_SURICATA_VERSION
from .generators import BuildResult, build_cve_map, build_iprep_map, evaluate_thresholds, run_all


class ListbotHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 34)
        super().__init__(*args, **kwargs)

    def _get_help_string(self, action: argparse.Action) -> str:
        help_text = action.help or ""
        if "%(default)" in help_text:
            return help_text
        if not action.option_strings:
            return help_text
        if action.default is argparse.SUPPRESS or action.default is None:
            return help_text
        return f"{help_text} (default: %(default)s)"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    try:
        _print_banner(console)

        if args.command == "gen-iprep":
            settings = _config_from_args(args)
            with _progress(console) as progress:
                result = build_iprep_map(
                    Path(settings.output_dir),
                    feeds=enabled_iprep_feeds(settings),
                    workers=settings.workers,
                    timeout=settings.timeout,
                    progress=progress,
                    cache_enabled=settings.cache_enabled,
                    cache_dir=Path(settings.cache_dir),
                    cache_max_age=settings.cache_max_age,
                )
            _print_iprep_summary(console, result)
            return 0

        if args.command == "gen-cve":
            settings = _config_from_args(args)
            with _progress(console) as progress:
                result = build_cve_map(
                    Path(settings.output_dir),
                    url=settings.cve_url,
                    suricata_version=settings.suricata_version,
                    timeout=settings.timeout,
                    progress=progress,
                    cache_enabled=settings.cache_enabled,
                    cache_dir=Path(settings.cache_dir),
                    cache_max_age=settings.cache_max_age,
                )
            _print_cve_summary(console, result)
            return 0

        if args.command == "run":
            settings = _config_from_args(args)
            with _progress(console) as progress:
                cve_result, iprep_result, message, ok = run_all(
                    Path(settings.output_dir),
                    feeds=enabled_iprep_feeds(settings),
                    workers=settings.workers,
                    timeout=settings.timeout,
                    suricata_version=settings.suricata_version,
                    cve_url=settings.cve_url,
                    thresholds_enabled=settings.thresholds_enabled,
                    min_cve=settings.min_cve,
                    min_iprep=settings.min_iprep,
                    logging_enabled=settings.logging_enabled,
                    log_dir=Path(settings.log_dir) if settings.log_dir else None,
                    progress=progress,
                    cache_enabled=settings.cache_enabled,
                    cache_dir=Path(settings.cache_dir),
                    cache_max_age=settings.cache_max_age,
                )
            console.print(_panel(message, title="Run Status", style="cyan" if ok else "red"))
            if settings.thresholds_enabled:
                _print_threshold_summary(
                    console,
                    cve_result.count,
                    iprep_result.count,
                    min_cve=settings.min_cve,
                    min_iprep=settings.min_iprep,
                )
            _print_cve_summary(console, cve_result)
            _print_iprep_summary(console, iprep_result)
            return 0 if ok else 1

    except KeyboardInterrupt:
        Console(stderr=True).print("[yellow]Interrupted.[/yellow]")
        return 130
    except ConfigError as exc:
        Console(stderr=True).print(f"[bold red]CONFIG ERROR:[/bold red] {exc}")
        return 2
    except Exception as exc:
        Console(stderr=True).print(f"[bold red]ERROR:[/bold red] {exc}")
        return 1

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="listbot",
        description="Generate Logstash-style CVE and IPv4 reputation translation maps.",
        epilog=(
            "Examples:\n"
            "  listbot run --output-dir /var/lib/listbot\n"
            "  listbot run --config config.toml --output-dir /var/lib/listbot\n"
            "  listbot gen-cve --config config.toml --output-dir .\n"
            "  listbot gen-iprep --config config.toml --output-dir .\n\n"
            "Use 'listbot COMMAND --help' for command-specific options."
        ),
        formatter_class=ListbotHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True, title="commands", metavar="COMMAND")

    iprep = subparsers.add_parser(
        "gen-iprep",
        help="Generate iprep.yaml, iprep.yaml.bz2, and NOTICE",
        description="Generate only the IPv4 reputation map and its NOTICE attribution file.",
        epilog=(
            "Cache is enabled by default. Use --no-cache to force live downloads.\n\n"
            "If ./config.toml exists, it is loaded automatically. Use --config to select another file.\n\n"
            "Example:\n  listbot gen-iprep --config config.toml --output-dir /var/lib/listbot --workers 12"
        ),
        formatter_class=ListbotHelpFormatter,
    )
    _add_config_arg(iprep)
    _add_output_arg(iprep, uses_config=True)
    _add_network_args(iprep, uses_config=True)
    _add_cache_args(iprep, uses_config=True)

    cve = subparsers.add_parser(
        "gen-cve",
        help="Generate cve.yaml, cve.yaml.bz2, and NOTICE",
        description="Generate only the Emerging Threats SID-to-CVE/CAN map and its NOTICE attribution file.",
        epilog=(
            "Cache is enabled by default. Use --no-cache to force a fresh sid-msg.map download.\n\n"
            "If ./config.toml exists, it is loaded automatically. Use --config to select another file.\n\n"
            "Example:\n  listbot gen-cve --config config.toml --output-dir /var/lib/listbot --suricata-version 8.0.0"
        ),
        formatter_class=ListbotHelpFormatter,
    )
    _add_config_arg(cve)
    _add_output_arg(cve, uses_config=True)
    _add_cve_args(cve, uses_config=True)
    cve.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        help="HTTP timeout in seconds (default: config or 30.0)",
    )
    _add_cache_args(cve, uses_config=True)

    run = subparsers.add_parser(
        "run",
        help="Generate cve.yaml, iprep.yaml, and NOTICE",
        description=(
            "Generate both maps and NOTICE in one output directory. By default this only writes artifacts; "
            "threshold checks and logs are enabled explicitly by config or CLI options. If ./config.toml "
            "exists, it is loaded automatically."
        ),
        epilog=(
            "Config precedence: CLI > --config/./config.toml > built-in defaults.\n"
            "Cache is enabled by default. Cache ages use m, h, or d suffixes, for example 30m, 6h, 2d.\n"
            "Expired cache entries are deleted before a fresh download is attempted.\n"
            "Logging enables threshold checks. --min-cve and --min-iprep also enable threshold checks.\n\n"
            "Examples:\n"
            "  listbot run --output-dir /var/lib/listbot\n"
            "  listbot run --config config.toml --output-dir /var/lib/listbot\n"
            "  listbot run --output-dir /var/lib/listbot --check-thresholds --min-iprep 200000\n"
            "  listbot run --output-dir /var/lib/listbot --log-dir /var/log/listbot"
        ),
        formatter_class=ListbotHelpFormatter,
    )
    _add_run_args(run)

    return parser


def _add_config_arg(parser: argparse.ArgumentParser) -> None:
    config = parser.add_argument_group("config")
    config.add_argument(
        "--config",
        metavar="PATH",
        help="Explicit TOML config file; otherwise ./config.toml is loaded when present",
    )
    config.add_argument(
        "--feed-usage-profile",
        choices=sorted(VALID_FEED_USAGE_PROFILES),
        metavar="PROFILE",
        help="Filter IPREP feeds by usage profile: all, commercial, or non-commercial (default: config or all)",
    )


def _add_output_arg(parser: argparse.ArgumentParser, *, uses_config: bool) -> None:
    output = parser.add_argument_group("output")
    help_text = "Directory for generated YAML, bz2, and NOTICE files"
    if uses_config:
        help_text += " (default: config or '.')"
    output.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None if uses_config else ".",
        help=help_text,
    )


def _add_network_args(parser: argparse.ArgumentParser, *, uses_config: bool) -> None:
    network = parser.add_argument_group("network")
    workers_help = "Concurrent IP feed downloads"
    timeout_help = "HTTP timeout in seconds"
    if uses_config:
        workers_help += " (default: config or 8)"
        timeout_help += " (default: config or 30.0)"
    network.add_argument("--workers", metavar="N", type=int, default=None if uses_config else 8, help=workers_help)
    network.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=None if uses_config else 30.0,
        help=timeout_help,
    )


def _add_cve_args(parser: argparse.ArgumentParser, *, uses_config: bool) -> None:
    cve = parser.add_argument_group("cve source")
    version_help = "Emerging Threats Open Suricata ruleset version"
    cve_url_help = "Override URL for sid-msg.map"
    if uses_config:
        version_help += f" (default: config or {DEFAULT_SURICATA_VERSION})"
        cve_url_help += " (default: config or ET Open URL)"
    cve.add_argument(
        "--suricata-version",
        metavar="VERSION",
        default=None if uses_config else DEFAULT_SURICATA_VERSION,
        help=version_help,
    )
    cve.add_argument("--cve-url", metavar="URL", help=cve_url_help)


def _add_cache_args(parser: argparse.ArgumentParser, *, uses_config: bool) -> None:
    cache_dir_help = "Directory for cached raw downloads and metadata"
    cache_max_age_help = "Refresh cache entries after this age; supported suffixes: m, h, d"
    if uses_config:
        cache_dir_help += f" (default: config or {DEFAULT_CACHE_DIR})"
        cache_max_age_help += f" (default: config or {DEFAULT_CACHE_MAX_AGE})"
    cache = parser.add_argument_group("cache")
    cache_switch = cache.add_mutually_exclusive_group()
    cache_switch.add_argument(
        "--cache",
        dest="cache_enabled",
        action="store_true",
        default=None,
        help="Enable local raw-download cache",
    )
    cache_switch.add_argument(
        "--no-cache",
        dest="cache_enabled",
        action="store_false",
        default=None,
        help="Disable local raw-download cache and force live downloads",
    )
    cache.add_argument(
        "--cache-dir",
        metavar="PATH",
        default=None if uses_config else DEFAULT_CACHE_DIR,
        help=cache_dir_help,
    )
    cache.add_argument(
        "--cache-max-age",
        metavar="DURATION",
        type=_cache_max_age_arg,
        default=None if uses_config else DEFAULT_CACHE_MAX_AGE,
        help=cache_max_age_help,
    )


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    _add_config_arg(parser)

    output = parser.add_argument_group("output")
    output.add_argument(
        "--output-dir",
        metavar="PATH",
        help="Directory for generated YAML, bz2, and NOTICE files (default: config or '.')",
    )

    network = parser.add_argument_group("network")
    network.add_argument("--workers", metavar="N", type=int, help="Concurrent IP feed downloads (default: config or 8)")
    network.add_argument("--timeout", metavar="SECONDS", type=float, help="HTTP timeout in seconds (default: config or 30.0)")

    cve = parser.add_argument_group("cve source")
    cve.add_argument(
        "--suricata-version",
        metavar="VERSION",
        help=f"Emerging Threats Open Suricata ruleset version (default: config or {DEFAULT_SURICATA_VERSION})",
    )
    cve.add_argument("--cve-url", metavar="URL", help="Override URL for sid-msg.map (default: config or ET Open URL)")

    _add_cache_args(parser, uses_config=True)

    thresholds = parser.add_argument_group("threshold checks")
    thresholds.add_argument(
        "--check-thresholds",
        action="store_true",
        default=None,
        help="Enable minimum count checks without enabling logs",
    )
    thresholds.add_argument(
        "--min-cve",
        metavar="N",
        type=int,
        help="Minimum CVE mappings for a successful checked run; also enables checks (default: config or 5000)",
    )
    thresholds.add_argument(
        "--min-iprep",
        metavar="N",
        type=int,
        help="Minimum IP reputation mappings for a successful checked run; also enables checks (default: config or 200000)",
    )

    logging = parser.add_argument_group("logging")
    logging.add_argument(
        "--log-dir",
        metavar="PATH",
        help="Directory for run.log/error.log; enables logging and threshold checks (default: output-dir)",
    )
    logging.add_argument("--no-log", action="store_true", default=None, help="Disable logging configured in --config")


def _config_from_args(args: argparse.Namespace) -> RunConfig:
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH if DEFAULT_CONFIG_PATH.exists() else None
    config = load_run_config(config_path) if config_path is not None else RunConfig()
    return merge_run_config(
        config,
        output_dir=getattr(args, "output_dir", None),
        workers=getattr(args, "workers", None),
        timeout=getattr(args, "timeout", None),
        suricata_version=getattr(args, "suricata_version", None),
        cve_url=getattr(args, "cve_url", None),
        check_thresholds=getattr(args, "check_thresholds", None),
        min_cve=getattr(args, "min_cve", None),
        min_iprep=getattr(args, "min_iprep", None),
        log_dir=getattr(args, "log_dir", None),
        no_log=getattr(args, "no_log", None),
        cache_enabled=getattr(args, "cache_enabled", None),
        cache_dir=getattr(args, "cache_dir", None),
        cache_max_age=getattr(args, "cache_max_age", None),
        feed_usage_profile=getattr(args, "feed_usage_profile", None),
    )


def _run_config_from_args(args: argparse.Namespace) -> RunConfig:
    return _config_from_args(args)


def _cache_enabled_from_args(args: argparse.Namespace) -> bool:
    return True if args.cache_enabled is None else args.cache_enabled


def _cache_max_age_arg(value: str) -> str:
    try:
        parse_cache_max_age(value)
    except ConfigError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


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
    if result.notice_output is not None:
        body += f"\n[dim]NOTICE:[/dim] {result.notice_output}"
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
    if result.notice_output is not None:
        body += f"\n[dim]NOTICE:[/dim] {result.notice_output}"
    console.print(_panel(body, title="IP Reputation Map", style="green" if not errors else "yellow"))

    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, title=None)
    table.add_column("Feed", style="cyan", no_wrap=True)
    table.add_column("Tag", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Extracted", justify="right")
    table.add_column("Added", justify="right")
    table.add_column("Error")
    for stat in sorted(result.stats, key=lambda item: item.added, reverse=True):
        is_ok = stat.status == "ok"
        status = "[bold green]ok[/bold green]" if is_ok else f"[bold red]{stat.status}[/bold red]"
        extracted = f"{stat.extracted:,}" if is_ok else "-"
        added = f"[green]{stat.added:,}[/green]" if is_ok else "-"
        error = "" if is_ok else f"[red]{stat.error or 'unknown error'}[/red]"
        table.add_row(stat.name, stat.tag, status, extracted, added, error)
    console.print(_panel(table, title="Feed Contributions", style="green" if not errors else "yellow"))


def _print_threshold_summary(
    console: Console,
    cve_count: int,
    iprep_count: int,
    *,
    min_cve: int,
    min_iprep: int,
) -> None:
    results = evaluate_thresholds(cve_count, iprep_count, min_cve=min_cve, min_iprep=min_iprep)
    failed = [result for result in results if not result.ok]
    title = "Threshold Check Failed" if failed else "Threshold Check Passed"
    style = "red" if failed else "green"
    headline = Text(
        "Minimum counts were not reached." if failed else "All configured minimum counts were reached.",
        style=f"bold {style}",
    )

    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, title=None)
    table.add_column("Map", style="cyan", no_wrap=True)
    table.add_column("Actual", justify="right")
    table.add_column("Minimum", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Missing", justify="right")
    for result in results:
        status = "[bold green]OK[/bold green]" if result.ok else "[bold red]FAIL[/bold red]"
        missing = "-" if result.ok else f"[bold red]{result.missing:,}[/bold red]"
        actual = f"[bold green]{result.actual:,}[/bold green]" if result.ok else f"[bold red]{result.actual:,}[/bold red]"
        table.add_row(result.name, actual, f"{result.minimum:,}", status, missing)

    console.print(_panel(Group(headline, table), title=title, style=style))


if __name__ == "__main__":
    raise SystemExit(main())
