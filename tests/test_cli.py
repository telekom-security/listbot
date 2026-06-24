from __future__ import annotations

import pytest
from rich.console import Console

import listbot.cli as cli_module
from listbot.cli import _config_from_args, _print_iprep_summary, _print_threshold_summary, build_parser
from listbot.config import default_iprep_feed_config
from listbot.generators import BuildResult, FeedStat


def test_run_command_parses() -> None:
    args = build_parser().parse_args(
        ["run", "--output-dir", "out", "--workers", "2", "--no-cache", "--feed-usage-profile", "commercial"]
    )

    assert args.command == "run"
    assert args.output_dir == "out"
    assert args.workers == 2
    assert args.cache_enabled is False
    assert args.feed_usage_profile == "commercial"


def test_gen_commands_accept_cache_options() -> None:
    iprep = build_parser().parse_args(
        [
            "gen-iprep",
            "--no-cache",
            "--cache-dir",
            "cache",
            "--cache-max-age",
            "2d",
            "--feed-usage-profile",
            "non-commercial",
        ]
    )
    cve = build_parser().parse_args(["gen-cve", "--cache", "--cache-max-age", "30m", "--feed-usage-profile", "all"])

    assert iprep.cache_enabled is False
    assert iprep.cache_dir == "cache"
    assert iprep.cache_max_age == "2d"
    assert iprep.feed_usage_profile == "non-commercial"
    assert cve.cache_enabled is True
    assert cve.cache_max_age == "30m"
    assert cve.feed_usage_profile == "all"


def test_run_auto_loads_config_toml(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path / "config.toml", run={"output_dir": "from-config"})
    args = build_parser().parse_args(["run"])

    config = _config_from_args(args)

    assert config.output_dir == "from-config"


def test_gen_commands_auto_load_config_toml(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_config(
        tmp_path / "config.toml",
        run={"output_dir": "from-config", "timeout": 12.0, "suricata_version": "8.0.0"},
        cache={"enabled": False},
        usage_profile="commercial",
    )

    iprep_config = _config_from_args(build_parser().parse_args(["gen-iprep"]))
    cve_config = _config_from_args(build_parser().parse_args(["gen-cve"]))

    assert iprep_config.output_dir == "from-config"
    assert iprep_config.timeout == 12.0
    assert iprep_config.cache_enabled is False
    assert iprep_config.feed_usage_profile == "commercial"
    assert cve_config.output_dir == "from-config"
    assert cve_config.suricata_version == "8.0.0"
    assert cve_config.feed_usage_profile == "commercial"


def test_cli_feed_usage_profile_overrides_config(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path / "config.toml", usage_profile="all")

    config = _config_from_args(build_parser().parse_args(["gen-iprep", "--feed-usage-profile", "commercial"]))

    assert config.feed_usage_profile == "commercial"


def test_run_does_not_auto_load_listbot_toml(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "listbot.toml").write_text("[run]\noutput_dir = \"ignored\"\n", encoding="utf-8")
    args = build_parser().parse_args(["run"])

    config = _config_from_args(args)

    assert config.output_dir == "."


def test_gen_all_command_is_removed() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["gen-all", "--output-dir", "out"])


@pytest.mark.parametrize(
    "option",
    ["--publish-dir", "--git-push", "--git-remote", "--pushover-token", "--pushover-user"],
)
def test_removed_run_options_are_rejected(option: str) -> None:
    argv = ["run", option]
    if option not in {"--git-push"}:
        argv.append("value")

    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_top_level_help_points_to_command_help() -> None:
    help_text = build_parser().format_help()

    assert "Generate Logstash-style CVE and IPv4 reputation translation maps." in help_text
    assert "gen-iprep" in help_text
    assert "gen-cve" in help_text
    assert "run" in help_text
    assert "Use 'listbot COMMAND --help'" in help_text
    assert "config.toml" in help_text


def test_run_help_is_grouped_and_explains_config_defaults(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["run", "--help"])

    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "config:" in help_text
    assert "output:" in help_text
    assert "network:" in help_text
    assert "cache:" in help_text
    assert "threshold checks:" in help_text
    assert "logging:" in help_text
    assert "Config precedence: CLI > --config/./config.toml > built-in defaults." in help_text
    assert "Cache is enabled by default." in help_text
    assert "--output-dir PATH" in help_text
    assert "--no-cache" in help_text
    assert "--cache-max-age DURATION" in help_text
    assert "--feed-usage-profile" in help_text
    assert "--check-thresholds" in help_text
    assert "--log-dir PATH" in help_text
    assert "(default: None)" not in help_text


def test_gen_iprep_help_includes_config_and_cache_options(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["gen-iprep", "--help"])

    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "config:" in help_text
    assert "--config PATH" in help_text
    assert "--cache-max-age DURATION" in help_text
    assert "If ./config.toml exists, it is loaded automatically." in help_text


def test_gen_cve_accepts_config_argument() -> None:
    args = build_parser().parse_args(
        ["gen-cve", "--config", "config.toml", "--output-dir", "out", "--feed-usage-profile", "commercial"]
    )

    assert args.command == "gen-cve"
    assert args.config == "config.toml"
    assert args.output_dir == "out"
    assert args.feed_usage_profile == "commercial"


def test_disabled_feed_is_not_passed_to_gen_iprep(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    feed_settings = default_iprep_feed_config()
    feed_settings["feodotracker"] = False
    _write_config(config_path, feeds=feed_settings)
    captured = {}

    def fake_build_iprep_map(output_dir, **kwargs):
        captured["feeds"] = kwargs["feeds"]
        return BuildResult(output=output_dir / "iprep.yaml", compressed_output=output_dir / "iprep.yaml.bz2", count=0)

    monkeypatch.setattr(cli_module, "build_iprep_map", fake_build_iprep_map)

    assert cli_module.main(["gen-iprep", "--config", str(config_path), "--output-dir", str(tmp_path / "out")]) == 0
    assert "feodotracker" not in {feed.name for feed in captured["feeds"]}


def test_disabled_feed_is_not_passed_to_run(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    feed_settings = default_iprep_feed_config()
    feed_settings["feodotracker"] = False
    _write_config(config_path, feeds=feed_settings)
    captured = {}

    def fake_run_all(output_dir, **kwargs):
        captured["feeds"] = kwargs["feeds"]
        cve = BuildResult(output=output_dir / "cve.yaml", compressed_output=output_dir / "cve.yaml.bz2", count=5_000)
        iprep = BuildResult(output=output_dir / "iprep.yaml", compressed_output=output_dir / "iprep.yaml.bz2", count=200_000)
        return cve, iprep, "ok", True

    monkeypatch.setattr(cli_module, "run_all", fake_run_all)

    assert cli_module.main(["run", "--config", str(config_path), "--output-dir", str(tmp_path / "out")]) == 0
    assert "feodotracker" not in {feed.name for feed in captured["feeds"]}


def test_main_returns_1_when_run_thresholds_fail(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    captured = {}

    def fake_run_all(output_dir, **kwargs):
        captured["thresholds_enabled"] = kwargs["thresholds_enabled"]
        cve = BuildResult(output=output_dir / "cve.yaml", compressed_output=output_dir / "cve.yaml.bz2", count=0)
        iprep = BuildResult(output=output_dir / "iprep.yaml", compressed_output=output_dir / "iprep.yaml.bz2", count=1)
        return cve, iprep, "threshold failure", False

    monkeypatch.setattr(cli_module, "run_all", fake_run_all)

    exit_code = cli_module.main(["run", "--output-dir", str(tmp_path / "out"), "--check-thresholds"])

    assert exit_code == 1
    assert captured["thresholds_enabled"] is True


def test_threshold_summary_highlights_failed_minimums() -> None:
    console = Console(record=True, width=100, color_system=None)

    _print_threshold_summary(console, 7_690, 925_740, min_cve=5_000, min_iprep=2_000_000)

    output = console.export_text()
    assert "Threshold Check Failed" in output
    assert "Minimum counts were not reached." in output
    assert "IP reputation map" in output
    assert "1,074,260" in output


def test_iprep_summary_lists_all_feed_contributions(tmp_path) -> None:
    console = Console(record=True, width=140, color_system=None)
    result = BuildResult(
        output=tmp_path / "iprep.yaml",
        compressed_output=tmp_path / "iprep.yaml.bz2",
        count=3,
        stats=[
            FeedStat(
                name="first_feed",
                tag="malware infra",
                status="ok",
                url="https://example.test/1",
                extracted=2,
                added=2,
            ),
            FeedStat(
                name="second_feed",
                tag="web abuse",
                status="ok",
                url="https://example.test/2",
                extracted=5,
                added=5,
            ),
            FeedStat(
                name="failed_feed",
                tag="attack source",
                status="error",
                url="https://example.test/3",
                error="offline",
            ),
        ],
    )

    _print_iprep_summary(console, result)

    output = console.export_text()
    assert "Feed Contributions" in output
    assert "Top Feed Contributions" not in output
    assert "first_feed" in output
    assert "second_feed" in output
    assert "failed_feed" in output
    assert "offline" in output
    assert output.index("second_feed") < output.index("first_feed")


def _write_config(
    path,
    *,
    run: dict[str, object] | None = None,
    cache: dict[str, object] | None = None,
    usage_profile: str | None = None,
    feeds: dict[str, bool] | None = None,
) -> None:
    feed_settings = feeds or default_iprep_feed_config()
    lines = []
    if run:
        lines.append("[run]")
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in run.items())
        lines.append("")
    if cache:
        lines.append("[cache]")
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in cache.items())
        lines.append("")
    if usage_profile is not None:
        lines.append("[feeds]")
        lines.append(f"usage_profile = {_toml_value(usage_profile)}")
        lines.append("")
    lines.append("[feeds.iprep]")
    lines.extend(f"{feed_id} = {str(enabled).lower()}" for feed_id, enabled in feed_settings.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{value}"'
