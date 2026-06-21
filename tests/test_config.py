from __future__ import annotations

from datetime import timedelta

import pytest

from listbot.config import (
    ConfigError,
    RunConfig,
    default_iprep_feed_config,
    enabled_iprep_feeds,
    load_run_config,
    merge_run_config,
    parse_cache_max_age,
    parse_run_config,
)


def test_parse_run_config_reads_toml_schema() -> None:
    config = parse_run_config(
        _config_data(
            run={
                "output_dir": "/tmp/listbot",
                "workers": 4,
                "timeout": 12.5,
                "suricata_version": "8.0.0",
                "cve_url": "https://example.test/sid-msg.map",
            },
            cache={"enabled": True, "cache_dir": "/var/cache/listbot", "cache_max_age": "2d"},
            thresholds={"enabled": True, "min_cve": 7000, "min_iprep": 300000},
            logging={"enabled": True, "dir": "/var/log/listbot"},
        )
    )

    assert config.output_dir == "/tmp/listbot"
    assert config.workers == 4
    assert config.timeout == 12.5
    assert config.cve_url == "https://example.test/sid-msg.map"
    assert config.thresholds_enabled is True
    assert config.min_cve == 7000
    assert config.min_iprep == 300000
    assert config.logging_enabled is True
    assert config.log_dir == "/var/log/listbot"
    assert config.cache_enabled is True
    assert config.cache_dir == "/var/cache/listbot"
    assert config.cache_max_age == "2d"
    assert config.iprep_feeds == default_iprep_feed_config()


def test_default_run_config_enables_cache() -> None:
    config = RunConfig()

    assert config.cache_enabled is True
    assert config.cache_dir == ".cache/listbot"
    assert config.cache_max_age == "6h"


def test_cache_can_be_disabled_in_config() -> None:
    config = parse_run_config(_config_data("cache", {"enabled": False}))

    assert config.cache_enabled is False


def test_cli_values_override_config() -> None:
    config = merge_run_config(
        RunConfig(output_dir="from-config", workers=2, thresholds_enabled=False),
        output_dir="from-cli",
        workers=9,
        check_thresholds=True,
        min_iprep=42,
        cache_enabled=False,
        cache_dir="from-cli-cache",
        cache_max_age="30m",
    )

    assert config.output_dir == "from-cli"
    assert config.workers == 9
    assert config.thresholds_enabled is True
    assert config.min_iprep == 42
    assert config.cache_enabled is False
    assert config.cache_dir == "from-cli-cache"
    assert config.cache_max_age == "30m"


def test_no_log_disables_configured_logging() -> None:
    config = merge_run_config(
        RunConfig(logging_enabled=True, log_dir="/var/log/listbot"),
        no_log=True,
    )

    assert config.logging_enabled is False
    assert config.log_dir is None


def test_unknown_config_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown key"):
        parse_run_config(_config_data("publish", {"dir": "out"}))


def test_unknown_cache_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown key"):
        parse_run_config(_config_data("cache", {"dir": ".cache/listbot"}))


def test_full_iprep_feed_config_is_required() -> None:
    feeds = default_iprep_feed_config()
    feeds.pop("feodotracker")

    with pytest.raises(ConfigError, match="Missing key\\(s\\) in feeds.iprep: feodotracker"):
        parse_run_config(_config_data("feeds", {"iprep": feeds}))


def test_unknown_iprep_feed_config_is_rejected() -> None:
    feeds = default_iprep_feed_config()
    feeds["unknown_feed"] = True

    with pytest.raises(ConfigError, match="Unknown key\\(s\\) in feeds.iprep: unknown_feed"):
        parse_run_config(_config_data("feeds", {"iprep": feeds}))


def test_iprep_feed_config_values_must_be_boolean() -> None:
    feeds = default_iprep_feed_config()
    feeds["feodotracker"] = "yes"

    with pytest.raises(ConfigError, match="feeds.iprep.feodotracker must be a boolean"):
        parse_run_config(_config_data("feeds", {"iprep": feeds}))


def test_disabled_iprep_feed_is_not_selected() -> None:
    feeds = default_iprep_feed_config()
    feeds["feodotracker"] = False
    config = parse_run_config(_config_data("feeds", {"iprep": feeds}))

    assert "feodotracker" not in {feed.name for feed in enabled_iprep_feeds(config)}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30m", timedelta(minutes=30)),
        ("6h", timedelta(hours=6)),
        ("2d", timedelta(days=2)),
    ],
)
def test_parse_cache_max_age(value: str, expected: timedelta) -> None:
    assert parse_cache_max_age(value) == expected


@pytest.mark.parametrize("value", ["", "0h", "-1h", "30", "1w", "1H"])
def test_invalid_cache_max_age_is_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="positive duration"):
        parse_cache_max_age(value)


def test_load_run_config_reads_file(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    feed_lines = "\n".join(f"{feed_id} = true" for feed_id in default_iprep_feed_config())
    config_path.write_text(f"[run]\noutput_dir = \"out\"\n\n[feeds.iprep]\n{feed_lines}\n", encoding="utf-8")

    assert load_run_config(config_path).output_dir == "out"


def _config_data(section: str | None = None, values: object | None = None, **sections: object) -> dict[str, object]:
    data: dict[str, object] = {"feeds": {"iprep": default_iprep_feed_config()}}
    if section is not None:
        data[section] = values
    data.update(sections)
    return data
