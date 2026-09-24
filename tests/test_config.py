from __future__ import annotations

from datetime import timedelta

import pytest

from listbot.config import (
    ConfigError,
    RunConfig,
    VALID_FEED_USAGE_PROFILES,
    default_iprep_feed_config,
    enabled_iprep_feeds,
    load_run_config,
    merge_run_config,
    parse_cache_max_age,
    parse_file_mode,
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

    assert config.run.output_dir == "/tmp/listbot"
    assert config.run.workers == 4
    assert config.run.timeout == 12.5
    assert config.run.cve_url == "https://example.test/sid-msg.map"
    assert config.thresholds.enabled is True
    assert config.thresholds.min_cve == 7000
    assert config.thresholds.min_iprep == 300000
    assert config.logging.enabled is True
    assert config.logging.dir == "/var/log/listbot"
    assert config.cache.enabled is True
    assert config.cache.dir == "/var/cache/listbot"
    assert config.cache.max_age == "2d"
    assert config.feeds.usage_profile == "all"
    assert config.feeds.iprep == default_iprep_feed_config()


def test_default_run_config_enables_cache() -> None:
    config = RunConfig()

    assert config.run.output_dir == "."
    assert config.run.workers == 8
    assert config.run.timeout == 30.0
    assert config.cache.enabled is True
    assert config.cache.dir == ".cache/listbot"
    assert config.cache.max_age == "6h"
    assert config.feeds.usage_profile == "all"
    assert config.feeds.iprep == default_iprep_feed_config()


def test_run_config_is_frozen() -> None:
    config = RunConfig()

    with pytest.raises(Exception, match="frozen"):
        config.run.output_dir = "changed"  # type: ignore[misc]


def test_cache_can_be_disabled_in_config() -> None:
    config = parse_run_config(_config_data("cache", {"enabled": False}))

    assert config.cache.enabled is False


def test_cli_values_override_config() -> None:
    config = merge_run_config(
        parse_run_config(_config_data(run={"output_dir": "from-config", "workers": 2}, thresholds={"enabled": False})),
        output_dir="from-cli",
        workers=9,
        check_thresholds=True,
        min_iprep=42,
        cache_enabled=False,
        cache_dir="from-cli-cache",
        cache_max_age="30m",
    )

    assert config.run.output_dir == "from-cli"
    assert config.run.workers == 9
    assert config.thresholds.enabled is True
    assert config.thresholds.min_iprep == 42
    assert config.cache.enabled is False
    assert config.cache.dir == "from-cli-cache"
    assert config.cache.max_age == "30m"


def test_no_log_disables_configured_logging() -> None:
    config = merge_run_config(
        parse_run_config(_config_data(logging={"enabled": True, "dir": "/var/log/listbot"})),
        no_log=True,
    )

    assert config.logging.enabled is False
    assert config.logging.dir is None


def test_bz2_dir_is_disabled_by_default() -> None:
    assert RunConfig().run.bz2_dir is None


def test_bz2_dir_is_read_from_config() -> None:
    config = parse_run_config(_config_data(run={"bz2_dir": "/srv/listbot/public"}))

    assert config.run.bz2_dir == "/srv/listbot/public"


def test_cli_bz2_dir_overrides_config() -> None:
    config = merge_run_config(parse_run_config(_config_data(run={"bz2_dir": "from-config"})), bz2_dir="from-cli")

    assert config.run.bz2_dir == "from-cli"


def test_merge_keeps_configured_bz2_dir() -> None:
    config = merge_run_config(parse_run_config(_config_data(run={"bz2_dir": "from-config"})))

    assert config.run.bz2_dir == "from-config"


def test_no_bz2_dir_disables_configured_bz2_dir() -> None:
    config = merge_run_config(parse_run_config(_config_data(run={"bz2_dir": "from-config"})), no_bz2_dir=True)

    assert config.run.bz2_dir is None


def test_file_mode_defaults_to_0644() -> None:
    assert RunConfig().run.file_mode == "0644"


def test_file_mode_is_read_from_config_and_overridden_by_cli() -> None:
    config = parse_run_config(_config_data(run={"file_mode": "0640"}))

    assert config.run.file_mode == "0640"
    assert merge_run_config(config).run.file_mode == "0640"
    assert merge_run_config(config, file_mode="0600").run.file_mode == "0600"


@pytest.mark.parametrize(("value", "expected"), [("0644", 0o644), ("640", 0o640), ("0600", 0o600)])
def test_parse_file_mode(value: str, expected: int) -> None:
    assert parse_file_mode(value) == expected


@pytest.mark.parametrize("value", ["0888", "4755", "64", "rw-r--r--", "", "00644"])
def test_invalid_file_mode_is_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="File mode"):
        parse_file_mode(value)


def test_config_rejects_invalid_file_mode() -> None:
    with pytest.raises(ConfigError, match="File mode"):
        parse_run_config(_config_data(run={"file_mode": "0888"}))


def test_unknown_config_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match="Extra inputs"):
        parse_run_config(_config_data("publish", {"dir": "out"}))


def test_unknown_cache_keys_are_rejected() -> None:
    with pytest.raises(ConfigError, match="Extra inputs"):
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

    with pytest.raises(ConfigError, match="valid boolean"):
        parse_run_config(_config_data("feeds", {"iprep": feeds}))


@pytest.mark.parametrize(
    ("section", "values", "match"),
    [
        ("run", {"workers": "4"}, "valid integer"),
        ("thresholds", {"min_cve": True}, "valid integer"),
        ("cache", {"enabled": "true"}, "valid boolean"),
        ("run", {"timeout": "12.5"}, "valid number"),
        ("run", {"timeout": True}, "valid number"),
        ("run", {"output_dir": 12}, "valid string"),
        ("run", {"bz2_dir": 1}, "valid string"),
        ("run", {"file_mode": 644}, "valid string"),
        ("cache", {"cache_max_age": 6}, "valid string"),
    ],
)
def test_config_rejects_type_coercion(section: str, values: dict[str, object], match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        parse_run_config(_config_data(section, values))


def test_config_rejects_invalid_cache_max_age() -> None:
    with pytest.raises(ConfigError, match="positive duration"):
        parse_run_config(_config_data("cache", {"cache_max_age": "0h"}))


def test_disabled_iprep_feed_is_not_selected() -> None:
    feeds = default_iprep_feed_config()
    feeds["feodotracker"] = False
    config = parse_run_config(_config_data("feeds", {"iprep": feeds}))

    assert "feodotracker" not in {feed.name for feed in enabled_iprep_feeds(config)}


@pytest.mark.parametrize("profile", sorted(VALID_FEED_USAGE_PROFILES))
def test_valid_feed_usage_profiles_are_accepted(profile: str) -> None:
    config = parse_run_config(_config_data("feeds", {"usage_profile": profile, "iprep": default_iprep_feed_config()}))

    assert config.feeds.usage_profile == profile


def test_invalid_feed_usage_profile_is_rejected() -> None:
    with pytest.raises(ConfigError, match="Input should be 'all'"):
        parse_run_config(
            _config_data("feeds", {"usage_profile": "enterprise", "iprep": default_iprep_feed_config()})
        )


def test_commercial_profile_selects_only_unrestricted_feeds() -> None:
    config = parse_run_config(
        _config_data("feeds", {"usage_profile": "commercial", "iprep": default_iprep_feed_config()})
    )

    assert {feed.name for feed in enabled_iprep_feeds(config)} == {
        "feodotracker",
        "maltrail_mass_scanner",
        "ipsum_level3",
    }


def test_non_commercial_profile_selects_unrestricted_and_non_commercial_feeds() -> None:
    config = parse_run_config(
        _config_data("feeds", {"usage_profile": "non-commercial", "iprep": default_iprep_feed_config()})
    )

    assert {feed.name for feed in enabled_iprep_feeds(config)} == {
        "feodotracker",
        "maltrail_mass_scanner",
        "firehol_dshield",
        "dshield",
        "ipsum_level3",
        "bitwire_outbound",
        "turris",
    }


def test_all_profile_respects_individual_feed_switches() -> None:
    feeds = default_iprep_feed_config()
    feeds["feodotracker"] = False
    config = parse_run_config(_config_data("feeds", {"usage_profile": "all", "iprep": feeds}))

    selected = {feed.name for feed in enabled_iprep_feeds(config)}
    assert "feodotracker" not in selected
    assert selected == {feed_id for feed_id, enabled in feeds.items() if enabled}


def test_usage_profile_respects_individual_feed_switches() -> None:
    feeds = default_iprep_feed_config()
    feeds["ipsum_level3"] = False
    config = parse_run_config(_config_data("feeds", {"usage_profile": "commercial", "iprep": feeds}))

    assert {feed.name for feed in enabled_iprep_feeds(config)} == {"feodotracker", "maltrail_mass_scanner"}


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
    config_path.write_text(
        f"[run]\noutput_dir = \"out\"\n\n[feeds]\nusage_profile = \"commercial\"\n\n[feeds.iprep]\n{feed_lines}\n",
        encoding="utf-8",
    )

    config = load_run_config(config_path)
    assert config.run.output_dir == "out"
    assert config.feeds.usage_profile == "commercial"


def _config_data(section: str | None = None, values: object | None = None, **sections: object) -> dict[str, object]:
    data: dict[str, object] = {"feeds": {"iprep": default_iprep_feed_config()}}
    if section is not None:
        data[section] = values
    data.update(sections)
    return data
