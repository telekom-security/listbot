from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from .feeds import DEFAULT_SURICATA_VERSION, Feed, IPREP_FEEDS

DEFAULT_CONFIG_PATH = Path("config.toml")
DEFAULT_CACHE_DIR = ".cache/listbot"
DEFAULT_CACHE_MAX_AGE = "6h"
_DURATION_RE = re.compile(r"^([1-9][0-9]*)([mhd])$")
_IPREP_FEED_IDS = tuple(feed.name for feed in IPREP_FEEDS)


class ConfigError(ValueError):
    pass


def default_iprep_feed_config() -> dict[str, bool]:
    return {feed_id: True for feed_id in _IPREP_FEED_IDS}


@dataclass(frozen=True)
class RunConfig:
    output_dir: str = "."
    workers: int = 8
    timeout: float = 30.0
    suricata_version: str = DEFAULT_SURICATA_VERSION
    cve_url: str | None = None
    thresholds_enabled: bool = False
    min_cve: int = 5_000
    min_iprep: int = 200_000
    logging_enabled: bool = False
    log_dir: str | None = None
    cache_enabled: bool = True
    cache_dir: str = DEFAULT_CACHE_DIR
    cache_max_age: str = DEFAULT_CACHE_MAX_AGE
    iprep_feeds: dict[str, bool] = field(default_factory=default_iprep_feed_config)


def load_run_config(path: Path) -> RunConfig:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML config {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read config {path}: {exc}") from exc

    return parse_run_config(data)


def parse_run_config(data: dict[str, Any]) -> RunConfig:
    _reject_unknown("config", data, {"run", "thresholds", "logging", "cache", "feeds"})
    run = _section(data, "run", {"output_dir", "workers", "timeout", "suricata_version", "cve_url"})
    thresholds = _section(data, "thresholds", {"enabled", "min_cve", "min_iprep"})
    logging = _section(data, "logging", {"enabled", "dir"})
    cache = _section(data, "cache", {"enabled", "cache_dir", "cache_max_age"})
    feeds = _section(data, "feeds", {"iprep"})

    return RunConfig(
        output_dir=_str(run, "output_dir", "."),
        workers=_int(run, "workers", 8),
        timeout=_float(run, "timeout", 30.0),
        suricata_version=_str(run, "suricata_version", DEFAULT_SURICATA_VERSION),
        cve_url=_optional_str(run, "cve_url"),
        thresholds_enabled=_bool(thresholds, "enabled", False),
        min_cve=_int(thresholds, "min_cve", 5_000),
        min_iprep=_int(thresholds, "min_iprep", 200_000),
        logging_enabled=_bool(logging, "enabled", False),
        log_dir=_optional_str(logging, "dir"),
        cache_enabled=_bool(cache, "enabled", True),
        cache_dir=_str(cache, "cache_dir", DEFAULT_CACHE_DIR),
        cache_max_age=_duration_str(cache, "cache_max_age", DEFAULT_CACHE_MAX_AGE),
        iprep_feeds=_iprep_feed_config(feeds),
    )


def merge_run_config(
    config: RunConfig,
    *,
    output_dir: str | None = None,
    workers: int | None = None,
    timeout: float | None = None,
    suricata_version: str | None = None,
    cve_url: str | None = None,
    check_thresholds: bool | None = None,
    min_cve: int | None = None,
    min_iprep: int | None = None,
    log_dir: str | None = None,
    no_log: bool | None = None,
    cache_enabled: bool | None = None,
    cache_dir: str | None = None,
    cache_max_age: str | None = None,
) -> RunConfig:
    thresholds_enabled = config.thresholds_enabled
    logging_enabled = config.logging_enabled
    effective_log_dir = config.log_dir

    if check_thresholds:
        thresholds_enabled = True
    if min_cve is not None or min_iprep is not None:
        thresholds_enabled = True
    if log_dir is not None:
        logging_enabled = True
        effective_log_dir = log_dir
    if no_log:
        logging_enabled = False
        effective_log_dir = None

    return RunConfig(
        output_dir=output_dir if output_dir is not None else config.output_dir,
        workers=workers if workers is not None else config.workers,
        timeout=timeout if timeout is not None else config.timeout,
        suricata_version=suricata_version if suricata_version is not None else config.suricata_version,
        cve_url=cve_url if cve_url is not None else config.cve_url,
        thresholds_enabled=thresholds_enabled or logging_enabled,
        min_cve=min_cve if min_cve is not None else config.min_cve,
        min_iprep=min_iprep if min_iprep is not None else config.min_iprep,
        logging_enabled=logging_enabled,
        log_dir=effective_log_dir,
        cache_enabled=cache_enabled if cache_enabled is not None else config.cache_enabled,
        cache_dir=cache_dir if cache_dir is not None else config.cache_dir,
        cache_max_age=_validate_duration(cache_max_age) if cache_max_age is not None else config.cache_max_age,
        iprep_feeds=dict(config.iprep_feeds),
    )


def enabled_iprep_feeds(config: RunConfig) -> tuple[Feed, ...]:
    return tuple(feed for feed in IPREP_FEEDS if config.iprep_feeds[feed.name])


def parse_cache_max_age(value: str) -> timedelta:
    match = _DURATION_RE.fullmatch(value)
    if match is None:
        raise ConfigError("Cache max age must be a positive duration like 30m, 6h, or 2d")

    amount = int(match.group(1))
    unit = match.group(2)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _section(data: dict[str, Any], name: str, allowed_keys: set[str]) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"Config section [{name}] must be a table")
    _reject_unknown(name, value, allowed_keys)
    return value


def _iprep_feed_config(feeds: dict[str, Any]) -> dict[str, bool]:
    if "iprep" not in feeds:
        raise ConfigError("Config section [feeds.iprep] is required")

    iprep = feeds["iprep"]
    if not isinstance(iprep, dict):
        raise ConfigError("Config section [feeds.iprep] must be a table")

    allowed = set(_IPREP_FEED_IDS)
    _reject_unknown("feeds.iprep", iprep, allowed)
    missing = sorted(allowed - set(iprep))
    if missing:
        keys = ", ".join(missing)
        raise ConfigError(f"Missing key(s) in feeds.iprep: {keys}")

    values: dict[str, bool] = {}
    for feed_id in _IPREP_FEED_IDS:
        value = iprep[feed_id]
        if not isinstance(value, bool):
            raise ConfigError(f"Config value feeds.iprep.{feed_id} must be a boolean")
        values[feed_id] = value
    return values


def _reject_unknown(section: str, data: dict[str, Any], allowed_keys: set[str]) -> None:
    unknown = sorted(set(data) - allowed_keys)
    if unknown:
        keys = ", ".join(unknown)
        raise ConfigError(f"Unknown key(s) in {section}: {keys}")


def _str(section: dict[str, Any], key: str, default: str) -> str:
    value = section.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"Config value {key} must be a string")
    return value


def _duration_str(section: dict[str, Any], key: str, default: str) -> str:
    return _validate_duration(_str(section, key, default))


def _validate_duration(value: str) -> str:
    parse_cache_max_age(value)
    return value


def _optional_str(section: dict[str, Any], key: str) -> str | None:
    value = section.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"Config value {key} must be a string")
    return value


def _int(section: dict[str, Any], key: str, default: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"Config value {key} must be an integer")
    return value


def _float(section: dict[str, Any], key: str, default: float) -> float:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"Config value {key} must be a number")
    return float(value)


def _bool(section: dict[str, Any], key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"Config value {key} must be a boolean")
    return value
