from __future__ import annotations

import re
import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .feeds import DEFAULT_SURICATA_VERSION, Feed, IPREP_FEEDS

DEFAULT_CONFIG_PATH = Path("config.toml")
DEFAULT_CACHE_DIR = ".cache/listbot"
DEFAULT_CACHE_MAX_AGE = "6h"
_DURATION_RE = re.compile(r"^([1-9][0-9]*)([mhd])$")
_IPREP_FEED_IDS = tuple(feed.name for feed in IPREP_FEEDS)
VALID_FEED_USAGE_PROFILES = frozenset({"all", "commercial", "non-commercial"})
FeedUsageProfile = Literal["all", "commercial", "non-commercial"]


class ConfigError(ValueError):
    pass


def default_iprep_feed_config() -> dict[str, bool]:
    return {feed_id: True for feed_id in _IPREP_FEED_IDS}


class _ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class _RunSection(_ConfigModel):
    output_dir: str = "."
    workers: int = 8
    timeout: float = 30.0
    suricata_version: str = DEFAULT_SURICATA_VERSION
    cve_url: str | None = None


class _CacheSection(_ConfigModel):
    enabled: bool = True
    dir: str = Field(default=DEFAULT_CACHE_DIR, validation_alias="cache_dir")
    max_age: str = Field(default=DEFAULT_CACHE_MAX_AGE, validation_alias="cache_max_age")

    @field_validator("max_age")
    @classmethod
    def _validate_max_age(cls, value: str) -> str:
        parse_cache_max_age(value)
        return value


class _ThresholdsSection(_ConfigModel):
    enabled: bool = True
    min_cve: int = 5_000
    min_iprep: int = 500_000


class _LoggingSection(_ConfigModel):
    enabled: bool = True
    dir: str | None = None


class _FeedsSection(_ConfigModel):
    usage_profile: FeedUsageProfile = "all"
    iprep: dict[str, bool] = Field(default_factory=default_iprep_feed_config)

    @field_validator("iprep")
    @classmethod
    def _validate_iprep(cls, value: dict[str, bool]) -> dict[str, bool]:
        allowed = set(_IPREP_FEED_IDS)
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"Unknown key(s) in feeds.iprep: {', '.join(unknown)}")

        missing = sorted(allowed - set(value))
        if missing:
            raise ValueError(f"Missing key(s) in feeds.iprep: {', '.join(missing)}")

        return {feed_id: value[feed_id] for feed_id in _IPREP_FEED_IDS}


class RunConfig(_ConfigModel):
    run: _RunSection = Field(default_factory=_RunSection)
    cache: _CacheSection = Field(default_factory=_CacheSection)
    thresholds: _ThresholdsSection = Field(default_factory=_ThresholdsSection)
    logging: _LoggingSection = Field(default_factory=_LoggingSection)
    feeds: _FeedsSection = Field(default_factory=_FeedsSection)


def load_run_config(path: Path) -> RunConfig:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"Could not read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML config {path}: {exc}") from exc

    return parse_run_config(data)


def parse_run_config(data: dict[str, Any]) -> RunConfig:
    try:
        return RunConfig.model_validate(data, strict=True)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


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
    feed_usage_profile: str | None = None,
) -> RunConfig:
    thresholds_enabled = config.thresholds.enabled
    logging_enabled = config.logging.enabled
    effective_log_dir = config.logging.dir

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

    return parse_run_config(
        {
            "run": {
                "output_dir": output_dir if output_dir is not None else config.run.output_dir,
                "workers": workers if workers is not None else config.run.workers,
                "timeout": timeout if timeout is not None else config.run.timeout,
                "suricata_version": (
                    suricata_version if suricata_version is not None else config.run.suricata_version
                ),
                "cve_url": cve_url if cve_url is not None else config.run.cve_url,
            },
            "cache": {
                "enabled": cache_enabled if cache_enabled is not None else config.cache.enabled,
                "cache_dir": cache_dir if cache_dir is not None else config.cache.dir,
                "cache_max_age": cache_max_age if cache_max_age is not None else config.cache.max_age,
            },
            "thresholds": {
                "enabled": thresholds_enabled or logging_enabled,
                "min_cve": min_cve if min_cve is not None else config.thresholds.min_cve,
                "min_iprep": min_iprep if min_iprep is not None else config.thresholds.min_iprep,
            },
            "logging": {"enabled": logging_enabled, "dir": effective_log_dir},
            "feeds": {
                "usage_profile": (
                    feed_usage_profile if feed_usage_profile is not None else config.feeds.usage_profile
                ),
                "iprep": dict(config.feeds.iprep),
            },
        }
    )


def enabled_iprep_feeds(config: RunConfig) -> tuple[Feed, ...]:
    return tuple(
        feed
        for feed in IPREP_FEEDS
        if config.feeds.iprep[feed.name] and _feed_matches_usage_profile(feed, config.feeds.usage_profile)
    )


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


def _feed_matches_usage_profile(feed: Feed, profile: str) -> bool:
    if profile == "all":
        return True
    if profile == "commercial":
        return feed.usage_class == "unrestricted"
    return feed.usage_class in {"unrestricted", "non_commercial"}
