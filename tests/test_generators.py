from __future__ import annotations

import bz2
import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from listbot.feeds import APPROVED_FEED_USAGE_CLASSES, APPROVED_IPREP_TAGS, FEED_NOTICES, Feed, IPREP_FEEDS
from listbot import generators
from listbot.generators import (
    BuildResult,
    FeedStat,
    USER_AGENT,
    build_iprep_map,
    evaluate_thresholds,
    fetch_url,
    run_all,
    write_notice_file,
    write_translation_map,
)


def test_user_agent_is_generic() -> None:
    assert USER_AGENT.startswith("curl/")
    assert "listbot" not in USER_AGENT.lower()


def test_all_iprep_feeds_have_notice_metadata() -> None:
    assert {feed.name for feed in IPREP_FEEDS} <= set(FEED_NOTICES)


def test_default_iprep_tags_use_approved_analyst_vocabulary() -> None:
    assert {feed.tag for feed in IPREP_FEEDS} <= APPROVED_IPREP_TAGS


def test_default_iprep_feeds_use_approved_usage_classes() -> None:
    assert {feed.usage_class for feed in IPREP_FEEDS} <= APPROVED_FEED_USAGE_CLASSES


def test_removed_overbroad_tags_are_not_default_vocabulary() -> None:
    removed_tags = {"known attacker", "ssh attacker"}

    assert APPROVED_IPREP_TAGS.isdisjoint(removed_tags)
    assert {feed.tag for feed in IPREP_FEEDS}.isdisjoint(removed_tags)


def test_spamlist_is_not_a_default_feed() -> None:
    assert "spamlist" not in {feed.name for feed in IPREP_FEEDS}


def test_direct_blocklist_is_replaced_by_firehol_blocklist_de() -> None:
    feed_names = {feed.name for feed in IPREP_FEEDS}

    assert "blocklist" not in feed_names
    assert "firehol_blocklist_de" in feed_names


def test_firehol_anonymous_is_last_default_feed() -> None:
    assert IPREP_FEEDS[-1].name == "firehol_anonymous"


def test_analyst_facing_feed_tags_are_explicit() -> None:
    expected_tags = {
        "feodotracker": "botnet C2",
        "threatfox_ip_port_recent": "malware infra",
        "neo23x0_c2": "C2 server",
        "cybercrime_tracker": "malware infra",
        "firehol_webclient": "malware infra",
        "firehol_mwdomainlist": "malware host",
        "firehol_cruzit": "web attacker",
        "firehol_dshield": "scan source",
        "dshield": "scan source",
        "firehol_darklist": "attack source",
        "firehol_blocklist_de_apache": "web attacker",
        "firehol_blocklist_de_bots": "bot activity",
        "firehol_blocklist_de_ftp": "ftp abuse",
        "firehol_blocklist_de_imap": "mail abuse",
        "firehol_blocklist_de_mail": "mail abuse",
        "firehol_blocklist_de_sip": "sip abuse",
        "firehol_blocklist_de_ssh": "ssh abuse",
        "firehol_blocklist_de": "service abuse",
        "cinsscore": "bad reputation",
        "binary_defense_banlist": "bad reputation",
        "firehol_php_commenters_30d": "comment spam",
        "firehol_php_dictionary_30d": "web scanner",
        "firehol_php_harvesters_30d": "web harvester",
        "firehol_php_spammers_30d": "form spammer",
        "firehol_stopforumspam_30d": "forum spammer",
        "firehol_stopforumspam_toxic": "spam network",
        "firehol_abusers_30d": "web abuse",
        "firehol_cleantalk": "form spammer",
        "myip": "web blacklist",
        "botvrij": "threat IOC",
        "turris": "service abuse",
        "greensnow": "attack source",
        "rutgers": "attack source",
        "tor_bulk_exit": "tor exit",
        "tor_exit_addresses": "tor exit",
        "firehol_dm_tor": "tor exit",
        "firehol_proxylists": "open proxy",
        "firehol_proxyrss": "open proxy",
        "firehol_proxyspy": "open proxy",
        "firehol_web_proxies": "open proxy",
        "firehol_socks_proxy": "open proxy",
        "firehol_sslproxies": "open proxy",
        "spys": "open proxy",
        "firehol_anonymous": "anonymizer",
    }
    actual_tags = {feed.name: feed.tag for feed in IPREP_FEEDS}

    for name, tag in expected_tags.items():
        assert actual_tags[name] == tag


def test_feed_usage_classes_are_conservative() -> None:
    actual_usage_classes = {feed.name: feed.usage_class for feed in IPREP_FEEDS}
    unrestricted = {
        "feodotracker",
        "maltrail_mass_scanner",
        "ipsum_level3",
    }
    non_commercial = {
        "firehol_dshield",
        "dshield",
        "bitwire_outbound",
        "turris",
    }
    restricted = {"binary_defense_banlist"}

    assert {name for name, usage in actual_usage_classes.items() if usage == "unrestricted"} == unrestricted
    assert {name for name, usage in actual_usage_classes.items() if usage == "non_commercial"} == non_commercial
    assert {name for name, usage in actual_usage_classes.items() if usage == "restricted"} == restricted
    assert {name for name, usage in actual_usage_classes.items() if usage == "unknown"} == (
        set(actual_usage_classes) - unrestricted - non_commercial - restricted
    )


def test_write_translation_map_uses_legacy_scalar_format(tmp_path) -> None:
    output = tmp_path / "sample.yaml"

    compressed = write_translation_map(
        {
            "2.2.2.2": "attack source",
            "1.1.1.1": "bad reputation",
        },
        output,
    )

    expected = '"1.1.1.1": "bad reputation"\n"2.2.2.2": "attack source"\n'
    assert output.read_text(encoding="utf-8") == expected
    assert bz2.decompress(compressed.read_bytes()).decode("utf-8") == expected


def test_write_translation_map_escapes_control_characters(tmp_path) -> None:
    output = tmp_path / "sample.yaml"

    write_translation_map(
        {
            "key\nwith\tcontrol": 'value\r\x01quote"backslash\\',
        },
        output,
    )

    text = output.read_text(encoding="utf-8")
    assert text.count("\n") == 1
    assert "\t" not in text
    assert "\r" not in text
    assert "\x01" not in text
    assert '"key\\nwith\\tcontrol":' in text
    assert 'value\\r\\x01quote\\"backslash\\\\' in text


def test_fetch_url_uses_valid_cache(tmp_path, monkeypatch) -> None:
    calls = 0

    def fake_urlopen(_request, timeout):
        nonlocal calls
        calls += 1
        return _FakeResponse(b"fresh", "https://example.test/feed.txt", 200)

    monkeypatch.setattr(generators.urllib.request, "urlopen", fake_urlopen)
    first = fetch_url(
        "https://example.test/feed.txt",
        cache_identity="feed",
        cache_dir=tmp_path / "cache",
        cache_max_age="1d",
    )
    second = fetch_url(
        "https://example.test/feed.txt",
        cache_identity="feed",
        cache_dir=tmp_path / "cache",
        cache_max_age="1d",
    )

    assert first[0] == b"fresh"
    assert second[0] == b"fresh"
    assert calls == 1


def test_fetch_url_deletes_expired_cache_before_refresh(tmp_path, monkeypatch) -> None:
    payloads = [b"new", b"old"]

    def fake_urlopen(_request, timeout):
        return _FakeResponse(payloads.pop(), "https://example.test/feed.txt", 200)

    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(generators.urllib.request, "urlopen", fake_urlopen)
    assert fetch_url("https://example.test/feed.txt", cache_identity="feed", cache_dir=cache_dir)[0] == b"old"
    _age_cache_entry(cache_dir, "2000-01-01T00:00:00Z")

    assert fetch_url("https://example.test/feed.txt", cache_identity="feed", cache_dir=cache_dir)[0] == b"new"


def test_fetch_url_does_not_use_stale_cache_after_refresh_failure(tmp_path, monkeypatch) -> None:
    def fake_urlopen(_request, timeout):
        return _FakeResponse(b"old", "https://example.test/feed.txt", 200)

    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(generators.urllib.request, "urlopen", fake_urlopen)
    assert fetch_url("https://example.test/feed.txt", cache_identity="feed", cache_dir=cache_dir)[0] == b"old"
    _age_cache_entry(cache_dir, "2000-01-01T00:00:00Z")

    def failing_urlopen(_request, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(generators.urllib.request, "urlopen", failing_urlopen)
    with pytest.raises(urllib.error.URLError):
        fetch_url("https://example.test/feed.txt", cache_identity="feed", cache_dir=cache_dir)

    assert not list(cache_dir.glob("*.raw"))
    assert not list(cache_dir.glob("*.json"))


def test_fetch_url_recovers_from_corrupt_cache_metadata(tmp_path, monkeypatch) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    payload_path, metadata_path = generators._cache_paths(cache_dir, "feed", "https://example.test/feed.txt")
    payload_path.write_bytes(b"cached")
    metadata_path.write_text("{not json", encoding="utf-8")
    calls = 0

    def fake_urlopen(_request, timeout):
        nonlocal calls
        calls += 1
        return _FakeResponse(b"fresh", "https://example.test/feed.txt", 200)

    monkeypatch.setattr(generators.urllib.request, "urlopen", fake_urlopen)

    payload, _final_url, _status, _retrieved_at = fetch_url(
        "https://example.test/feed.txt",
        cache_identity="feed",
        cache_dir=cache_dir,
        cache_max_age="1d",
    )

    assert payload == b"fresh"
    assert calls == 1
    assert payload_path.read_bytes() == b"fresh"
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["status"] == 200


def test_cache_paths_preserve_dotted_identity_and_digest() -> None:
    raw_path, metadata_path = generators._cache_paths(
        Path("cache"),
        "blocklist.de",
        "https://example.test/feed.txt",
    )

    assert raw_path.name.startswith("blocklist.de-")
    assert raw_path.name.endswith(".raw")
    assert metadata_path.name == f"{raw_path.stem}.json"


def test_build_iprep_map_aggregates_in_feed_order_and_records_errors(tmp_path, monkeypatch) -> None:
    now = datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)
    feeds = (
        Feed("first", "https://example.test/first.txt", "bad reputation"),
        Feed("second", "https://example.test/second.txt", "malware infra"),
        Feed("failed", "https://example.test/failed.txt", "attack source"),
    )

    def fake_fetch_url(url, **kwargs):
        if kwargs["cache_identity"] == "failed":
            raise urllib.error.URLError("offline")
        payloads = {
            "first": b"8.8.8.8\n1.1.1.1\n",
            "second": b"8.8.8.8\n9.9.9.9\n",
        }
        return payloads[kwargs["cache_identity"]], url, 200, now

    monkeypatch.setattr(generators, "fetch_url", fake_fetch_url)

    result = build_iprep_map(tmp_path, feeds=feeds, workers=3, cache_enabled=False)

    assert result.count == 3
    assert result.output.read_text(encoding="utf-8") == (
        '"1.1.1.1": "bad reputation"\n'
        '"8.8.8.8": "bad reputation"\n'
        '"9.9.9.9": "malware infra"\n'
    )
    assert [(stat.name, stat.extracted, stat.added, stat.status) for stat in result.stats] == [
        ("first", 2, 2, "ok"),
        ("second", 2, 1, "ok"),
        ("failed", 0, 0, "error"),
    ]
    assert result.stats[-1].error is not None


def test_run_all_continues_when_cve_download_fails(tmp_path, monkeypatch) -> None:
    now = datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)
    feeds = (Feed("ip_feed", "https://example.test/ip.txt", "bad reputation"),)

    def fake_fetch_url(url, **kwargs):
        if kwargs["cache_identity"] == "emerging_threats_sid_msg":
            raise urllib.error.URLError("cve down")
        return b"8.8.8.8\n", url, 200, now

    monkeypatch.setattr(generators, "fetch_url", fake_fetch_url)

    cve, iprep, message, ok = run_all(
        tmp_path,
        feeds=feeds,
        thresholds_enabled=True,
        min_cve=1,
        min_iprep=1,
        cache_enabled=False,
    )

    assert ok is False
    assert "CVE map: 0 < 1 FAIL" in message
    assert cve.count == 0
    assert cve.stats[0].status == "error"
    assert cve.stats[0].error is not None
    assert cve.output.exists()
    assert cve.output.read_text(encoding="utf-8") == ""
    assert iprep.count == 1
    assert iprep.stats[0].status == "ok"
    assert cve.notice_output == iprep.notice_output == tmp_path / "NOTICE"
    notice = (tmp_path / "NOTICE").read_text(encoding="utf-8")
    assert "| cve.yaml | emerging_threats_sid_msg |" in notice
    assert "| iprep.yaml | ip_feed |" in notice


def test_write_notice_file_documents_feed_attribution(tmp_path) -> None:
    result = BuildResult(
        output=tmp_path / "iprep.yaml",
        compressed_output=tmp_path / "iprep.yaml.bz2",
        count=3,
        stats=[
            FeedStat(
                name="dshield",
                tag="scan source",
                url="https://feeds.dshield.org/block.txt",
                final_url="https://feeds.dshield.org/block.txt",
                status="ok",
                retrieved_at=datetime(2026, 6, 20, 11, 58, tzinfo=timezone.utc),
                extracted=4,
                added=3,
            )
        ],
    )

    notice = write_notice_file(
        tmp_path,
        [result],
        generated_at=datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc),
    )
    text = notice.read_text(encoding="utf-8")

    assert "Generated at: 2026-06-20T12:00:00Z" in text
    assert "HTTP User-Agent" not in text
    assert "derived data from the listed upstream sources" in text
    assert "| iprep.yaml | dshield | DShield block list |" in text
    assert "2026-06-20T11:58:00Z" in text
    assert "Creative Commons BY-NC-SA 2.5" in text


def test_run_without_thresholds_or_logging_writes_no_logs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(generators, "build_all_maps", _fake_build_all_maps)

    _cve, _iprep, message, ok = run_all(tmp_path)

    assert ok is True
    assert "GENERATED" in message
    assert not (tmp_path / "run.log").exists()
    assert not (tmp_path / "error.log").exists()


def test_logging_writes_run_log_and_error_log_for_failed_thresholds(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(generators, "build_all_maps", _fake_build_all_maps)

    _cve, _iprep, message, ok = run_all(tmp_path, logging_enabled=True)

    assert ok is False
    assert "ERROR" in message
    assert "Threshold check failed" in message
    assert "CVE map: 1 < 5,000 FAIL, missing 4,999" in message
    assert "IP reputation map: 1 < 200,000 FAIL, missing 199,999" in message
    assert (tmp_path / "run.log").exists()
    assert (tmp_path / "error.log").exists()
    assert "Threshold check failed" in (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "Threshold check failed" in (tmp_path / "error.log").read_text(encoding="utf-8")


def test_logging_appends_new_runs_to_existing_logs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(generators, "build_all_maps", _fake_build_all_maps)

    run_all(tmp_path, logging_enabled=True)
    run_all(tmp_path, logging_enabled=True)

    run_log = (tmp_path / "run.log").read_text(encoding="utf-8")
    error_log = (tmp_path / "error.log").read_text(encoding="utf-8")
    assert run_log.count("Threshold check failed:") == 2
    assert error_log.count("Threshold check failed:") == 2
    assert "\n\n" in run_log
    assert "\n\n" in error_log


def test_successful_logged_run_writes_only_run_log(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(generators, "build_all_maps", _fake_successful_build_all_maps)

    _cve, _iprep, message, ok = run_all(tmp_path, logging_enabled=True)

    assert ok is True
    assert "OK" in message
    assert (tmp_path / "run.log").exists()
    assert not (tmp_path / "error.log").exists()


def test_thresholds_pass_when_counts_reach_minimum() -> None:
    results = evaluate_thresholds(5_000, 200_000, min_cve=5_000, min_iprep=200_000)

    assert all(result.ok for result in results)


def _fake_build_all_maps(output_dir: Path, **_kwargs) -> tuple[BuildResult, BuildResult]:
    cve = BuildResult(
        output=output_dir / "cve.yaml",
        compressed_output=output_dir / "cve.yaml.bz2",
        count=1,
    )
    iprep = BuildResult(
        output=output_dir / "iprep.yaml",
        compressed_output=output_dir / "iprep.yaml.bz2",
        count=1,
    )
    return cve, iprep


def _fake_successful_build_all_maps(output_dir: Path, **_kwargs) -> tuple[BuildResult, BuildResult]:
    cve = BuildResult(
        output=output_dir / "cve.yaml",
        compressed_output=output_dir / "cve.yaml.bz2",
        count=5_000,
    )
    iprep = BuildResult(
        output=output_dir / "iprep.yaml",
        compressed_output=output_dir / "iprep.yaml.bz2",
        count=200_000,
    )
    return cve, iprep


class _FakeResponse:
    def __init__(self, payload: bytes, url: str, status: int) -> None:
        self._payload = payload
        self._url = url
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        return None

    def read(self) -> bytes:
        return self._payload

    def geturl(self) -> str:
        return self._url


def _age_cache_entry(cache_dir: Path, retrieved_at: str) -> None:
    metadata_path = next(cache_dir.glob("*.json"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["retrieved_at"] = retrieved_at
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
