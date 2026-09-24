from __future__ import annotations

import bz2
import concurrent.futures
import hashlib
import http.cookiejar
import json
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import DEFAULT_CACHE_DIR, DEFAULT_CACHE_MAX_AGE, parse_cache_max_age
from .feeds import CVE_NOTICE, DEFAULT_SURICATA_VERSION, ET_SID_MAP_URL_TEMPLATE, FEED_NOTICES, Feed, IPREP_FEEDS
from .parsers import decode_payloads, extract_ipv4_indicators, first_cve_reference, iter_lines

USER_AGENT = "curl/8.0"
NOTICE_FILENAME = "NOTICE"


@dataclass(frozen=True)
class FetchResult:
    feed: Feed
    payload: bytes | None = None
    final_url: str | None = None
    retrieved_at: datetime | None = None
    error: str | None = None


@dataclass
class FeedStat:
    name: str
    tag: str
    url: str
    status: str
    final_url: str | None = None
    retrieved_at: datetime | None = None
    extracted: int = 0
    added: int = 0
    error: str | None = None


@dataclass
class BuildResult:
    output: Path
    compressed_output: Path
    count: int
    stats: list[FeedStat] = field(default_factory=list)
    notice_output: Path | None = None
    bz2_copy: Path | None = None


@dataclass(frozen=True)
class ThresholdResult:
    name: str
    actual: int
    minimum: int

    @property
    def ok(self) -> bool:
        return self.actual >= self.minimum

    @property
    def missing(self) -> int:
        return max(0, self.minimum - self.actual)


def build_iprep_map(
    output_dir: Path,
    *,
    feeds: tuple[Feed, ...] = IPREP_FEEDS,
    workers: int = 8,
    timeout: float = 30.0,
    progress: Any | None = None,
    write_notice: bool = True,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
    bz2_dir: Path | None = None,
) -> BuildResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    mapping: dict[str, str] = {}
    stats: list[FeedStat] = []

    download_task = _add_progress_task(progress, "Downloading IP feeds", len(feeds))
    results = _fetch_feeds(
        feeds,
        workers=workers,
        timeout=timeout,
        progress=progress,
        progress_task=download_task,
        cache_enabled=cache_enabled,
        cache_dir=cache_dir,
        cache_max_age=cache_max_age,
    )
    parse_task = _add_progress_task(progress, "Parsing IP feeds", len(results))
    for result in results:
        feed = result.feed
        if result.error is not None or result.payload is None:
            stats.append(
                FeedStat(
                    name=feed.name,
                    tag=feed.tag,
                    url=feed.url,
                    status="error",
                    final_url=result.final_url,
                    retrieved_at=result.retrieved_at,
                    error=result.error or "empty response",
                )
            )
            _advance_progress(progress, parse_task)
            continue

        texts = decode_payloads(result.payload)
        indicators: set[str] = set()
        for text in texts:
            indicators.update(
                extract_ipv4_indicators(
                    text,
                    max_network_hosts=feed.max_network_hosts,
                    max_range_hosts=feed.max_range_hosts,
                    parser=feed.parser,
                )
            )

        before = len(mapping)
        for ip in sorted(indicators):
            mapping.setdefault(ip, feed.tag)
        added = len(mapping) - before
        stats.append(
            FeedStat(
                name=feed.name,
                tag=feed.tag,
                url=feed.url,
                status="ok",
                final_url=result.final_url,
                retrieved_at=result.retrieved_at,
                extracted=len(indicators),
                added=added,
            )
        )
        _advance_progress(progress, parse_task)

    output = output_dir / "iprep.yaml"
    write_task = _add_progress_task(progress, "Writing iprep.yaml", 2)
    compressed = write_translation_map(mapping, output, progress=progress, progress_task=write_task)
    result = BuildResult(output=output, compressed_output=compressed, count=len(mapping), stats=stats)
    if bz2_dir is not None:
        copy_compressed_output(result, bz2_dir)
    if write_notice:
        notice_task = _add_progress_task(progress, f"Writing {NOTICE_FILENAME}", 1)
        result.notice_output = write_notice_file(output_dir, [result])
        _advance_progress(progress, notice_task)
    return result


def build_cve_map(
    output_dir: Path,
    *,
    url: str | None = None,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    timeout: float = 30.0,
    progress: Any | None = None,
    write_notice: bool = True,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
    bz2_dir: Path | None = None,
) -> BuildResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_url = url or ET_SID_MAP_URL_TEMPLATE.format(version=suricata_version)
    download_task = _add_progress_task(progress, "Downloading CVE map", 1)
    mapping: dict[str, str] = {}
    final_url: str | None = None
    status_text = "error"
    retrieved_at = datetime.now(timezone.utc)
    error: str | None = None

    try:
        payload, final_url, status, retrieved_at = fetch_url(
            source_url,
            timeout=timeout,
            cache_identity="emerging_threats_sid_msg",
            cache_enabled=cache_enabled,
            cache_dir=cache_dir,
            cache_max_age=cache_max_age,
        )
        status_text = str(status)
        texts = decode_payloads(payload)
        _advance_progress(progress, download_task)

        parse_task = _add_progress_task(progress, "Parsing CVE map", 1)
        for line in iter_lines(texts):
            cve = first_cve_reference(line)
            if cve is None:
                continue
            sid = line.split(maxsplit=1)[0]
            if sid.isdigit():
                mapping.setdefault(sid, cve)
        _advance_progress(progress, parse_task)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        error = str(exc)
        _advance_progress(progress, download_task)

    output = output_dir / "cve.yaml"
    write_task = _add_progress_task(progress, "Writing cve.yaml", 2)
    compressed = write_translation_map(mapping, output, progress=progress, progress_task=write_task)
    stats = [
        FeedStat(
            name="emerging_threats_sid_msg",
            tag="cve",
            url=source_url,
            status=status_text,
            final_url=final_url,
            retrieved_at=retrieved_at,
            extracted=len(mapping),
            added=len(mapping),
            error=error,
        )
    ]
    result = BuildResult(output=output, compressed_output=compressed, count=len(mapping), stats=stats)
    if bz2_dir is not None:
        copy_compressed_output(result, bz2_dir)
    if write_notice:
        notice_task = _add_progress_task(progress, f"Writing {NOTICE_FILENAME}", 1)
        result.notice_output = write_notice_file(output_dir, [result])
        _advance_progress(progress, notice_task)
    return result


def build_all_maps(
    output_dir: Path,
    *,
    feeds: tuple[Feed, ...] = IPREP_FEEDS,
    workers: int = 8,
    timeout: float = 30.0,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    cve_url: str | None = None,
    progress: Any | None = None,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
) -> tuple[BuildResult, BuildResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        cve_future = executor.submit(
            build_cve_map,
            output_dir,
            url=cve_url,
            suricata_version=suricata_version,
            timeout=timeout,
            progress=progress,
            write_notice=False,
            cache_enabled=cache_enabled,
            cache_dir=cache_dir,
            cache_max_age=cache_max_age,
        )
        iprep_future = executor.submit(
            build_iprep_map,
            output_dir,
            feeds=feeds,
            workers=workers,
            timeout=timeout,
            progress=progress,
            write_notice=False,
            cache_enabled=cache_enabled,
            cache_dir=cache_dir,
            cache_max_age=cache_max_age,
        )
        cve_result, iprep_result = cve_future.result(), iprep_future.result()

    notice_task = _add_progress_task(progress, f"Writing {NOTICE_FILENAME}", 1)
    notice_output = write_notice_file(output_dir, [cve_result, iprep_result])
    cve_result.notice_output = notice_output
    iprep_result.notice_output = notice_output
    _advance_progress(progress, notice_task)
    return cve_result, iprep_result


def run_all(
    output_dir: Path,
    *,
    feeds: tuple[Feed, ...] = IPREP_FEEDS,
    workers: int = 8,
    timeout: float = 30.0,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    cve_url: str | None = None,
    thresholds_enabled: bool = False,
    min_cve: int = 5_000,
    min_iprep: int = 200_000,
    logging_enabled: bool = False,
    log_dir: Path | None = None,
    progress: Any | None = None,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
    bz2_dir: Path | None = None,
) -> tuple[BuildResult, BuildResult, str, bool]:
    cve_result, iprep_result = build_all_maps(
        output_dir,
        feeds=feeds,
        workers=workers,
        timeout=timeout,
        suricata_version=suricata_version,
        cve_url=cve_url,
        progress=progress,
        cache_enabled=cache_enabled,
        cache_dir=cache_dir,
        cache_max_age=cache_max_age,
    )

    checks_enabled = thresholds_enabled or logging_enabled
    ok = True
    threshold_results: tuple[ThresholdResult, ...] = ()
    if checks_enabled:
        threshold_results = evaluate_thresholds(
            cve_result.count,
            iprep_result.count,
            min_cve=min_cve,
            min_iprep=min_iprep,
        )
        ok = all(result.ok for result in threshold_results)
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    state = "OK" if ok else "ERROR"
    if not checks_enabled:
        state = "GENERATED"
    message = f"{now}: {cve_result.count} CVE IDs, {iprep_result.count} reps - {state}."
    if checks_enabled:
        message = "\n".join([message, *_format_threshold_log_lines(threshold_results)])

    if bz2_dir is not None:
        if ok:
            copy_compressed_output(cve_result, bz2_dir)
            copy_compressed_output(iprep_result, bz2_dir)
        else:
            message = "\n".join([message, "bz2_dir not updated: threshold check failed."])

    if logging_enabled:
        _write_run_log(message, ok=ok, log_dir=log_dir or output_dir)

    return cve_result, iprep_result, message, ok


def evaluate_thresholds(
    cve_count: int,
    iprep_count: int,
    *,
    min_cve: int,
    min_iprep: int,
) -> tuple[ThresholdResult, ThresholdResult]:
    return (
        ThresholdResult("CVE map", cve_count, min_cve),
        ThresholdResult("IP reputation map", iprep_count, min_iprep),
    )


def write_translation_map(
    mapping: dict[str, str],
    output: Path,
    *,
    progress: Any | None = None,
    progress_task: Any | None = None,
) -> Path:
    tmp_output = output.with_name(f"{output.name}.tmp")
    with tmp_output.open("w", encoding="utf-8", newline="\n") as handle:
        for key in sorted(mapping):
            handle.write(f'"{_yaml_escape(key)}": "{_yaml_escape(mapping[key])}"\n')
    tmp_output.replace(output)
    _advance_progress(progress, progress_task)

    compressed = output.with_name(f"{output.name}.bz2")
    tmp_compressed = compressed.with_name(f"{compressed.name}.tmp")
    with output.open("rb") as source, bz2.open(tmp_compressed, "wb", compresslevel=9) as target:
        shutil.copyfileobj(source, target)
    tmp_compressed.replace(compressed)
    _advance_progress(progress, progress_task)
    return compressed


def copy_compressed_output(result: BuildResult, target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / result.compressed_output.name
    if target.resolve() != result.compressed_output.resolve():
        tmp_target = target.with_name(f"{target.name}.tmp")
        shutil.copyfile(result.compressed_output, tmp_target)
        tmp_target.replace(target)
    result.bz2_copy = target
    return target


def write_notice_file(
    output_dir: Path,
    results: list[BuildResult],
    *,
    generated_at: datetime | None = None,
) -> Path:
    generated_at = generated_at or datetime.now(timezone.utc)
    output = output_dir / NOTICE_FILENAME
    tmp_output = output.with_name(f"{output.name}.tmp")

    rows: list[str] = []
    for result in results:
        for stat in result.stats:
            notice = CVE_NOTICE if stat.name == "emerging_threats_sid_msg" else FEED_NOTICES.get(stat.name)
            source = notice.source if notice is not None else stat.name
            purpose = notice.purpose if notice is not None else "No purpose metadata available."
            license_terms = notice.license_terms if notice is not None else "No explicit feed license found."
            rows.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        result.output.name,
                        stat.name,
                        source,
                        purpose,
                        stat.url,
                        stat.final_url or stat.url,
                        stat.tag,
                        stat.status,
                        _format_utc(stat.retrieved_at),
                        str(stat.extracted),
                        str(stat.added),
                        license_terms,
                    )
                )
                + " |"
            )

    artifacts = sorted({result.output.name for result in results} | {result.compressed_output.name for result in results})
    with tmp_output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Third-Party Feed Notice\n\n")
        handle.write(f"Generated at: {_format_utc(generated_at)}\n")
        handle.write("\n")
        handle.write("This file documents third-party feeds used to generate listbot map artifacts.\n")
        handle.write("The generated YAML maps are derived data from the listed upstream sources.\n")
        handle.write("listbot does not relicense upstream feed data; upstream license and usage terms continue to apply.\n\n")
        handle.write("## Generated Artifacts\n\n")
        for artifact in artifacts:
            handle.write(f"- {artifact}\n")
        handle.write("\n")
        handle.write("## Feed Attribution\n\n")
        handle.write(
            "| Artifact | Feed ID | Source | Purpose | Configured URL | Final URL | Tag | Status | "
            "Retrieved at UTC | Extracted | Added | Upstream license / terms |\n"
        )
        handle.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | --- |\n")
        for row in rows:
            handle.write(f"{row}\n")

    tmp_output.replace(output)
    return output


def fetch_url(
    url: str,
    *,
    timeout: float = 30.0,
    cache_identity: str | None = None,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
) -> tuple[bytes, str, int, datetime]:
    if cache_enabled:
        cached = _read_cached_url(
            url,
            cache_identity=cache_identity,
            cache_dir=Path(cache_dir),
            cache_max_age=_coerce_cache_max_age(cache_max_age),
        )
        if cached is not None:
            return cached

    payload, final_url, status, retrieved_at = _download_url(url, timeout=timeout)
    if cache_enabled:
        try:
            _write_cached_url(
                url,
                payload=payload,
                final_url=final_url,
                status=status,
                retrieved_at=retrieved_at,
                cache_identity=cache_identity,
                cache_dir=Path(cache_dir),
            )
        except OSError:
            pass
    return payload, final_url, status, retrieved_at


def _open_url(request: urllib.request.Request, timeout: float) -> Any:
    # Some feeds sit behind a cookie challenge: the first request is redirected to a
    # token URL that sets a cookie and redirects back. Without a cookie jar those
    # redirects loop forever. The jar is per call, so feeds never share cookies.
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    return opener.open(request, timeout=timeout)


def _download_url(url: str, *, timeout: float) -> tuple[bytes, str, int, datetime]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )
    with _open_url(request, timeout) as response:
        payload = response.read()
        return payload, response.geturl(), response.status, datetime.now(timezone.utc)


def _read_cached_url(
    url: str,
    *,
    cache_identity: str | None,
    cache_dir: Path,
    cache_max_age: timedelta,
) -> tuple[bytes, str, int, datetime] | None:
    payload_path, metadata_path = _cache_paths(cache_dir, cache_identity, url)
    if not payload_path.exists() or not metadata_path.exists():
        return None

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        retrieved_at = _parse_cached_datetime(metadata["retrieved_at"])
        status = int(metadata["status"])
        final_url = str(metadata.get("final_url") or url)
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
        _delete_cache_entry(payload_path, metadata_path)
        return None

    if datetime.now(timezone.utc) - retrieved_at > cache_max_age:
        _delete_cache_entry(payload_path, metadata_path)
        return None

    try:
        payload = payload_path.read_bytes()
    except OSError:
        _delete_cache_entry(payload_path, metadata_path)
        return None

    return payload, final_url, status, retrieved_at


def _write_cached_url(
    url: str,
    *,
    payload: bytes,
    final_url: str,
    status: int,
    retrieved_at: datetime,
    cache_identity: str | None,
    cache_dir: Path,
) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload_path, metadata_path = _cache_paths(cache_dir, cache_identity, url)
    payload_tmp = payload_path.with_name(f"{payload_path.name}.tmp")
    metadata_tmp = metadata_path.with_name(f"{metadata_path.name}.tmp")
    metadata = {
        "identity": cache_identity,
        "url": url,
        "final_url": final_url,
        "status": status,
        "retrieved_at": _format_utc(retrieved_at),
    }
    payload_tmp.write_bytes(payload)
    metadata_tmp.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    payload_tmp.replace(payload_path)
    metadata_tmp.replace(metadata_path)


def _cache_paths(cache_dir: Path, cache_identity: str | None, url: str) -> tuple[Path, Path]:
    identity = cache_identity or "url"
    safe_identity = re.sub(r"[^A-Za-z0-9_.-]+", "_", identity).strip("._") or "url"
    digest = hashlib.sha256(f"{identity}\0{url}".encode("utf-8")).hexdigest()[:20]
    base = f"{safe_identity}-{digest}"
    return cache_dir / f"{base}.raw", cache_dir / f"{base}.json"


def _delete_cache_entry(payload_path: Path, metadata_path: Path) -> None:
    for path in (payload_path, metadata_path):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _coerce_cache_max_age(value: str | timedelta) -> timedelta:
    if isinstance(value, timedelta):
        return value
    return parse_cache_max_age(value)


def _parse_cached_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _fetch_feeds(
    feeds: tuple[Feed, ...],
    *,
    workers: int,
    timeout: float,
    progress: Any | None = None,
    progress_task: Any | None = None,
    cache_enabled: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    cache_max_age: str | timedelta = DEFAULT_CACHE_MAX_AGE,
) -> list[FetchResult]:
    results: list[FetchResult | None] = [None] * len(feeds)

    def fetch_one(index: int, feed: Feed) -> tuple[int, FetchResult]:
        try:
            payload, final_url, _status, retrieved_at = fetch_url(
                feed.url,
                timeout=timeout,
                cache_identity=feed.name,
                cache_enabled=cache_enabled,
                cache_dir=cache_dir,
                cache_max_age=cache_max_age,
            )
            return index, FetchResult(
                feed=feed,
                payload=payload,
                final_url=final_url,
                retrieved_at=retrieved_at,
            )
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            return index, FetchResult(feed=feed, retrieved_at=datetime.now(timezone.utc), error=str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [executor.submit(fetch_one, index, feed) for index, feed in enumerate(feeds)]
        for future in concurrent.futures.as_completed(futures):
            index, result = future.result()
            results[index] = result
            _advance_progress(progress, progress_task)

    return [result for result in results if result is not None]


def _add_progress_task(progress: Any | None, description: str, total: int) -> Any | None:
    if progress is None:
        return None
    return progress.add_task(description, total=total)


def _advance_progress(progress: Any | None, task_id: Any | None, advance: int = 1) -> None:
    if progress is not None and task_id is not None:
        progress.advance(task_id, advance)


def _write_run_log(message: str, *, ok: bool, log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    _append_log_entry(log_dir / "run.log", message)
    if not ok:
        _append_log_entry(log_dir / "error.log", message)


def _append_log_entry(path: Path, message: str) -> None:
    needs_separator = path.exists() and path.stat().st_size > 0
    with path.open("a", encoding="utf-8") as handle:
        if needs_separator:
            handle.write("\n")
        handle.write(f"{message}\n")


def _format_threshold_log_lines(results: tuple[ThresholdResult, ...]) -> list[str]:
    failed = [result for result in results if not result.ok]
    header = "Threshold check failed:" if failed else "Threshold check passed:"
    lines = [header]
    for result in results:
        comparator = ">=" if result.ok else "<"
        line = f"- {result.name}: {result.actual:,} {comparator} {result.minimum:,}"
        if result.ok:
            line += " OK"
        else:
            line += f" FAIL, missing {result.missing:,}"
        lines.append(line)
    return lines


def _yaml_escape(value: str) -> str:
    escaped: list[str] = []
    for char in value:
        codepoint = ord(char)
        if char == "\\":
            escaped.append("\\\\")
        elif char == '"':
            escaped.append('\\"')
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\r":
            escaped.append("\\r")
        elif char == "\t":
            escaped.append("\\t")
        elif codepoint < 0x20 or codepoint == 0x7F:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _format_utc(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _markdown_cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
