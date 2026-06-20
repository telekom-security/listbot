from __future__ import annotations

import bz2
import concurrent.futures
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .feeds import DEFAULT_SURICATA_VERSION, ET_SID_MAP_URL_TEMPLATE, Feed, IPREP_FEEDS
from .parsers import decode_payloads, extract_ipv4_indicators, first_cve_reference, iter_lines

USER_AGENT = "curl/8.0"


@dataclass(frozen=True)
class FetchResult:
    feed: Feed
    payload: bytes | None = None
    final_url: str | None = None
    status: int | None = None
    error: str | None = None


@dataclass
class FeedStat:
    name: str
    tag: str
    url: str
    status: str
    extracted: int = 0
    added: int = 0
    error: str | None = None


@dataclass
class BuildResult:
    output: Path
    compressed_output: Path
    count: int
    stats: list[FeedStat] = field(default_factory=list)


def build_iprep_map(
    output_dir: Path,
    *,
    feeds: tuple[Feed, ...] = IPREP_FEEDS,
    workers: int = 8,
    timeout: float = 30.0,
    progress: Any | None = None,
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
                extracted=len(indicators),
                added=added,
            )
        )
        _advance_progress(progress, parse_task)

    output = output_dir / "iprep.yaml"
    write_task = _add_progress_task(progress, "Writing iprep.yaml", 2)
    compressed = write_translation_map(mapping, output, progress=progress, progress_task=write_task)
    return BuildResult(output=output, compressed_output=compressed, count=len(mapping), stats=stats)


def build_cve_map(
    output_dir: Path,
    *,
    url: str | None = None,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    timeout: float = 30.0,
    progress: Any | None = None,
) -> BuildResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_url = url or ET_SID_MAP_URL_TEMPLATE.format(version=suricata_version)
    download_task = _add_progress_task(progress, "Downloading CVE map", 1)
    payload, final_url, status = fetch_url(source_url, timeout=timeout)
    _advance_progress(progress, download_task)
    texts = decode_payloads(payload)
    mapping: dict[str, str] = {}

    parse_task = _add_progress_task(progress, "Parsing CVE map", 1)
    for line in iter_lines(texts):
        cve = first_cve_reference(line)
        if cve is None:
            continue
        sid = line.split(maxsplit=1)[0]
        if sid.isdigit():
            mapping.setdefault(sid, cve)
    _advance_progress(progress, parse_task)

    output = output_dir / "cve.yaml"
    write_task = _add_progress_task(progress, "Writing cve.yaml", 2)
    compressed = write_translation_map(mapping, output, progress=progress, progress_task=write_task)
    stats = [
        FeedStat(
            name="emerging_threats_sid_msg",
            tag="cve",
            url=final_url or source_url,
            status=str(status),
            extracted=len(mapping),
            added=len(mapping),
        )
    ]
    return BuildResult(output=output, compressed_output=compressed, count=len(mapping), stats=stats)


def build_all_maps(
    output_dir: Path,
    *,
    workers: int = 8,
    timeout: float = 30.0,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    cve_url: str | None = None,
    progress: Any | None = None,
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
        )
        iprep_future = executor.submit(
            build_iprep_map,
            output_dir,
            workers=workers,
            timeout=timeout,
            progress=progress,
        )
        return cve_future.result(), iprep_future.result()


def run_all(
    output_dir: Path,
    *,
    workers: int = 8,
    timeout: float = 30.0,
    suricata_version: str = DEFAULT_SURICATA_VERSION,
    cve_url: str | None = None,
    min_cve: int = 5_000,
    min_iprep: int = 200_000,
    publish_dir: Path | None = None,
    git_push: bool = False,
    git_remote: str = "origin",
    pushover_token: str | None = None,
    pushover_user: str | None = None,
    log_dir: Path | None = None,
    progress: Any | None = None,
) -> tuple[BuildResult, BuildResult, str, bool]:
    cve_result, iprep_result = build_all_maps(
        output_dir,
        workers=workers,
        timeout=timeout,
        suricata_version=suricata_version,
        cve_url=cve_url,
        progress=progress,
    )

    ok = cve_result.count > min_cve and iprep_result.count > min_iprep
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    state = "OK" if ok else "ERROR"
    message = f"{now}: {cve_result.count} CVE IDs, {iprep_result.count} reps - {state}."

    _write_run_log(message, ok=ok, log_dir=log_dir or output_dir)

    if ok and publish_dir is not None:
        publish_outputs(output_dir, publish_dir)
        if git_push:
            commit_and_push(
                publish_dir,
                cve_count=cve_result.count,
                iprep_count=iprep_result.count,
                remote=git_remote,
            )

    token = pushover_token or os.environ.get("PUSHOVER_TOKEN")
    user = pushover_user or os.environ.get("PUSHOVER_USER")
    if token and user:
        send_pushover(token, user, message, timeout=timeout)

    return cve_result, iprep_result, message, ok


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


def fetch_url(url: str, *, timeout: float = 30.0) -> tuple[bytes, str, int]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(), response.geturl(), response.status


def publish_outputs(output_dir: Path, publish_dir: Path) -> None:
    publish_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("cve.yaml", "cve.yaml.bz2", "iprep.yaml", "iprep.yaml.bz2"):
        shutil.copy2(output_dir / filename, publish_dir / filename)


def commit_and_push(
    repo_dir: Path,
    *,
    cve_count: int,
    iprep_count: int,
    remote: str = "origin",
) -> None:
    subprocess.run(
        ["git", "add", "-f", "cve.yaml", "cve.yaml.bz2", "iprep.yaml", "iprep.yaml.bz2"],
        cwd=repo_dir,
        check=True,
    )
    diff = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=repo_dir,
        check=False,
    )
    if diff.returncode == 0:
        return
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            f"Include {cve_count} CVE IDs, {iprep_count} reputations",
        ],
        cwd=repo_dir,
        check=True,
    )
    subprocess.run(["git", "push", remote], cwd=repo_dir, check=True)


def send_pushover(token: str, user: str, message: str, *, timeout: float = 30.0) -> None:
    body = urllib.parse.urlencode(
        {
            "token": token,
            "user": user,
            "message": message,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.pushover.net/1/messages.json",
        data=body,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()


def _fetch_feeds(
    feeds: tuple[Feed, ...],
    *,
    workers: int,
    timeout: float,
    progress: Any | None = None,
    progress_task: Any | None = None,
) -> list[FetchResult]:
    results: list[FetchResult | None] = [None] * len(feeds)

    def fetch_one(index: int, feed: Feed) -> tuple[int, FetchResult]:
        try:
            payload, final_url, status = fetch_url(feed.url, timeout=timeout)
            return index, FetchResult(feed=feed, payload=payload, final_url=final_url, status=status)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            return index, FetchResult(feed=feed, error=str(exc))

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
    filename = "run.log" if ok else "error.log"
    with (log_dir / filename).open("a", encoding="utf-8") as handle:
        handle.write(f"{message}\n")


def _yaml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
