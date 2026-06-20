from __future__ import annotations

import gzip
import ipaddress
import io
import re
import zipfile
from collections.abc import Iterable

IPV4_RE = re.compile(r"(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?![\w.-])")
CIDR_RE = re.compile(r"(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.-])")
CVE_RE = re.compile(r"(?i)\b(?:(CVE|CAN)-|cve,)(\d{4})-(\d{4,})\b")


def decode_payloads(payload: bytes) -> list[str]:
    if payload.startswith(b"\x1f\x8b"):
        return [_decode_bytes(gzip.decompress(payload))]

    if zipfile.is_zipfile(io.BytesIO(payload)):
        texts: list[str] = []
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                texts.append(_decode_bytes(archive.read(info)))
        return texts

    return [_decode_bytes(payload)]


def extract_ipv4_indicators(
    text: str,
    *,
    max_network_hosts: int = 65_536,
    max_range_hosts: int = 65_536,
    parser: str = "generic",
) -> set[str]:
    if parser == "dshield":
        ranged = extract_dshield_ranges(text, max_range_hosts=max_range_hosts)
        if ranged:
            return ranged

    return extract_generic_ipv4s(text, max_network_hosts=max_network_hosts)


def extract_generic_ipv4s(text: str, *, max_network_hosts: int = 65_536) -> set[str]:
    indicators: set[str] = set()
    cidr_spans: list[tuple[int, int]] = []

    for match in CIDR_RE.finditer(text):
        network = _parse_network(match.group(0))
        if network is None:
            continue
        cidr_spans.append(match.span())
        if network.num_addresses <= max_network_hosts:
            indicators.update(str(ip) for ip in network if _is_public_ipv4(ip))

    cidr_spans.sort()
    span_index = 0
    for match in IPV4_RE.finditer(text):
        while span_index < len(cidr_spans) and cidr_spans[span_index][1] <= match.start():
            span_index += 1
        if span_index < len(cidr_spans):
            start, end = cidr_spans[span_index]
            if start <= match.start() < end:
                continue

        ip = _parse_ip(match.group(0))
        if ip is not None:
            indicators.add(str(ip))

    return indicators


def extract_dshield_ranges(text: str, *, max_range_hosts: int = 65_536) -> set[str]:
    indicators: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue

        columns = line.split("\t")
        if len(columns) < 3:
            columns = line.split()
        if len(columns) < 3 or not columns[2].isdigit():
            continue

        start = _parse_ip(columns[0])
        end = _parse_ip(columns[1])
        if start is None or end is None:
            continue

        start_int = int(start)
        end_int = int(end)
        if end_int < start_int:
            continue

        size = end_int - start_int + 1
        if size > max_range_hosts:
            continue

        indicators.update(str(ipaddress.ip_address(value)) for value in range(start_int, end_int + 1))

    return indicators


def first_cve_reference(line: str) -> str | None:
    match = CVE_RE.search(line)
    if match is None:
        return None

    prefix = match.group(1)
    year = match.group(2)
    identifier = match.group(3)
    normalized_prefix = "CAN" if prefix and prefix.upper() == "CAN" else "CVE"
    return f"{normalized_prefix}-{year}-{identifier}"


def iter_lines(texts: Iterable[str]) -> Iterable[str]:
    for text in texts:
        yield from text.splitlines()


def _decode_bytes(payload: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("utf-8", errors="replace")


def _parse_ip(value: str) -> ipaddress.IPv4Address | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    return ip if _is_public_ipv4(ip) else None


def _parse_network(value: str) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return network if isinstance(network, ipaddress.IPv4Network) else None


def _is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return ip.is_global
