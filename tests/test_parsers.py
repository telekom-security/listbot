from __future__ import annotations

import gzip
import io
import zipfile

from listbot.parsers import (
    decode_payloads,
    extract_dshield_ranges,
    extract_generic_ipv4s,
    extract_ipv4_indicators,
    first_cve_reference,
)


def test_extract_generic_ipv4s_validates_ips_and_expands_small_cidrs() -> None:
    text = "1.2.3.4 999.1.1.1 8.8.8.0/30 172.16.0.0/16 0.12.0.1"

    assert extract_generic_ipv4s(text, max_network_hosts=4) == {
        "1.2.3.4",
        "8.8.8.0",
        "8.8.8.1",
        "8.8.8.2",
        "8.8.8.3",
    }


def test_extract_dshield_ranges_expands_start_end_columns() -> None:
    text = "\n".join(
        [
            "# comment",
            "45.205.1.0\t45.205.1.3\t30\t123\tNETWORK\tUS\tabuse@example.test",
        ]
    )

    assert extract_dshield_ranges(text) == {
        "45.205.1.0",
        "45.205.1.1",
        "45.205.1.2",
        "45.205.1.3",
    }


def test_dshield_parser_falls_back_to_generic_when_no_ranges_exist() -> None:
    assert extract_ipv4_indicators("plain 8.8.8.8", parser="dshield") == {"8.8.8.8"}


def test_dshield_parser_does_not_fall_back_when_range_lines_are_invalid() -> None:
    text = "8.8.8.1\t8.8.8.2\tnot-a-count\n"

    assert extract_ipv4_indicators(text, parser="dshield") == set()


def test_dshield_parser_does_not_fall_back_when_ranges_are_too_large() -> None:
    text = "8.8.8.0\t8.8.8.255\t30\n"

    assert extract_ipv4_indicators(text, parser="dshield", max_range_hosts=2) == set()


def test_extract_dshield_ranges_filters_interior_non_global_addresses() -> None:
    text = "198.51.99.255\t198.51.101.0\t1\n"

    indicators = extract_dshield_ranges(text, max_range_hosts=300)

    assert "198.51.99.255" in indicators
    assert "198.51.101.0" in indicators
    assert "198.51.100.1" not in indicators
    assert not any(indicator.startswith("198.51.100.") for indicator in indicators)


def test_decode_payloads_supports_plain_gzip_and_zip() -> None:
    assert decode_payloads(b"1.2.3.4\n") == ["1.2.3.4\n"]
    assert decode_payloads(gzip.compress(b"5.6.7.8\n")) == ["5.6.7.8\n"]

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("feed.txt", "9.9.9.9\n")

    assert decode_payloads(buffer.getvalue()) == ["9.9.9.9\n"]


def test_first_cve_reference_uses_first_match_and_preserves_can_prefix() -> None:
    line = (
        "2003099 || ET TEST || url,example.test || "
        "cve,2006-3602 || CVE-2006-4458 || CAN-2006-4542"
    )

    assert first_cve_reference(line) == "CVE-2006-3602"
    assert first_cve_reference("2000016 || test || cve,CAN-2004-0120") == "CAN-2004-0120"
    assert first_cve_reference("2000001 || no references") is None
