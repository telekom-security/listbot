from __future__ import annotations

import bz2

from listbot.generators import USER_AGENT, write_translation_map


def test_user_agent_is_generic() -> None:
    assert USER_AGENT.startswith("curl/")
    assert "listbot" not in USER_AGENT.lower()


def test_write_translation_map_uses_legacy_scalar_format(tmp_path) -> None:
    output = tmp_path / "sample.yaml"

    compressed = write_translation_map(
        {
            "2.2.2.2": "known attacker",
            "1.1.1.1": "bad reputation",
        },
        output,
    )

    expected = '"1.1.1.1": "bad reputation"\n"2.2.2.2": "known attacker"\n'
    assert output.read_text(encoding="utf-8") == expected
    assert bz2.decompress(compressed.read_bytes()).decode("utf-8") == expected
