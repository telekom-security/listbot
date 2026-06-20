from __future__ import annotations

from listbot.cli import build_parser


def test_gen_all_command_parses() -> None:
    args = build_parser().parse_args(["gen-all", "--output-dir", "out", "--workers", "2"])

    assert args.command == "gen-all"
    assert args.output_dir == "out"
    assert args.workers == 2
