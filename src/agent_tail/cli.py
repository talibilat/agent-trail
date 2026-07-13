import argparse


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agent-tail")
    result.add_argument("input", help="JSONL file or - for standard input")
    result.add_argument("--export", metavar="PATH")
    result.add_argument("--full-payloads", action="store_true")
    result.add_argument("--unsafe-unredacted", action="store_true")
    result.add_argument("--loop-threshold", type=int, default=4)
    result.add_argument("--stall-seconds", type=float, default=30.0)
    return result


def main(argv: list[str] | None = None) -> int:
    parser().parse_args(argv)
    return 0
