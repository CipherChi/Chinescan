"""Run repeatable offline benchmarks against checked-in synthetic fixtures."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from chinescan.core.orchestration.code_scan import BuiltinRuleScanner
from chinescan.log_analysis.parsers import parse_log_data

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def percentile(values: list[float], fraction: float) -> float:
    """Return a nearest-rank percentile for a non-empty sample."""
    if not values:
        raise ValueError("percentile requires at least one measurement")
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be greater than 0 and at most 1")
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _measure(
    name: str,
    fixture: Path,
    operation: Callable[[], int],
    *,
    warmup: int,
    iterations: int,
) -> dict[str, object]:
    for _ in range(warmup):
        operation()
    elapsed: list[float] = []
    output_count = 0
    for _ in range(iterations):
        started = time.perf_counter()
        output_count = operation()
        elapsed.append(time.perf_counter() - started)
    median = statistics.median(elapsed)
    return {
        "name": name,
        "fixture": fixture.name,
        "fixture_bytes": fixture.stat().st_size,
        "iterations": iterations,
        "warmup_iterations": warmup,
        "output_count": output_count,
        "median_seconds": median,
        "p95_seconds": percentile(elapsed, 0.95),
        "operations_per_second": (1.0 / median) if median else None,
    }


def run_benchmarks(*, warmup: int, iterations: int) -> dict[str, Any]:
    code_fixture = FIXTURES / "sample-python-project"
    jsonl_fixture = FIXTURES / "sample-logs" / "events.jsonl"
    access_fixture = FIXTURES / "sample-logs" / "nginx-access.log"
    scanner = BuiltinRuleScanner()

    def scan_code() -> int:
        return len(scanner.scan(code_fixture))

    def parse_fixture(path: Path) -> int:
        batch = parse_log_data(path.read_bytes(), path.name, path.name)
        if batch.errors:
            raise RuntimeError(f"benchmark fixture could not be parsed: {path.name}")
        return len(batch.events)

    return {
        "schema_version": "1.0",
        "revision": os.environ.get("GITHUB_SHA") or os.environ.get("CI_COMMIT_SHA"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "benchmarks": [
            _measure(
                "builtin_code_scan",
                code_fixture / "app.py",
                scan_code,
                warmup=warmup,
                iterations=iterations,
            ),
            _measure(
                "jsonl_log_parse",
                jsonl_fixture,
                lambda: parse_fixture(jsonl_fixture),
                warmup=warmup,
                iterations=iterations,
            ),
            _measure(
                "nginx_access_parse",
                access_fixture,
                lambda: parse_fixture(access_fixture),
                warmup=warmup,
                iterations=iterations,
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=_positive_int, default=25)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    arguments = parser.parse_args()
    if not 0 <= arguments.warmup <= 20:
        parser.error("--warmup must be between 0 and 20")
    report = run_benchmarks(warmup=arguments.warmup, iterations=arguments.iterations)
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
