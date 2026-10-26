import pytest

from scripts.benchmark_local import percentile


def test_percentile_uses_nearest_rank() -> None:
    assert percentile([0.1, 0.3, 0.2, 0.4], 0.5) == 0.2
    assert percentile([0.1, 0.3, 0.2, 0.4], 0.95) == 0.4


def test_percentile_rejects_invalid_samples() -> None:
    with pytest.raises(ValueError, match="at least one"):
        percentile([], 0.5)
    with pytest.raises(ValueError, match="fraction"):
        percentile([1.0], 0.0)
