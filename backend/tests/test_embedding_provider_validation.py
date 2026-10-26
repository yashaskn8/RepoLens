"""Structured cloud-embedding responses must never be treated as complete if partial."""

import pytest

from app.indexing.embeddings import _validated_embedding_results


def test_embedding_provider_batch_is_complete_and_deterministically_sorted():
    result = _validated_embedding_results(
        [(1, [0.0, 1.0]), (0, [1.0, 0.0])], expected_count=2,
    )
    assert [r.index for r in result] == [0, 1]
    assert [r.vector for r in result] == [[1.0, 0.0], [0.0, 1.0]]


@pytest.mark.parametrize(
    "vectors,count",
    [
        ([], 1),
        ([(0, [1.0])], 2),
        ([(0, [1.0]), (0, [2.0])], 2),
        ([(2, [1.0]), (1, [2.0])], 2),
        ([(0, [])], 1),
        ([(0, [float("nan")])], 1),
        ([(0, [float("inf")])], 1),
        ([(0, [True])], 1),
        ([(0, ["secret"])], 1),
        ([(0, [1.0]), (1, [1.0, 0.0])], 2),
    ],
)
def test_embedding_provider_rejects_missing_duplicate_or_malformed_vectors(vectors, count):
    with pytest.raises(RuntimeError, match="incomplete|malformed|inconsistent"):
        _validated_embedding_results(vectors, expected_count=count)
