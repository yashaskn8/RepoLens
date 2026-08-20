"""Deterministic Reciprocal Rank Fusion (RRF) implementation for multi-channel retrieval."""

from collections import defaultdict
from typing import Dict, List, Tuple

from app.retrieval.schemas import RetrievalChannel


def reciprocal_rank_fusion(
    channel_rankings: Dict[RetrievalChannel, List[Tuple[str, float]]],
    k: int = 60,
) -> List[Tuple[str, float, List[RetrievalChannel]]]:
    """Fuse multiple ranked lists of candidate chunk IDs using Reciprocal Rank Fusion (RRF).

    Args:
        channel_rankings: Dict mapping each RetrievalChannel to a ranked list of (chunk_id, score).
        k: Smoothing constant (standard default is 60).

    Returns:
        Sorted list of tuples: (chunk_id, fused_rrf_score, contributing_channels).
    """
    rrf_scores: Dict[str, float] = defaultdict(float)
    contributing_channels: Dict[str, List[RetrievalChannel]] = defaultdict(list)

    for channel, ranked_items in channel_rankings.items():
        for rank_idx, (chunk_id, _channel_score) in enumerate(ranked_items):
            rank = rank_idx + 1  # 1-indexed rank
            rrf_score = 1.0 / (k + rank)
            rrf_scores[chunk_id] += rrf_score
            if channel not in contributing_channels[chunk_id]:
                contributing_channels[chunk_id].append(channel)

    # Sort deterministically by descending RRF score, then ascending chunk_id for tie-breaking
    fused_results = [
        (chunk_id, score, contributing_channels[chunk_id])
        for chunk_id, score in rrf_scores.items()
    ]
    fused_results.sort(key=lambda item: (-item[1], item[0]))

    return fused_results
