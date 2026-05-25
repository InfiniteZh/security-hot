"""Mirror clustering: group articles whose titles are highly similar.

Algorithm: 3-character shingles + Jaccard similarity, threshold 0.7.
Bucketed by title-head character to keep comparisons sub-quadratic.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import db


def shingles(title: str) -> set[str]:
    """3-character n-grams of the normalized title.

    Normalization: lowercase + strip non-word chars (keeps CJK, drops
    spaces/punctuation/emoji).
    """
    normalized = re.sub(r"\W", "", (title or "").lower())
    if len(normalized) < 3:
        return set()
    return {normalized[i:i+3] for i in range(len(normalized) - 2)}


def jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity. 0 if both sets empty."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


JACCARD_THRESHOLD = 0.7
