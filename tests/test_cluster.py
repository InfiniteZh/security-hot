"""cluster_articles.py: Jaccard 3-shingle algorithm + primary selection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import cluster_articles as ca  # noqa: E402
import db  # noqa: E402


def test_shingles_3char():
    s = ca.shingles("abcdef")
    assert s == {"abc", "bcd", "cde", "def"}


def test_shingles_normalizes():
    """Lowercase + drops non-word chars."""
    a = ca.shingles("Hello, World!")
    b = ca.shingles("helloworld")
    assert a == b


def test_jaccard_identical_is_1():
    assert ca.jaccard({"a", "b"}, {"a", "b"}) == 1.0


def test_jaccard_disjoint_is_0():
    assert ca.jaccard({"a", "b"}, {"c", "d"}) == 0.0


def test_jaccard_partial():
    # |A ∩ B| = 1, |A ∪ B| = 3
    assert abs(ca.jaccard({"a", "b"}, {"b", "c"}) - 1/3) < 1e-9


def test_jaccard_empty_inputs():
    assert ca.jaccard(set(), set()) == 0.0


def test_titles_with_high_overlap_pass_threshold():
    """Similar titles should score well above 0.5 (3-char shingles, no spaces)."""
    a = ca.shingles("Microsoft patches Outlook RCE vulnerability")
    b = ca.shingles("Microsoft patches Outlook RCE flaw")
    assert ca.jaccard(a, b) >= 0.5


def test_translated_titles_do_not_pass_threshold():
    """Chinese vs English title for same event should NOT cluster."""
    zh = ca.shingles("微软修补 Outlook 远程代码执行漏洞")
    en = ca.shingles("Microsoft patches Outlook RCE vulnerability")
    assert ca.jaccard(zh, en) < 0.5
