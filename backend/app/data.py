"""Load cached JSON snapshots and normalize them into API-ready models.

This module is now a **façade**: the implementation was split into focused
sibling modules for cohesion, and everything is re-exported here so the public
import path ``backend.app.data`` (used heavily by ``main.py`` and the test
suite) keeps the exact same surface.

Split layout:
  * ``cache_io``       — low-level JSON/SQLite primitives + the two mutable
                         globals (``_state``, ``_NEWS_DB``) that tests patch
  * ``scoring``        — pure Vuln scoring (classify_kind/derive_severity/heat)
  * ``vuln_murphy``    — MurphySec → Vuln parser
  * ``vuln_sources``   — KEV/GHSA/PoC/OSV-malware/news-bridge → Vuln parsers
  * ``vuln_aggregate`` — cross-source Vuln merge (``all_vulns``)
  * ``news_query``     — SQLite reads for articles/search/sources/dispatches
  * ``aggregate``      — API aggregate views (heat boards, today, manifest,
                         cross-domain search)

Monkeypatch write-through
-------------------------
Tests do ``monkeypatch.setattr(data, "_NEWS_DB", tmp)`` / patch ``data._state``.
The real loaders live in the sibling modules and read these globals from
:mod:`cache_io` *at call time*. To make a patch on this façade reach them, the
module's ``__setattr__`` mirrors ``_NEWS_DB`` / ``_state`` straight into
``cache_io`` (write-through). See ``_DataModule`` below.
"""
from __future__ import annotations

import sys as _sys
from types import ModuleType as _ModuleType

from . import cache_io as _cache_io

# Re-export everything from the leaf primitives.
from .cache_io import (  # noqa: F401
    CACHE,
    CVE_RE,
    ROOT,
    _RELOAD_TTL,
    _VALID_CATEGORIES,
    _json_list,
    _json_obj,
    _load_json,
    _news_conn,
    _normalize_iocs,
    _row_to_article,
    parse_iso_date,
    severity_from_cvss,
)
from .cache_io import _NEWS_DB, _state  # noqa: F401

# Scoring (pure).
from .scoring import (  # noqa: F401
    _SEV_RANK,
    classify_kind,
    compute_heat,
    derive_severity,
)

# MurphySec parser.
from .vuln.murphy import (  # noqa: F401
    _dedupe_nonempty,
    _first_cve,
    _first_float,
    _first_ghsa,
    _first_text,
    _murphy_affected_entries,
    _murphy_affected_versions,
    _murphy_bool,
    _murphy_fix_versions,
    _murphy_iocs,
    _murphy_language_ecosystem,
    _murphy_packages,
    _murphy_references,
    _murphy_title_package,
    _murphy_to_vulns,
    _normalize_murphy_ecosystem,
    _normalize_murphy_severity,
    _normalize_murphy_time,
)

# Other vuln sources.
from .vuln.sources import (  # noqa: F401
    _VULN_RSS_SOURCES,
    _cve_signals,
    _ghsa_to_vulns,
    _kev_to_vulns,
    _news_cve_to_vulns,
    _osv_malware_to_vulns,
    _pkg_scope,
    _pocs_to_vulns,
)

# Cross-source aggregate.
from .vuln.aggregate import all_vulns  # noqa: F401

# News-domain SQLite reads.
from .news.query import (  # noqa: F401
    _CJK_RE,
    _DEFAULT_DISPATCH_TOPIC,
    _load_dispatch_cache,
    all_articles,
    all_sources,
    load_dispatches,
    search_articles,
)

# API aggregate views.
from .aggregate import (  # noqa: F401
    _CAT_COLOR,
    _CVE_SEARCH_RE,
    _news_heat_score,
    heat_board,
    manifest,
    news_heat_board,
    search_aggregated,
    today_summary,
)


class _DataModule(_ModuleType):
    """Façade module whose ``_NEWS_DB`` / ``_state`` writes mirror into
    :mod:`cache_io`, so test monkeypatches on this module reach the real
    loaders (which read the globals from ``cache_io`` at call time)."""

    def __setattr__(self, name, value):
        # Mirror the mutable globals the test-suite patches onto cache_io, the
        # single source of truth the relocated loaders read at call time.
        if name in ("_NEWS_DB", "_state", "CACHE"):
            setattr(_cache_io, name, value)
        super().__setattr__(name, value)


_sys.modules[__name__].__class__ = _DataModule
