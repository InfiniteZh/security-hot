"""Compute multilingual sentence embeddings for unembedded articles.

Uses sentence-transformers + intfloat/multilingual-e5-small (~470MB,
MIT license, 384-dim, supports zh + en + 100 langs).

Runs as a separate step between fetch_data and cluster_articles. Idempotent:
only embeds articles missing from article_embeddings table (or with a
different model name).
"""
from __future__ import annotations

import argparse
import sys
import numpy as np
from datetime import datetime, timezone, timedelta
from pathlib import Path

import db

MODEL_NAME = "intfloat/multilingual-e5-small"
EMBEDDING_DIM = 384  # for shape sanity check


def _load_model():
    """Lazy import + load. First call downloads ~470MB to ~/.cache/huggingface."""
    from sentence_transformers import SentenceTransformer
    import torch
    device = "mps" if torch.backends.mps.is_available() else ("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[embed] loading {MODEL_NAME} on {device}", file=sys.stderr)
    return SentenceTransformer(MODEL_NAME, device=device)


def _to_blob(vec: np.ndarray) -> bytes:
    """float32 numpy → little-endian raw bytes (1536 bytes for 384-dim)."""
    return vec.astype(np.float32).tobytes()


def _from_blob(b: bytes) -> np.ndarray:
    return np.frombuffer(b, dtype=np.float32)


def embed_unembedded_articles(
    *,
    db_path=None,
    window_hours: int = 72,
    batch_size: int = 64,
    verbose: bool = True,
) -> int:
    """Embed articles in window_hours that have no row in article_embeddings
    (or have one from a different model). Returns number of new embeddings written.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    conn = db.connect(db_path)
    try:
        rows = list(conn.execute("""
            SELECT a.id, a.title FROM articles a
            LEFT JOIN article_embeddings e ON e.article_id = a.id AND e.model = ?
            WHERE a.fetched_at >= ? AND e.article_id IS NULL
        """, [MODEL_NAME, cutoff]))
        if not rows:
            if verbose: print(f"[embed] 0 articles need embedding (window={window_hours}h)", file=sys.stderr)
            return 0

        if verbose: print(f"[embed] {len(rows)} articles to embed", file=sys.stderr)
        model = _load_model()
        # e5 prefers "query: " or "passage: " prefix; for clustering use "passage:"
        texts = [f"passage: {(r['title'] or '').strip()}" for r in rows]
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        n_written = 0
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i+batch_size]
            ids = [r["id"] for r in rows[i:i+batch_size]]
            vectors = model.encode(batch, normalize_embeddings=True, show_progress_bar=False, batch_size=batch_size)
            for art_id, vec in zip(ids, vectors):
                if vec.shape[-1] != EMBEDDING_DIM:
                    raise RuntimeError(f"unexpected embedding dim {vec.shape}; expected {EMBEDDING_DIM}")
                db.upsert_embedding(conn, art_id, _to_blob(vec), MODEL_NAME, now_iso)
                n_written += 1
            if verbose:
                print(f"[embed] batch {i//batch_size + 1}: +{len(batch)} ({n_written}/{len(rows)})", file=sys.stderr)
        return n_written
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Compute sentence embeddings for unembedded articles.")
    p.add_argument("--window", type=int, default=72, help="Look-back window in hours")
    p.add_argument("--batch", type=int, default=64)
    p.add_argument("--db", default=None)
    args = p.parse_args()
    n = embed_unembedded_articles(
        db_path=Path(args.db) if args.db else None,
        window_hours=args.window,
        batch_size=args.batch,
    )
    print(f"[embed] done: {n} new embeddings written", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
