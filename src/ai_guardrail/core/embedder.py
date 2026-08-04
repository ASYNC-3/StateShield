"""Module for generating semantic embeddings using sentence-transformers."""

import threading
from typing import List

from sentence_transformers import SentenceTransformer


class EmbedderModelManager:
    """Thread-safe singleton manager for loading and reusing the SentenceTransformer model."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls) -> "EmbedderModelManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._model = None
        return cls._instance

    def get_model(self) -> SentenceTransformer:
        if self._model is None:
            with self._lock:
                if self._model is None:
                    try:
                        self._model = SentenceTransformer(
                            "sentence-transformers/all-MiniLM-L6-v2",
                            device="cpu"
                        )
                    except Exception as e:
                        raise RuntimeError(
                            f"Failed to load sentence-transformers/all-MiniLM-L6-v2: {e}"
                        ) from e
        return self._model


_manager = EmbedderModelManager()
try:
    _manager.get_model()
except Exception:
    pass


def embed(text: str) -> List[float]:
    """Generates a 384-dimensional semantic embedding for a single text string."""
    if text is None:
        raise TypeError("Input text must be a string, received None.")
    if not isinstance(text, str):
        raise TypeError(f"Input text must be a string, received {type(text).__name__}.")
    if not text.strip():
        raise ValueError("Input text cannot be empty or contain only whitespace.")

    try:
        model = _manager.get_model()
        embedding = model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        )
        return embedding.tolist()
    except Exception as e:
        if isinstance(e, (TypeError, ValueError)):
            raise
        raise RuntimeError(f"Failed to generate embedding: {e}") from e


def embed_batch(texts: List[str]) -> List[List[float]]:
    """Generates semantic embeddings for a batch of text strings."""
    if texts is None:
        raise TypeError("Input texts must be a list of strings, received None.")
    if not isinstance(texts, list):
        raise TypeError(f"Input texts must be a list of strings, received {type(texts).__name__}.")
    if len(texts) == 0:
        raise ValueError("Input list cannot be empty.")

    for i, t in enumerate(texts):
        if t is None:
            raise TypeError(f"Element at index {i} is None; all elements must be strings.")
        if not isinstance(t, str):
            raise TypeError(f"Element at index {i} must be a string, received {type(t).__name__}.")
        if not t.strip():
            raise ValueError(f"Element at index {i} cannot be empty or contain only whitespace.")

    try:
        model = _manager.get_model()
        embeddings = model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        )
        return embeddings.tolist()
    except Exception as e:
        if isinstance(e, (TypeError, ValueError)):
            raise
        raise RuntimeError(f"Failed to generate batch embeddings: {e}") from e
