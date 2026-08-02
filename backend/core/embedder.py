"""Module for generating semantic embeddings using sentence-transformers.

This module provides thread-safe singleton access to the SentenceTransformer model
'sentence-transformers/all-MiniLM-L6-v2' and exposes functions to generate embeddings
for single strings and batches of strings.
"""

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
        """Retrieves the SentenceTransformer model, loading it if not already loaded.

        Returns:
            SentenceTransformer: The initialized SentenceTransformer model instance.

        Raises:
            RuntimeError: If the model fails to load.
        """
        if self._model is None:
            with self._lock:
                if self._model is None:
                    try:
                        # Load the model on CPU for optimization and compatibility
                        self._model = SentenceTransformer(
                            "sentence-transformers/all-MiniLM-L6-v2",
                            device="cpu"
                        )
                    except Exception as e:
                        raise RuntimeError(
                            f"Failed to load sentence-transformers/all-MiniLM-L6-v2: {e}"
                        ) from e
        return self._model


# Eagerly initialize the singleton manager and load the model when the module is imported.
_manager = EmbedderModelManager()
try:
    _manager.get_model()
except Exception as _err:
    # We allow the exception to propagate during import to fail fast if the model cannot be loaded.
    raise RuntimeError(f"Error during eager model loading: {_err}") from _err


def embed(text: str) -> list[float]:
    """Generates a 384-dimensional semantic embedding for a single text string.

    Args:
        text (str): The text string to embed.

    Returns:
        list[float]: A 384-dimensional list of floats representing the embedding.

    Raises:
        TypeError: If the input is not a string.
        ValueError: If the input is empty or contains only whitespace.
        RuntimeError: If the underlying model fails or is not loaded.
    """
    if text is None:
        raise TypeError("Input text must be a string, received None.")
    if not isinstance(text, str):
        raise TypeError(f"Input text must be a string, received {type(text).__name__}.")
    if not text.strip():
        raise ValueError("Input text cannot be empty or contain only whitespace.")

    try:
        model = _manager.get_model()
        # encode returns a numpy array by default; we convert it to a plain python list.
        embedding = model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        )
        return embedding.tolist()
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Failed to generate embedding: {e}") from e


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Generates semantic embeddings for a batch of text strings.

    Args:
        texts (list[str]): A list of text strings to embed.

    Returns:
        list[list[float]]: A list of 384-dimensional embedding lists.

    Raises:
        TypeError: If the input is not a list, or if any element is not a string.
        ValueError: If the input list is empty, or if any element is empty or whitespace-only.
        RuntimeError: If the underlying model fails or is not loaded.
    """
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
        # Batch inference is used here for better performance.
        embeddings = model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        )
        return embeddings.tolist()
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Failed to generate batch embeddings: {e}") from e
