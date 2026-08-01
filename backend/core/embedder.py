import random
from typing import List
from backend.config import EMBEDDING_DIM

def embed(text: str) -> List[float]:
    """
    Generates a 384-dimensional dense embedding vector for the input string.
    
    # TODO: Replace with real model logic (e.g. sentence-transformers MiniLM-L6-v2)
    """
    # Deterministic pseudo-random seed based on text content for reproducible mock embeddings
    seed = sum(ord(c) for c in text)
    rng = random.Random(seed)
    return [rng.uniform(-1.0, 1.0) for _ in range(EMBEDDING_DIM)]


def embed_batch(texts: List[str]) -> List[List[float]]:
    """
    Generates dense embeddings for a batch of strings.
    
    # TODO: Replace with real model logic (e.g. batch model inference)
    """
    return [embed(text) for text in texts]
