"""Tier-1 Semantic Similarity Filter for AI Prompt Security.

This module evaluates incoming user prompts against a database of known prompt
injection attacks stored in ChromaDB using vector similarity. It categorizes
prompts into block, escalate, or pass actions based on configured similarity
thresholds.
"""

import logging
import os
import sys
import threading
from typing import Any, Literal, TypedDict

# Setup path resolution to support absolute backend imports
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tier1_filter")

try:
    # Import the shared embed function
    from backend.core.embedder import embed
except ImportError as err:
    logger.critical(
        f"Failed to import embed function from backend.core.embedder. "
        f"Ensure that backend/core/embedder.py is present. Error: {err}"
    )
    raise

# Define Configurable Threshold Constants
THRESHOLD_BLOCK = 0.85
THRESHOLD_ESCALATE = 0.55

# Database config constants
COLLECTION_NAME = "known_attacks"
SEARCH_TOP_K = 5


class Tier1Result(TypedDict):
    """The structured result returned by the Tier-1 Semantic Similarity Filter."""
    similarity: float
    nearest_family: str
    decision: Literal["block", "escalate", "pass"]


class ChromaDBConnectionManager:
    """Thread-safe connection manager for keeping a single persistent ChromaDB client."""

    _client = None
    _collection = None
    _lock = threading.Lock()

    @classmethod
    def get_collection(cls) -> Any:
        """Connects to and retrieves the persistent ChromaDB collection.

        Returns:
            Any: The ChromaDB collection object.

        Raises:
            RuntimeError: If ChromaDB is unavailable or the collection is missing.
        """
        if cls._collection is None:
            with cls._lock:
                if cls._collection is None:
                    import chromadb

                    db_path = os.path.abspath(
                        os.path.join(os.path.dirname(__file__), "..", "data", "chromadb")
                    )

                    try:
                        cls._client = chromadb.PersistentClient(path=db_path)
                        # We use get_collection to verify the collection exists (Collection Missing)
                        cls._collection = cls._client.get_collection(name=COLLECTION_NAME)
                    except Exception as err:
                        cls._client = None
                        cls._collection = None
                        raise RuntimeError(
                            f"ChromaDB connection failed or collection '{COLLECTION_NAME}' is missing. "
                            f"Ensure seeder has run successfully. Error: {err}"
                        ) from err

        return cls._collection


def calculate_similarity(distance: float, space: str) -> float:
    """Converts a ChromaDB distance metric to cosine similarity.

    Args:
        distance (float): The distance value returned by ChromaDB.
        space (str): The metric space name (e.g., 'cosine', 'l2', 'ip').

    Returns:
        float: The calculated cosine similarity in range [-1.0, 1.0].
    """
    if space == "cosine":
        # Cosine distance = 1.0 - cosine_similarity
        return 1.0 - distance
    elif space == "l2":
        # Squared L2 distance = 2.0 * (1.0 - cosine_similarity) for normalized vectors
        clamped_distance = max(0.0, distance)
        return 1.0 - (clamped_distance / 2.0)
    elif space == "ip":
        # Inner Product = cosine_similarity for normalized vectors
        return distance
    else:
        # Default fallback to L2 space
        clamped_distance = max(0.0, distance)
        return 1.0 - (clamped_distance / 2.0)


def check_tier1(prompt: str) -> Tier1Result:
    """Evaluates the incoming prompt against the vector database of known attacks.

    Args:
        prompt (str): The user input prompt text.

    Returns:
        Tier1Result: The semantic similarity query details and filter decision.

    Raises:
        TypeError: If the prompt is not a string.
        ValueError: If the prompt is empty or only whitespace, or if metadata is corrupted.
        RuntimeError: If embedding, database access, or query execution fails.
    """
    # 1. Validation of prompt input
    if prompt is None:
        raise TypeError("Prompt input must be a string, received None.")
    if not isinstance(prompt, str):
        raise TypeError(f"Prompt input must be a string, received {type(prompt).__name__}.")
    if not prompt.strip():
        raise ValueError("Prompt input cannot be empty or contain only whitespace.")

    logger.info(f"Received prompt for Tier-1 evaluation (Length: {len(prompt)} characters).")

    # 2. Retrieve ChromaDB Collection
    try:
        collection = ChromaDBConnectionManager.get_collection()
    except Exception as err:
        logger.error(f"ChromaDB connection error: {err}")
        if isinstance(err, RuntimeError):
            raise
        raise RuntimeError(f"Failed to access vector database: {err}") from err

    # Check for empty database collection (Collection Empty)
    try:
        if collection.count() == 0:
            raise RuntimeError("ChromaDB collection is empty. Seeding is required.")
    except Exception as err:
        logger.error(f"Error checking collection count: {err}")
        if isinstance(err, RuntimeError):
            raise
        raise RuntimeError(f"ChromaDB error while validating collection state: {err}") from err

    # 3. Generate Semantic Embedding (Embedding Failures)
    try:
        prompt_embedding = embed(prompt)
    except Exception as err:
        logger.error(f"Failed to generate semantic embedding for prompt: {err}")
        raise RuntimeError(f"Embedding generation failed: {err}") from err

    # 4. Search Vector Database (ChromaDB Unavailable)
    try:
        results = collection.query(
            query_embeddings=[prompt_embedding],
            n_results=SEARCH_TOP_K
        )
    except Exception as err:
        logger.error(f"ChromaDB query execution failed: {err}")
        raise RuntimeError(f"Failed to query vector database: {err}") from err

    # 5. Check query response (No Search Results)
    if (
        not results
        or not results.get("ids")
        or len(results["ids"]) == 0
        or len(results["ids"][0]) == 0
    ):
        raise RuntimeError("No search results returned from vector database.")

    # 6. Extract nearest neighbor and calculate similarity
    try:
        # ChromaDB results are returned as list-of-lists, index [0][0] represents the top match
        nearest_id = results["ids"][0][0]
        nearest_distance = results["distances"][0][0]
        nearest_metadata = results["metadatas"][0][0]
    except (IndexError, TypeError) as err:
        logger.error(f"ChromaDB returned improperly structured search results: {err}")
        raise RuntimeError(f"Search results processing failed: {err}") from err

    # Handle potentially corrupted or missing metadata fields (Corrupted Metadata)
    if not nearest_metadata or "family" not in nearest_metadata:
        logger.error(f"Corrupted metadata detected for vector ID '{nearest_id}': {nearest_metadata}")
        raise ValueError(
            f"Corrupted metadata in matched vector '{nearest_id}': 'family' field is missing."
        )

    nearest_family = str(nearest_metadata["family"])

    # Determine metric space from collection metadata configuration
    space = "l2"
    if collection.metadata and "hnsw:space" in collection.metadata:
        space = collection.metadata["hnsw:space"]

    similarity = calculate_similarity(nearest_distance, space)

    # 7. Apply Configurable Decision Rules
    if similarity >= THRESHOLD_BLOCK:
        decision: Literal["block", "escalate", "pass"] = "block"
    elif similarity >= THRESHOLD_ESCALATE:
        decision: Literal["block", "escalate", "pass"] = "escalate"
    else:
        decision: Literal["block", "escalate", "pass"] = "pass"

    logger.info(
        f"Tier-1 Match: family='{nearest_family}', similarity={similarity:.4f}, decision='{decision}'"
    )

    return {
        "similarity": similarity,
        "nearest_family": nearest_family,
        "decision": decision
    }
