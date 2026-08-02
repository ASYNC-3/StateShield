"""Attack Lineage Clustering module for Prompt Security.

This module processes blocked prompts by embedding them, storing them in ChromaDB,
projecting their embeddings into 2D space using UMAP, clustering them with
HDBSCAN, and labeling clusters using majority voting. This powers the attack
lineage visualization dashboard.
"""

import datetime
import logging
import os
import sys
import threading
import uuid
from collections import Counter
from typing import Any, Dict, List, TypedDict

import numpy as np

# Setup path resolution to support absolute backend imports
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("lineage_clustering")

try:
    # Import the shared embed function
    from backend.core.embedder import embed
except ImportError as err:
    logger.critical(
        f"Failed to import embed function from backend.core.embedder. "
        f"Ensure that backend/core/embedder.py is present. Error: {err}"
    )
    raise

# Constants
COLLECTION_NAME = "blocked_attempts"


class LineagePoint(TypedDict):
    """Data structure representing a 2D projected attack lineage point."""
    x: float
    y: float
    cluster_id: int
    family_label: str
    prompt_snippet: str


class BlockedAttemptsChromaDBManager:
    """Thread-safe connection manager for the blocked_attempts collection."""

    _client = None
    _collection = None
    _lock = threading.Lock()

    @classmethod
    def get_collection(cls) -> Any:
        """Connects to and retrieves the persistent ChromaDB collection.

        Returns:
            Any: The ChromaDB collection object.

        Raises:
            RuntimeError: If ChromaDB initialization fails.
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
                        cls._collection = cls._client.get_or_create_collection(name=COLLECTION_NAME)
                    except Exception as err:
                        cls._client = None
                        cls._collection = None
                        raise RuntimeError(
                            f"ChromaDB connection or collection '{COLLECTION_NAME}' retrieval failed: {err}"
                        ) from err
        return cls._collection


def make_snippet(prompt: str) -> str:
    """Truncates the prompt string to ~50 characters for security previews.

    Args:
        prompt (str): The raw prompt text.

    Returns:
        str: A preview snippet of the prompt.
    """
    if not prompt:
        return ""
    cleaned = prompt.strip()
    if len(cleaned) <= 50:
        return cleaned
    return cleaned[:50] + "..."


def add_blocked_prompt(prompt: str, metadata: dict) -> None:
    """Embeds and saves a blocked prompt and its metadata to ChromaDB.

    Args:
        prompt (str): The blocked user prompt text.
        metadata (dict): Associated metadata (e.g., family, severity).

    Raises:
        TypeError: If prompt is not a string or metadata is not a dictionary.
        ValueError: If prompt is empty or contains only whitespace.
        RuntimeError: If embedding generation or database insertion fails.
    """
    if prompt is None:
        raise TypeError("Prompt must be a string, received None.")
    if not isinstance(prompt, str):
        raise TypeError(f"Prompt must be a string, received {type(prompt).__name__}.")
    if not prompt.strip():
        raise ValueError("Prompt cannot be empty or contain only whitespace.")
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError(f"Metadata must be a dictionary, received {type(metadata).__name__}.")

    logger.info(f"Inserting blocked prompt to lineage database. Length: {len(prompt)} characters.")

    # 1. Generate semantic embedding
    try:
        embedding = embed(prompt)
    except Exception as err:
        logger.error(f"Failed to generate embedding for blocked prompt: {err}")
        raise RuntimeError(f"Embedding generation failed: {err}") from err

    # 2. Retrieve collection
    try:
        collection = BlockedAttemptsChromaDBManager.get_collection()
    except Exception as err:
        logger.error(f"Failed to access ChromaDB: {err}")
        raise RuntimeError(f"ChromaDB connection failed: {err}") from err

    # 3. Check for duplicates using deterministic UUIDv5 of the prompt
    record_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, prompt.strip()))
    try:
        existing = collection.get(ids=[record_id])
        if existing and existing.get("ids"):
            logger.info(f"Blocked prompt already exists (ID: {record_id}). Skipping insertion to prevent duplicate.")
            return
    except Exception as err:
        logger.error(f"Error checking duplicate ID in database: {err}")
        raise RuntimeError(f"Database query failed: {err}") from err

    # 4. Prepare metadata and serialize non-basic types
    full_metadata = metadata.copy() if metadata else {}
    full_metadata["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    sanitized_metadata = {}
    for k, v in full_metadata.items():
        if isinstance(v, (str, int, float, bool)):
            sanitized_metadata[k] = v
        else:
            sanitized_metadata[k] = str(v)

    # 5. Insert into collection
    try:
        collection.add(
            ids=[record_id],
            embeddings=[embedding],
            documents=[prompt],
            metadatas=[sanitized_metadata]
        )
        logger.info(f"Successfully inserted blocked prompt (ID: {record_id}) into ChromaDB.")
    except Exception as err:
        logger.error(f"Failed to insert blocked prompt to ChromaDB: {err}")
        raise RuntimeError(f"ChromaDB write failed: {err}") from err


def get_projection() -> list[LineagePoint]:
    """Retrieves all blocked prompts, projects to 2D using UMAP, and clusters with HDBSCAN.

    Returns:
        list[LineagePoint]: A list of 2D lineage points containing visualization properties.

    Raises:
        RuntimeError: For critical database operation failures.
    """
    logger.info("Generating lineage projection coordinates...")

    # 1. Retrieve ChromaDB Collection
    try:
        collection = BlockedAttemptsChromaDBManager.get_collection()
    except Exception as err:
        logger.error(f"ChromaDB connection failed: {err}")
        raise RuntimeError(f"ChromaDB connection failed: {err}") from err

    # 2. Get All Blocked Prompts
    try:
        data = collection.get(include=["embeddings", "documents", "metadatas"])
    except Exception as err:
        logger.error(f"Failed to retrieve data from ChromaDB collection: {err}")
        raise RuntimeError(f"Database retrieval failed: {err}") from err

    if not data or not data.get("ids") or len(data["ids"]) == 0:
        logger.info("No blocked prompts found in the database. Returning empty projection list.")
        return []

    raw_ids = data["ids"]
    raw_embeddings = data["embeddings"]
    raw_documents = data["documents"]
    raw_metadatas = data["metadatas"]

    # Filter out corrupted records
    valid_ids = []
    valid_embeddings = []
    valid_documents = []
    valid_metadatas = []

    for i in range(len(raw_ids)):
        emb = raw_embeddings[i]
        doc = raw_documents[i]
        meta = raw_metadatas[i]

        # Valid embeddings must be 384-dimensional arrays/lists
        if not isinstance(emb, list) or len(emb) != 384:
            logger.warning(f"Skipped corrupted record (ID: {raw_ids[i]}): Invalid embedding length/type.")
            continue
        if not isinstance(meta, dict):
            logger.warning(f"Skipped corrupted record (ID: {raw_ids[i]}): Missing metadata dictionary.")
            continue

        valid_ids.append(raw_ids[i])
        valid_embeddings.append(emb)
        valid_documents.append(doc)
        valid_metadatas.append(meta)

    n_samples = len(valid_ids)
    if n_samples == 0:
        logger.info("No valid records found after screening corrupted embeddings. Returning empty list.")
        return []

    # Convert to Numpy matrix
    embeddings_np = np.array(valid_embeddings, dtype=np.float32)

    # Handle float errors (NaN / Inf checks)
    if not np.isfinite(embeddings_np).all():
        logger.error("Embeddings contain NaN or Inf. Aborting projection computation.")
        projection = np.zeros((n_samples, 2), dtype=np.float32)
        umap_failed = True
    else:
        umap_failed = False

    # 3. UMAP Dimensionality Reduction
    projection = None
    if not umap_failed:
        if n_samples < 5:
            # Fallback layout coordinates for sparse dataset
            logger.info("Insufficient samples (<5) for UMAP projection. Applying coordinate fallback.")
            projection = np.zeros((n_samples, 2), dtype=np.float32)
            for idx in range(n_samples):
                projection[idx, 0] = float(idx)
                projection[idx, 1] = 0.0
        else:
            try:
                import umap

                n_neighbors = min(15, n_samples - 1)
                reducer = umap.UMAP(
                    n_neighbors=n_neighbors,
                    n_components=2,
                    metric="cosine",
                    random_state=42
                )
                projection = reducer.fit_transform(embeddings_np)
            except Exception as err:
                logger.error(f"UMAP projection failed: {err}. Applying coordinate fallback.")
                projection = np.zeros((n_samples, 2), dtype=np.float32)

    if projection is None:
        projection = np.zeros((n_samples, 2), dtype=np.float32)

    # 4. HDBSCAN Clustering
    cids = []
    if n_samples < 5:
        logger.info("Insufficient samples (<5) for HDBSCAN clustering. Assigning all to noise (-1).")
        cids = [-1] * n_samples
    else:
        try:
            import hdbscan

            min_cluster_size = max(2, min(5, n_samples // 3))
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=min_cluster_size,
                min_samples=1,
                metric="euclidean"
            )
            labels = clusterer.fit_predict(projection)
            cids = [int(lbl) for lbl in labels]
        except Exception as err:
            logger.error(f"HDBSCAN clustering execution failed: {err}. Defaulting all points to noise.")
            cids = [-1] * n_samples

    # 5. Cluster Majority Voting Label Selection
    cluster_majority_label: Dict[int, str] = {}
    cluster_families: Dict[int, List[str]] = {}

    for i, cid in enumerate(cids):
        if cid < 0:
            continue
        family = valid_metadatas[i].get("family", "unlabeled_emerging")
        if not family or not family.strip():
            family = "unlabeled_emerging"
        if cid not in cluster_families:
            cluster_families[cid] = []
        cluster_families[cid].append(family)

    for cid, families in cluster_families.items():
        counter = Counter(families)
        most_common_family, count = counter.most_common(1)[0]
        # Strict majority (> 50% threshold)
        if count > len(families) / 2:
            cluster_majority_label[cid] = most_common_family
        else:
            cluster_majority_label[cid] = "unlabeled_emerging"

    # 6. Format final results
    results: List[LineagePoint] = []
    for i in range(n_samples):
        cid = cids[i]

        if cid >= 0:
            family_label = cluster_majority_label.get(cid, "unlabeled_emerging")
        else:
            # Noise points get their individual family labels or fallback
            family_label = valid_metadatas[i].get("family", "unlabeled_emerging")
            if not family_label or not family_label.strip():
                family_label = "unlabeled_emerging"

        prompt_snippet = make_snippet(valid_documents[i])

        results.append({
            "x": float(projection[i, 0]),
            "y": float(projection[i, 1]),
            "cluster_id": cid,
            "family_label": family_label,
            "prompt_snippet": prompt_snippet
        })

    logger.info(f"Projection generated. Clusters detected: {len(set(cids) - {-1})}. Points: {len(results)}.")
    return results
