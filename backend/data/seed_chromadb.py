"""ChromaDB seeding utility for the AI Prompt Security Layer.

This module reads attack corpus datasets from JSONL files, validates and processes
each record, generates semantic embeddings using the shared embedder module,
and populates a persistent ChromaDB collection. It is designed to be fully
idempotent and thread-safe.
"""

import datetime
import json
import logging
import os
import sys
import uuid
from typing import Any, Dict, List, Optional, Set

# Setup path resolution to import core modules
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("seed_chromadb")

try:
    # Import the shared embedding functions
    from backend.core.embedder import embed, embed_batch
except ImportError as err:
    logger.critical(
        f"Failed to import from backend.core.embedder. "
        f"Ensure that backend/core/embedder.py exists and is accessible. Error: {err}"
    )
    raise

# Defaults & constants
DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "chromadb"))
DEFAULT_CORPUS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "attack_corpus"))
COLLECTION_NAME = "known_attacks"
DATASET_FILES = [
    "direct_injection.jsonl",
    "jailbreak_roleplay.jsonl",
    "obfuscation.jsonl",
    "extraction_leakage.jsonl",
    "benign_tricky.jsonl"
]
BATCH_SIZE = 256


def validate_and_parse_record(
    line: str,
    line_number: int,
    file_name: str
) -> Optional[Dict[str, Any]]:
    """Validates and parses a single JSONL line into a standard record format.

    Args:
        line (str): The raw string line to parse.
        line_number (int): The line index for logging.
        file_name (str): The name of the file being processed for logging.

    Returns:
        Optional[Dict[str, Any]]: Validated dictionary containing parsed keys,
            or None if the entry is invalid or empty.
    """
    cleaned_line = line.strip()
    if not cleaned_line:
        return None

    try:
        data = json.loads(cleaned_line)
    except json.JSONDecodeError as err:
        logger.error(
            f"Skipped record - invalid JSON in file '{file_name}' at line {line_number}: {err}"
        )
        return None

    if not isinstance(data, dict):
        logger.warning(
            f"Skipped record - expected JSON object in file '{file_name}' at line {line_number}, "
            f"received {type(data).__name__}"
        )
        return None

    prompt = data.get("prompt")
    family = data.get("family")
    severity = data.get("severity")
    record_id = data.get("id")

    if not isinstance(prompt, str) or not prompt.strip():
        logger.warning(
            f"Skipped record in '{file_name}' at line {line_number}: 'prompt' field must be a "
            f"non-empty string."
        )
        return None

    if not isinstance(family, str) or not family.strip():
        logger.warning(
            f"Skipped record in '{file_name}' at line {line_number}: 'family' field must be a "
            f"non-empty string."
        )
        return None

    if not isinstance(severity, str) or not severity.strip():
        logger.warning(
            f"Skipped record in '{file_name}' at line {line_number}: 'severity' field must be a "
            f"non-empty string."
        )
        return None

    # Determine or generate record ID
    if record_id is not None:
        record_id = str(record_id).strip()
    if not record_id:
        # Generate a deterministic UUID using the prompt to guarantee idempotency
        record_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, prompt.strip()))

    return {
        "id": record_id,
        "prompt": prompt.strip(),
        "family": family.strip(),
        "severity": severity.strip(),
        "source_file": file_name,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


def load_all_records(corpus_dir: str) -> Dict[str, Dict[str, Any]]:
    """Reads, parses, and validates all JSONL datasets in the corpus folder.

    Args:
        corpus_dir (str): Absolute path to the directory containing dataset files.

    Returns:
        Dict[str, Dict[str, Any]]: A mapping of unique deterministic IDs to validated
            records, resolving source duplicates.
    """
    records_by_id: Dict[str, Dict[str, Any]] = {}

    if not os.path.isdir(corpus_dir):
        logger.error(f"Attack corpus directory not found at '{corpus_dir}'.")
        return records_by_id

    for file_name in DATASET_FILES:
        file_path = os.path.join(corpus_dir, file_name)
        if not os.path.isfile(file_path):
            logger.warning(f"Expected attack corpus dataset file not found: '{file_path}'. Skipping.")
            continue

        logger.info(f"Processing dataset file: '{file_name}'")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    try:
                        record = validate_and_parse_record(line, line_idx, file_name)
                        if record:
                            rid = record["id"]
                            if rid in records_by_id:
                                logger.debug(
                                    f"Duplicate ID '{rid}' detected in source datasets. "
                                    f"Keeping the latest parsed record."
                                )
                            records_by_id[rid] = record
                    except Exception as err:
                        logger.error(
                            f"Unexpected error validating record at line {line_idx} "
                            f"in '{file_name}': {err}"
                        )
        except PermissionError as err:
            logger.error(f"Permission denied while reading dataset file '{file_path}': {err}")
        except Exception as err:
            logger.error(f"Failed to read dataset file '{file_path}': {err}")

    logger.info(f"Completed loading datasets. Total unique valid records: {len(records_by_id)}.")
    return records_by_id


def filter_existing_ids(collection: Any, ids: List[str]) -> Set[str]:
    """Queries ChromaDB to find which IDs from the given list already exist.

    Args:
        collection (Any): The instantiated ChromaDB Collection.
        ids (List[str]): List of record IDs to check.

    Returns:
        Set[str]: A set containing all IDs that are already stored in ChromaDB.
    """
    existing_ids: Set[str] = set()
    query_chunk_size = 1000

    for i in range(0, len(ids), query_chunk_size):
        chunk = ids[i : i + query_chunk_size]
        try:
            result = collection.get(ids=chunk)
            if result and "ids" in result:
                existing_ids.update(result["ids"])
        except Exception as err:
            logger.error(f"Error querying ChromaDB collection for existing IDs: {err}")
            raise
    return existing_ids


def seed(db_path: str = DEFAULT_DB_PATH, corpus_dir: str = DEFAULT_CORPUS_DIR) -> None:
    """Seeds the ChromaDB database with the attack corpus dataset.

    Args:
        db_path (str): The persistent directory path for ChromaDB.
        corpus_dir (str): The directory containing the source corpus files.

    Raises:
        RuntimeError: If critical failures occur in database initialization or querying.
    """
    import chromadb

    # 1. Load and parse all dataset files
    records_by_id = load_all_records(corpus_dir)
    if not records_by_id:
        logger.warning("No valid records loaded. Seeding process completed with 0 updates.")
        return

    # 2. Instantiate persistent ChromaDB client and collection
    logger.info(f"Connecting to persistent ChromaDB client at '{db_path}'")
    try:
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_or_create_collection(name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"})
    except Exception as err:
        logger.critical(f"ChromaDB client initialization or collection retrieval failed: {err}")
        raise RuntimeError(f"ChromaDB startup error: {err}") from err

    # 3. Filter existing IDs for idempotency
    all_ids = list(records_by_id.keys())
    logger.info("Checking ChromaDB for existing record IDs to prevent vector duplicates...")
    try:
        existing_ids = filter_existing_ids(collection, all_ids)
    except Exception as err:
        logger.critical(f"Failed checking existing vectors in collection: {err}")
        raise RuntimeError(f"ChromaDB idempotency verification failed: {err}") from err

    to_insert_ids = [rid for rid in all_ids if rid not in existing_ids]
    if not to_insert_ids:
        logger.info("All parsed records already exist in the ChromaDB database. Seeding skipped.")
        return

    logger.info(f"Seeding {len(to_insert_ids)} new vector entries into the database...")

    # 4. Batch embed and insert remaining items
    total_new = len(to_insert_ids)
    for i in range(0, total_new, BATCH_SIZE):
        chunk_ids = to_insert_ids[i : i + BATCH_SIZE]
        chunk_records = [records_by_id[rid] for rid in chunk_ids]
        chunk_prompts = [rec["prompt"] for rec in chunk_records]

        logger.info(
            f"Generating embeddings for batch {i // BATCH_SIZE + 1} of "
            f"{(total_new + BATCH_SIZE - 1) // BATCH_SIZE} ({len(chunk_ids)} prompts)..."
        )

        try:
            embeddings = embed_batch(chunk_prompts)
        except Exception as err:
            logger.error(
                f"Embedding generation failed for batch starting at index {i}: {err}. "
                f"Skipping this batch."
            )
            continue

        # Format metadata dictionary list for ChromaDB
        metadatas = [
            {
                "family": rec["family"],
                "severity": rec["severity"],
                "source_file": rec["source_file"],
                "timestamp": rec["timestamp"],
            }
            for rec in chunk_records
        ]

        try:
            collection.add(
                ids=chunk_ids,
                embeddings=embeddings,
                documents=chunk_prompts,
                metadatas=metadatas,
            )
            logger.info(f"Successfully populated database with batch of {len(chunk_ids)} records.")
        except Exception as err:
            logger.error(
                f"ChromaDB insert failed for batch starting at index {i}: {err}. "
                f"Skipping this batch."
            )

    logger.info("ChromaDB database seeding complete.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ChromaDB Seeder script for prompt injection dataset.")
    parser.add_argument(
        "--db-path",
        type=str,
        default=DEFAULT_DB_PATH,
        help="Local directory where ChromaDB data will be persisted.",
    )
    parser.add_argument(
        "--corpus-dir",
        type=str,
        default=DEFAULT_CORPUS_DIR,
        help="Local directory containing the JSONL attack corpus.",
    )

    args = parser.parse_args()

    try:
        seed(db_path=args.db_path, corpus_dir=args.corpus_dir)
    except Exception as main_err:
        logger.error(f"Seeding process encountered a fatal error: {main_err}")
        sys.exit(1)
