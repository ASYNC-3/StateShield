"""Adversarial Evaluation Script for Tier-1 Prompt Security Layer.

This script loads the attack corpus prompts from the JSONL files, executes them
against the Tier-1 Semantic Similarity filter, compiles classification metrics
(accuracy, precision, recall, F1, confusion matrix) for both safety decisions
and family categories, and exports the results to a CSV file.
"""

import csv
import json
import logging
import os
import sys
import time
from collections import Counter
from typing import Any, Dict, List

# Setup path resolution to support absolute backend imports
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("eval_adversarial_set")

try:
    # Import the Tier-1 detection and embedder interfaces
    from backend.core.tier1_filter import check_tier1
except ImportError as err:
    logger.critical(
        f"Failed to import check_tier1 from backend.core.tier1_filter. "
        f"Ensure the filter module is fully implemented. Error: {err}"
    )
    raise

# Constants
CORPUS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "attack_corpus"))
CSV_OUTPUT_PATH = os.path.abspath(os.path.join(ROOT_DIR, "evaluation_results.csv"))
DATASET_FILES = [
    "direct_injection.jsonl",
    "jailbreak_roleplay.jsonl",
    "obfuscation.jsonl",
    "extraction_leakage.jsonl",
    "benign_tricky.jsonl"
]


def get_expected_decision(family: str, severity: str) -> str:
    """Maps a prompt's family and severity to the ground truth security decision.

    Args:
        family (str): The true attack family of the prompt.
        severity (str): The severity level (low, medium, high) of the attack.

    Returns:
        str: The expected security action ('block', 'escalate', or 'pass').
    """
    if family == "benign_tricky":
        return "pass"
    if severity == "high":
        return "block"
    if severity == "medium":
        return "escalate"
    # Low-severity attacks default to escalate to initiate containment/audits
    return "escalate"


def calculate_classification_metrics(y_true: List[str], y_pred: List[str], labels: List[str]) -> Dict[str, Any]:
    """Calculates precision, recall, F1-score, and support for each class label.

    Args:
        y_true (List[str]): Ground truth labels.
        y_pred (List[str]): Predicted labels.
        labels (List[str]): All possible label classes.

    Returns:
        Dict[str, Any]: A dictionary containing per-class metrics and averages.
    """
    metrics = {}
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)
        support = sum(1 for t in y_true if t == label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support
        }

    total_support = sum(m["support"] for m in metrics.values())
    accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true) if y_true else 0.0

    # Macro averages
    macro_precision = sum(m["precision"] for m in metrics.values()) / len(labels) if labels else 0.0
    macro_recall = sum(m["recall"] for m in metrics.values()) / len(labels) if labels else 0.0
    macro_f1 = sum(m["f1"] for m in metrics.values()) / len(labels) if labels else 0.0

    # Weighted averages
    if total_support > 0:
        weighted_precision = sum(m["precision"] * m["support"] for m in metrics.values()) / total_support
        weighted_recall = sum(m["recall"] * m["support"] for m in metrics.values()) / total_support
        weighted_f1 = sum(m["f1"] * m["support"] for m in metrics.values()) / total_support
    else:
        weighted_precision, weighted_recall, weighted_f1 = 0.0, 0.0, 0.0

    return {
        "accuracy": accuracy,
        "per_class": metrics,
        "macro": {"precision": macro_precision, "recall": macro_recall, "f1": macro_f1},
        "weighted": {"precision": weighted_precision, "recall": weighted_recall, "f1": weighted_f1}
    }


def print_confusion_matrix(y_true: List[str], y_pred: List[str], labels: List[str], title: str) -> None:
    """Generates and prints an aligned textual confusion matrix.

    Args:
        y_true (List[str]): Ground truth labels.
        y_pred (List[str]): Predicted labels.
        labels (List[str]): List of labels representing rows and columns.
        title (str): Header title for the printed confusion matrix.
    """
    matrix = {l_true: {l_pred: 0 for l_pred in labels} for l_true in labels}
    for t, p in zip(y_true, y_pred):
        if t in matrix and p in matrix[t]:
            matrix[t][p] += 1

    max_len = max(len(str(l)) for l in labels)
    col_width = max(max_len + 3, 10)

    print(f"\n=== {title} ===")
    print(" " * col_width + "".join(f"{str(l):>{col_width}}" for l in labels))
    print("-" * (col_width * (len(labels) + 1)))
    for t in labels:
        row = f"{str(t):<{col_width}}"
        for p in labels:
            row += f"{matrix[t][p]:>{col_width}}"
        print(row)
    print("=" * (col_width * (len(labels) + 1)) + "\n")


def print_report(
    decision_metrics: Dict[str, Any],
    family_metrics: Dict[str, Any],
    decision_true: List[str],
    decision_pred: List[str],
    family_true: List[str],
    family_pred: List[str],
    similarities: List[float],
    runtime_stats: Dict[str, float]
) -> None:
    """Prints a detailed performance evaluation report for the CLI or research logs.

    Args:
        decision_metrics (Dict[str, Any]): Mapped metrics for decision quality.
        family_metrics (Dict[str, Any]): Mapped metrics for attack classification quality.
        decision_true (List[str]): True decisions list.
        decision_pred (List[str]): Mapped predicted decisions list.
        family_true (List[str]): True source families.
        family_pred (List[str]): Matched similarity families.
        similarities (List[float]): Collected float similarity scores.
        runtime_stats (Dict[str, float]): Run duration metrics.
    """
    total_samples = len(decision_true)
    decision_counts = Counter(decision_pred)

    print("\n" + "=" * 60)
    print("             TIER-1 PROMPT SECURITY EVALUATION REPORT")
    print("=" * 60)
    print(f"Total Samples Processed: {total_samples}")
    print(f"Total Evaluation Time: {runtime_stats['total_time']:.2f} seconds")
    print(f"Throughput: {runtime_stats['throughput']:.2f} prompts/sec")
    print(f"Average Latency: {runtime_stats['avg_latency_ms']:.2f} ms/prompt")
    print("-" * 60)

    # Decisions Distribution Rates
    block_rate = (decision_counts.get("block", 0) / total_samples) * 100 if total_samples else 0
    escalate_rate = (decision_counts.get("escalate", 0) / total_samples) * 100 if total_samples else 0
    pass_rate = (decision_counts.get("pass", 0) / total_samples) * 100 if total_samples else 0

    print("DECISION DISTRIBUTION RATES:")
    print(f"  * BLOCK Rate:      {block_rate:.2f}% ({decision_counts.get('block', 0)} prompts)")
    print(f"  * ESCALATE Rate:   {escalate_rate:.2f}% ({decision_counts.get('escalate', 0)} prompts)")
    print(f"  * PASS Rate:       {pass_rate:.2f}% ({decision_counts.get('pass', 0)} prompts)")
    print("-" * 60)

    # Similarity Stats
    if similarities:
        print("SEMANTIC SIMILARITY METRICS:")
        print(f"  * Highest Similarity: {max(similarities):.4f}")
        print(f"  * Lowest Similarity:  {min(similarities):.4f}")
        print(f"  * Average Similarity: {sum(similarities) / len(similarities):.4f}")
    print("-" * 60)

    # Security Decision Performance
    print("SECURITY DECISION CLASSIFICATION PERFORMANCE:")
    print(f"  * Overall Accuracy: {decision_metrics['accuracy']:.4f}")
    print("\n  Per-Decision Details:")
    print(f"    {'Decision':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("    " + "-" * 55)
    for dec, info in decision_metrics["per_class"].items():
        print(f"    {dec:<12} | {info['precision']:<10.4f} | {info['recall']:<10.4f} | {info['f1']:<10.4f} | {info['support']:<8}")

    print("\n  Averages:")
    print(f"    Macro Avg    | {decision_metrics['macro']['precision']:<10.4f} | {decision_metrics['macro']['recall']:<10.4f} | {decision_metrics['macro']['f1']:<10.4f}")
    print(f"    Weighted Avg | {decision_metrics['weighted']['precision']:<10.4f} | {decision_metrics['weighted']['recall']:<10.4f} | {decision_metrics['weighted']['f1']:<10.4f}")
    print("-" * 60)

    # Attack Family Classification Performance
    print("ATTACK FAMILY MATCHING PERFORMANCE:")
    print(f"  * Overall Accuracy: {family_metrics['accuracy']:.4f}")
    print("\n  Per-Family Details:")
    print(f"    {'Family Class':<20} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("    " + "-" * 67)
    for fam, info in family_metrics["per_class"].items():
        print(f"    {fam:<20} | {info['precision']:<10.4f} | {info['recall']:<10.4f} | {info['f1']:<10.4f} | {info['support']:<8}")

    print("\n  Averages:")
    print(f"    Macro Avg    | {family_metrics['macro']['precision']:<10.4f} | {family_metrics['macro']['recall']:<10.4f} | {family_metrics['macro']['f1']:<10.4f}")
    print(f"    Weighted Avg | {family_metrics['weighted']['precision']:<10.4f} | {family_metrics['weighted']['recall']:<10.4f} | {family_metrics['weighted']['f1']:<10.4f}")
    print("=" * 60)

    # Print Textual Confusion Matrices
    print_confusion_matrix(decision_true, decision_pred, ["block", "escalate", "pass"], "DECISION CONFUSION MATRIX")
    print_confusion_matrix(family_true, family_pred, family_metrics["per_class"].keys(), "FAMILY MATCHING CONFUSION MATRIX")


def run_evaluation() -> None:
    """Executes the evaluation pipeline across all loaded attack corpus datasets.

    Loads the records, executes predictions, collects performance analytics,
    generates printed reports, and exports raw evaluation details to CSV.
    """
    logger.info("Starting adversarial dataset evaluation pipeline...")

    if not os.path.isdir(CORPUS_DIR):
        logger.error(f"Attack corpus directory does not exist at '{CORPUS_DIR}'. Aborting evaluation.")
        return

    records: List[Dict[str, Any]] = []

    # 1. Load datasets from files
    for file_name in DATASET_FILES:
        file_path = os.path.join(CORPUS_DIR, file_name)
        if not os.path.isfile(file_path):
            logger.warning(f"Dataset file '{file_name}' not found at '{file_path}'. Skipping.")
            continue

        family_name = file_name.replace(".jsonl", "")
        logger.info(f"Loading evaluation prompts from: '{file_name}'")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    cleaned_line = line.strip()
                    if not cleaned_line:
                        continue
                    try:
                        data = json.loads(cleaned_line)
                        prompt = data.get("prompt")
                        severity = data.get("severity", "medium")

                        if not prompt or not prompt.strip():
                            continue

                        records.append({
                            "prompt": prompt.strip(),
                            "family": family_name,
                            "severity": severity.strip()
                        })
                    except json.JSONDecodeError as err:
                        logger.error(f"Failed to parse JSON in '{file_name}' line {line_idx}: {err}")
                    except Exception as err:
                        logger.error(f"Unexpected row read error in '{file_name}' line {line_idx}: {err}")
        except Exception as err:
            logger.error(f"Failed to open/read dataset file '{file_path}': {err}")

    if not records:
        logger.error("No valid evaluation records were loaded. Evaluation aborted.")
        return

    logger.info(f"Loaded {len(records)} test cases. Executing check_tier1 evaluations...")

    # Lists to compile metrics
    family_true: List[str] = []
    family_pred: List[str] = []
    decision_true: List[str] = []
    decision_pred: List[str] = []
    similarities: List[float] = []

    csv_rows = []

    # 2. Pipeline processing
    start_time = time.perf_counter()

    for idx, record in enumerate(records, start=1):
        prompt = record["prompt"]
        true_family = record["family"]
        severity = record["severity"]

        expected_decision = get_expected_decision(true_family, severity)

        try:
            # Query the Tier-1 Filter
            res = check_tier1(prompt)

            pred_decision = res["decision"]
            pred_family = res["nearest_family"]
            similarity = res["similarity"]

            # Save stats for aggregates
            family_true.append(true_family)
            family_pred.append(pred_family)
            decision_true.append(expected_decision)
            decision_pred.append(pred_decision)
            similarities.append(similarity)

            csv_rows.append([
                prompt,
                true_family,
                severity,
                f"{similarity:.6f}",
                pred_family,
                pred_decision
            ])

        except Exception as err:
            logger.error(f"Evaluation failed on test record {idx} ('{true_family}'): {err}")
            # Maintain alignment in stats by recording a fallback 'pass' decision
            family_true.append(true_family)
            family_pred.append("unlabeled_emerging")
            decision_true.append(expected_decision)
            decision_pred.append("pass")
            similarities.append(0.0)

            csv_rows.append([
                prompt,
                true_family,
                severity,
                "0.000000",
                "unlabeled_emerging",
                "pass (error)"
            ])

    end_time = time.perf_counter()

    # 3. Calculate Performance Metrics
    total_time = end_time - start_time
    avg_latency = (total_time / len(records)) * 1000
    throughput = len(records) / total_time

    runtime_stats = {
        "total_time": total_time,
        "avg_latency_ms": avg_latency,
        "throughput": throughput
    }

    # 4. Compute Classification Reports
    decision_metrics = calculate_classification_metrics(decision_true, decision_pred, ["block", "escalate", "pass"])
    
    # Include all 5 families + any potential 'unlabeled_emerging' fallback classes
    all_family_classes = sorted(list(set(family_true + family_pred)))
    family_metrics = calculate_classification_metrics(family_true, family_pred, all_family_classes)

    # 5. Export results to CSV
    logger.info(f"Exporting raw evaluation results to: '{CSV_OUTPUT_PATH}'")
    try:
        with open(CSV_OUTPUT_PATH, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Prompt", "Family", "Severity", "Similarity", "Prediction", "Decision"])
            writer.writerows(csv_rows)
        logger.info("CSV export completed successfully.")
    except Exception as err:
        logger.error(f"Failed to write evaluation CSV results: {err}")

    # 6. Generate final print outputs
    print_report(
        decision_metrics=decision_metrics,
        family_metrics=family_metrics,
        decision_true=decision_true,
        decision_pred=decision_pred,
        family_true=family_true,
        family_pred=family_pred,
        similarities=similarities,
        runtime_stats=runtime_stats
    )


if __name__ == "__main__":
    try:
        run_evaluation()
    except Exception as main_err:
        logger.error(f"Evaluation pipeline failed with a fatal error: {main_err}")
        sys.exit(1)
