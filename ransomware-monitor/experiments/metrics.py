#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compute TP/FP/TN/FN and classification metrics from results.csv"
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Path to CSV produced by experiments/run_experiments.py",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write metrics JSON.",
    )
    return parser.parse_args()


def safe_div(numer, denom):
    if denom == 0:
        return 0.0
    return numer / denom


def main():
    args = parse_args()
    results_path = Path(args.results).resolve()
    tp = fp = tn = fn = 0
    total = 0

    with results_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            total += 1
            actual_positive = row.get("actual_positive", "0") == "1"
            predicted_positive = row.get("predicted_positive", "0") == "1"
            if actual_positive and predicted_positive:
                tp += 1
            elif (not actual_positive) and predicted_positive:
                fp += 1
            elif (not actual_positive) and (not predicted_positive):
                tn += 1
            else:
                fn += 1

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    fpr = safe_div(fp, fp + tn)
    accuracy = safe_div(tp + tn, total)

    metrics = {
        "runs": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall_tpr": recall,
        "specificity_tnr": specificity,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
    }

    print("Confusion Matrix")
    print(f"TP={tp}  FP={fp}")
    print(f"FN={fn}  TN={tn}")
    print("")
    print("Metrics")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall (TPR):        {recall:.4f}")
    print(f"Specificity (TNR):   {specificity:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"Accuracy:            {accuracy:.4f}")

    if args.json_out:
        json_out_path = Path(args.json_out).resolve()
        try:
            json_out_path.parent.mkdir(parents=True, exist_ok=True)
            json_out_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
            print(f"\nWrote metrics JSON to {json_out_path}")
        except PermissionError:
            print(
                f"\n[WARN] Could not write metrics JSON to {json_out_path} due to permissions.",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
