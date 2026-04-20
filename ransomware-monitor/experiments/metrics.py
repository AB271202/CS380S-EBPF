#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
import sys

DEFAULT_GROUP_COLUMNS = ("scenario_id", "source", "variant", "family")


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
        "--group-by",
        action="append",
        default=[],
        help="Optional column to summarize by. Repeat to include multiple columns.",
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


def is_true(value):
    return str(value).strip() == "1"


def summarize_rows(rows):
    tp = fp = tn = fn = 0
    failed_runs = timed_out_runs = predicted_positive_runs = 0

    for row in rows:
        actual_positive = is_true(row.get("actual_positive", "0"))
        predicted_positive = is_true(row.get("predicted_positive", "0"))
        if predicted_positive:
            predicted_positive_runs += 1
        if row.get("workload_exit_code", "0") not in {"", "0"}:
            failed_runs += 1
        if is_true(row.get("workload_timed_out", "0")):
            timed_out_runs += 1

        if actual_positive and predicted_positive:
            tp += 1
        elif (not actual_positive) and predicted_positive:
            fp += 1
        elif (not actual_positive) and (not predicted_positive):
            tn += 1
        else:
            fn += 1

    total = len(rows)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    fpr = safe_div(fp, fp + tn)
    accuracy = safe_div(tp + tn, total)
    f1 = safe_div(2 * precision * recall, precision + recall)
    balanced_accuracy = (recall + specificity) / 2 if total else 0.0

    return {
        "runs": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "predicted_positive_runs": predicted_positive_runs,
        "failed_runs": failed_runs,
        "timed_out_runs": timed_out_runs,
        "precision": precision,
        "recall_tpr": recall,
        "specificity_tnr": specificity,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "f1": f1,
        "balanced_accuracy": balanced_accuracy,
    }


def print_overall_summary(summary):
    print("Confusion Matrix")
    print(f"TP={summary['tp']}  FP={summary['fp']}")
    print(f"FN={summary['fn']}  TN={summary['tn']}")
    print("")
    print("Metrics")
    print(f"Runs:                {summary['runs']}")
    print(f"Predicted Positive:  {summary['predicted_positive_runs']}")
    print(f"Failed Workloads:    {summary['failed_runs']}")
    print(f"Timed Out Workloads: {summary['timed_out_runs']}")
    print(f"Precision:           {summary['precision']:.4f}")
    print(f"Recall (TPR):        {summary['recall_tpr']:.4f}")
    print(f"Specificity (TNR):   {summary['specificity_tnr']:.4f}")
    print(f"False Positive Rate: {summary['false_positive_rate']:.4f}")
    print(f"Accuracy:            {summary['accuracy']:.4f}")
    print(f"F1 Score:            {summary['f1']:.4f}")
    print(f"Balanced Accuracy:   {summary['balanced_accuracy']:.4f}")


def group_rows(rows, column):
    groups = {}
    for row in rows:
        key = row.get(column, "") or "(empty)"
        groups.setdefault(key, []).append(row)
    return groups


def print_breakdown(rows, column):
    print(f"\nBreakdown by {column}")
    for key in sorted(group_rows(rows, column)):
        group = group_rows(rows, column)[key]
        summary = summarize_rows(group)
        label = ""
        labels = {row.get("label", "") for row in group if row.get("label", "")}
        if len(labels) == 1:
            label = f" label={next(iter(labels))}"
        print(
            f"{key}:{label} runs={summary['runs']} "
            f"TP={summary['tp']} FP={summary['fp']} TN={summary['tn']} FN={summary['fn']} "
            f"precision={summary['precision']:.3f} recall={summary['recall_tpr']:.3f} "
            f"fpr={summary['false_positive_rate']:.3f}"
        )


def print_failed_runs(rows):
    failed_rows = [
        row for row in rows if row.get("workload_exit_code", "0") not in {"", "0"}
        or is_true(row.get("workload_timed_out", "0"))
    ]
    if not failed_rows:
        return []

    print("\nWorkload Failures")
    for row in failed_rows:
        print(
            f"{row.get('run_id', '')}: exit={row.get('workload_exit_code', '')} "
            f"timed_out={row.get('workload_timed_out', '')} "
            f"scenario={row.get('scenario_id', '')}"
        )
    return failed_rows


def main():
    args = parse_args()
    results_path = Path(args.results).resolve()
    with results_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    if not rows:
        raise ValueError(f"No result rows found in {results_path}")

    overall = summarize_rows(rows)
    print_overall_summary(overall)
    failed_rows = print_failed_runs(rows)

    requested_columns = args.group_by or [
        column for column in DEFAULT_GROUP_COLUMNS
        if any(row.get(column, "") for row in rows)
    ]
    requested_columns = list(dict.fromkeys(requested_columns))

    grouped = {}
    for column in requested_columns:
        if not any(column in row for row in rows):
            continue
        grouped[column] = {
            key: summarize_rows(group)
            for key, group in group_rows(rows, column).items()
        }
        print_breakdown(rows, column)

    payload = {
        "overall": overall,
        "grouped": grouped,
        "failed_runs": [
            {
                "run_id": row.get("run_id", ""),
                "scenario_id": row.get("scenario_id", ""),
                "workload_exit_code": row.get("workload_exit_code", ""),
                "workload_timed_out": row.get("workload_timed_out", ""),
            }
            for row in failed_rows
        ],
    }

    if args.json_out:
        json_out_path = Path(args.json_out).resolve()
        try:
            json_out_path.parent.mkdir(parents=True, exist_ok=True)
            json_out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"\nWrote metrics JSON to {json_out_path}")
        except PermissionError:
            print(
                f"\n[WARN] Could not write metrics JSON to {json_out_path} due to permissions.",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
