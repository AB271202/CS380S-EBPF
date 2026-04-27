#!/usr/bin/env python3
"""Run a whitelist ablation study across the ransomware experiment suites.

Each variant keeps the detector unchanged except for one whitelist entry
being removed through the JSON whitelist-config path. The script runs the
four core suites (legacy, T1486, benign, behavioral), collects the per-suite
confusion matrices, and writes both CSV and Markdown summaries.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Dict, Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = REPO_ROOT / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from detector import DEFAULT_WHITELISTED_PROCESSES  # noqa: E402


SUITES: List[Tuple[str, str]] = [
    ("legacy", "experiments/scenarios.csv"),
    ("t1486", "experiments/scenarios_atomic_t1486_official.csv"),
    ("benign", "experiments/scenarios_benign_stress.csv"),
    ("behavioral", "experiments/scenarios_behavioral.csv"),
]
SUITE_MAP = dict(SUITES)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run an ablation study over the detector whitelist and summarize "
            "per-suite TP/FP/TN/FN counts."
        )
    )
    parser.add_argument(
        "--output-dir",
        default="experiments/out/whitelist_ablation",
        help="Directory for per-variant results and summary tables.",
    )
    parser.add_argument(
        "--base-config",
        help=(
            "Optional whitelist config JSON to treat as the baseline policy. "
            "When provided, the baseline row uses this config and each "
            "ablation row removes one entry from its effective whitelist."
        ),
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Repeat count passed through to experiments/run_experiments.py.",
    )
    parser.add_argument(
        "--entries",
        default="all",
        help=(
            "Comma-separated whitelist entries to ablate, or 'all' "
            "(default: all)."
        ),
    )
    parser.add_argument(
        "--keep-suite-artifacts",
        action="store_true",
        help=(
            "Keep the logs/ and runs/ directories for every suite. "
            "By default they are deleted after results.csv is parsed to "
            "reduce disk usage."
        ),
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Run only the full-whitelist baseline row.",
    )
    parser.add_argument(
        "--suites",
        default="all",
        help=(
            "Comma-separated suite names to run "
            f"({', '.join(SUITE_MAP)}), or 'all' (default: all)."
        ),
    )
    return parser.parse_args()


def ensure_root() -> None:
    if os.geteuid() != 0:
        print(
            "This ablation runner must be run as root because it invokes the "
            "eBPF experiment harness.",
            file=sys.stderr,
        )
        print(
            "Try: sudo -E python3 experiments/whitelist_ablation.py",
            file=sys.stderr,
        )
        sys.exit(2)


def chown_path_recursive(path: Path, uid: int, gid: int) -> None:
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for name in dirs:
            os.chown(os.path.join(root, name), uid, gid)
        for name in files:
            os.chown(os.path.join(root, name), uid, gid)


def restore_output_ownership_if_needed(output_dir: Path) -> None:
    sudo_uid = os.getenv("SUDO_UID")
    sudo_gid = os.getenv("SUDO_GID")
    if not sudo_uid or not sudo_gid:
        return
    try:
        uid = int(sudo_uid)
        gid = int(sudo_gid)
    except ValueError:
        return
    try:
        chown_path_recursive(output_dir, uid, gid)
    except PermissionError:
        print(
            f"[WARN] Could not restore ownership for {output_dir}.",
            file=sys.stderr,
        )


def load_config_payload(config_path: Path | None) -> dict:
    if config_path is None:
        return {}
    with config_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def effective_whitelist_from_config(config_path: Path | None) -> List[str]:
    entries = set(DEFAULT_WHITELISTED_PROCESSES)
    if config_path is None:
        return sorted(entries)
    cfg = load_config_payload(config_path)
    entries.update(cfg.get("whitelisted_processes", []))
    entries.difference_update(cfg.get("remove_whitelisted_processes", []))
    return sorted(entries)


def selected_entries(raw: str, available_entries: List[str]) -> List[str]:
    all_entries = sorted(available_entries)
    if raw.strip().lower() == "all":
        return all_entries
    requested = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = sorted(set(requested) - set(all_entries))
    if unknown:
        raise ValueError(
            "Unknown whitelist entries requested: " + ", ".join(unknown)
        )
    return requested


def selected_suites(raw: str) -> List[Tuple[str, str]]:
    if raw.strip().lower() == "all":
        return SUITES
    requested = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = sorted(set(requested) - set(SUITE_MAP))
    if unknown:
        raise ValueError("Unknown suites requested: " + ", ".join(unknown))
    return [(name, SUITE_MAP[name]) for name in requested]


def variant_slug(name: str) -> str:
    if name == "__baseline__":
        return "baseline"
    return "minus_" + "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in name
    )


def write_variant_config(
    configs_dir: Path,
    removed_entry: str | None,
    base_config: Path | None,
) -> Path | None:
    if removed_entry is None and base_config is None:
        return None
    configs_dir.mkdir(parents=True, exist_ok=True)
    slug = variant_slug(removed_entry or "__baseline__")
    config_path = configs_dir / f"{slug}.json"
    payload = load_config_payload(base_config)
    removed = list(payload.get("remove_whitelisted_processes", []))
    if removed_entry is not None and removed_entry not in removed:
        removed.append(removed_entry)
    if removed:
        payload["remove_whitelisted_processes"] = removed
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return config_path


def run_suite(
    suite_name: str,
    scenario_path: str,
    suite_output_dir: Path,
    repeats: int,
    whitelist_config: Path | None,
) -> Path:
    if suite_output_dir.exists():
        shutil.rmtree(suite_output_dir)
    suite_output_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("THRESHOLD_ENTROPY", "5.8")
    env.setdefault("THRESHOLD_WRITES", "1")
    env.setdefault("TIME_WINDOW_SEC", "3.0")
    if whitelist_config is not None:
        env["WHITELIST_CONFIG"] = str(whitelist_config)
    else:
        env.pop("WHITELIST_CONFIG", None)

    cmd = [
        "python3",
        "experiments/run_experiments.py",
        "--scenarios",
        scenario_path,
        "--output-dir",
        str(suite_output_dir),
        "--repeats",
        str(repeats),
    ]
    subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=True)
    return suite_output_dir / "results.csv"


def confusion_from_results(results_path: Path) -> Dict[str, int]:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    with results_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            actual_positive = row["actual_positive"] == "1"
            predicted_positive = row["predicted_positive"] == "1"
            if actual_positive and predicted_positive:
                counts["TP"] += 1
            elif (not actual_positive) and predicted_positive:
                counts["FP"] += 1
            elif (not actual_positive) and (not predicted_positive):
                counts["TN"] += 1
            else:
                counts["FN"] += 1
    return counts


def prune_suite_artifacts(suite_output_dir: Path) -> None:
    for child in ("logs", "runs"):
        target = suite_output_dir / child
        if target.exists():
            shutil.rmtree(target)


def write_summary_csv(
    output_dir: Path,
    rows: Iterable[dict],
    suites: List[Tuple[str, str]],
) -> Path:
    rows = list(rows)
    summary_path = output_dir / "summary.csv"
    fixed = ["variant", "removed_entry"]
    dynamic = [
        f"{suite}_{suffix}"
        for suite, _ in suites
        for suffix in ("tp", "fp", "tn", "fn")
    ]
    fieldnames = fixed + dynamic
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return summary_path


def write_summary_md(
    output_dir: Path,
    rows: Iterable[dict],
    repeats: int,
    suites: List[Tuple[str, str]],
) -> Path:
    rows = list(rows)
    md_path = output_dir / "summary.md"
    suite_headers = []
    for suite_name, _ in suites:
        label = suite_name.capitalize()
        suite_headers.extend(
            [f"{label} TP", f"{label} FP", f"{label} TN", f"{label} FN"]
        )
    header = "| Variant | Removed | " + " | ".join(suite_headers) + " |"
    divider = "|---|---|" + "|".join(["---:" for _ in suite_headers]) + "|"
    lines = [
        "# Whitelist Ablation Results",
        "",
        f"- Repeats per scenario: `{repeats}`",
        (
            "- Tuned env: "
            f"`THRESHOLD_ENTROPY={os.environ.get('THRESHOLD_ENTROPY', '5.8')}` "
            f"`THRESHOLD_WRITES={os.environ.get('THRESHOLD_WRITES', '1')}` "
            f"`TIME_WINDOW_SEC={os.environ.get('TIME_WINDOW_SEC', '3.0')}`"
        ),
        "",
        header,
        divider,
    ]
    for row in rows:
        cells = [row["variant"], row["removed_entry"]]
        for suite_name, _ in suites:
            lowered = suite_name.lower()
            cells.extend(
                [
                    str(row.get(f"{lowered}_tp", "")),
                    str(row.get(f"{lowered}_fp", "")),
                    str(row.get(f"{lowered}_tn", "")),
                    str(row.get(f"{lowered}_fn", "")),
                ]
            )
        lines.append("| " + " | ".join(cells) + " |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return md_path


def build_row(
    variant_name: str,
    removed_entry: str,
    suite_counts: Dict[str, Dict[str, int]],
    suites: List[Tuple[str, str]],
) -> dict:
    row = {
        "variant": variant_name,
        "removed_entry": removed_entry,
    }
    for suite_name, _ in suites:
        counts = suite_counts[suite_name]
        lowered = suite_name.lower()
        row[f"{lowered}_tp"] = counts["TP"]
        row[f"{lowered}_fp"] = counts["FP"]
        row[f"{lowered}_tn"] = counts["TN"]
        row[f"{lowered}_fn"] = counts["FN"]
    return row


def main() -> None:
    args = parse_args()
    ensure_root()

    output_dir = (REPO_ROOT / args.output_dir).resolve()
    base_config = (REPO_ROOT / args.base_config).resolve() if args.base_config else None
    configs_dir = output_dir / "configs"
    variants_dir = output_dir / "variants"
    output_dir.mkdir(parents=True, exist_ok=True)
    variants_dir.mkdir(parents=True, exist_ok=True)
    try:
        available_entries = effective_whitelist_from_config(base_config)
        entries = [] if args.baseline_only else selected_entries(args.entries, available_entries)
        suites = selected_suites(args.suites)
        baseline_label = "baseline_config" if base_config else "full_whitelist"
        variants: List[Tuple[str, str | None]] = [(baseline_label, None)]
        variants.extend((f"remove:{entry}", entry) for entry in entries)

        rows = []
        for variant_label, removed_entry in variants:
            whitelist_config = write_variant_config(
                configs_dir,
                removed_entry,
                base_config,
            )
            suite_counts: Dict[str, Dict[str, int]] = {}
            variant_dir = variants_dir / variant_slug(removed_entry or "__baseline__")
            print(
                f"\n=== {variant_label} ===",
                flush=True,
            )
            for suite_name, scenario_path in suites:
                suite_output_dir = variant_dir / suite_name
                print(
                    f"Running {suite_name} -> {suite_output_dir}",
                    flush=True,
                )
                results_path = run_suite(
                    suite_name=suite_name,
                    scenario_path=scenario_path,
                    suite_output_dir=suite_output_dir,
                    repeats=args.repeats,
                    whitelist_config=whitelist_config,
                )
                counts = confusion_from_results(results_path)
                suite_counts[suite_name] = counts
                print(
                    f"  {suite_name}: TP={counts['TP']} FP={counts['FP']} TN={counts['TN']} FN={counts['FN']}",
                    flush=True,
                )
                if not args.keep_suite_artifacts:
                    prune_suite_artifacts(suite_output_dir)

            rows.append(
                build_row(
                    variant_name=variant_label,
                    removed_entry=removed_entry or "(none)",
                    suite_counts=suite_counts,
                    suites=suites,
                )
            )

        summary_csv = write_summary_csv(output_dir, rows, suites=suites)
        summary_md = write_summary_md(
            output_dir,
            rows,
            repeats=args.repeats,
            suites=suites,
        )
        print(f"\nWrote CSV summary to {summary_csv}")
        print(f"Wrote Markdown summary to {summary_md}")
    finally:
        restore_output_ownership_if_needed(output_dir)


if __name__ == "__main__":
    main()
