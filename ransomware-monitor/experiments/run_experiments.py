#!/usr/bin/env python3
import argparse
import csv
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ALERT_PREFIX = "ALERT_JSON:"
REQUIRED_SCENARIO_COLUMNS = {"id", "label", "command"}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run labeled workloads and collect monitor predictions."
    )
    parser.add_argument(
        "--scenarios",
        default="experiments/scenarios.csv",
        help="CSV file with scenario rows: id,label,command[,expected_comm,notes]",
    )
    parser.add_argument(
        "--output-dir",
        default="experiments/out/latest",
        help="Directory to write logs and results.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="How many times to run each scenario.",
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=2.0,
        help="Seconds to wait after starting the monitor.",
    )
    parser.add_argument(
        "--cooldown-delay",
        type=float,
        default=1.5,
        help="Seconds to wait after workload finishes before stopping monitor.",
    )
    parser.add_argument(
        "--command-timeout",
        type=float,
        default=30.0,
        help="Max seconds per workload command.",
    )
    parser.add_argument(
        "--monitor-timeout",
        type=float,
        default=8.0,
        help="Max seconds to wait for monitor shutdown after SIGINT.",
    )
    return parser.parse_args()


def load_scenarios(csv_path):
    scenarios = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_SCENARIO_COLUMNS - set(reader.fieldnames or [])
        if missing:
            missing_str = ", ".join(sorted(missing))
            raise ValueError(f"Scenarios file missing required columns: {missing_str}")
        for row in reader:
            row_id = row["id"].strip()
            label = row["label"].strip().lower()
            command = row["command"].strip()
            expected_comm = row.get("expected_comm", "").strip()
            notes = row.get("notes", "").strip()
            if not row_id or not command:
                continue
            if label not in {"positive", "negative"}:
                raise ValueError(f"Scenario '{row_id}' has invalid label '{label}'")
            scenarios.append(
                {
                    "id": row_id,
                    "label": label,
                    "command": command,
                    "expected_comm": expected_comm,
                    "notes": notes,
                }
            )
    if not scenarios:
        raise ValueError("No scenarios found.")
    return scenarios


def ensure_root():
    if os.geteuid() != 0:
        print(
            "This harness must run as root because the monitor loads eBPF programs.",
            file=sys.stderr,
        )
        print(
            "Try: sudo -E python3 experiments/run_experiments.py",
            file=sys.stderr,
        )
        sys.exit(2)


def chown_path_recursive(path, uid, gid):
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for name in dirs:
            os.chown(os.path.join(root, name), uid, gid)
        for name in files:
            os.chown(os.path.join(root, name), uid, gid)


def restore_output_ownership_if_needed(output_dir):
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
        chown_path_recursive(str(output_dir), uid, gid)
        print(f"Restored ownership of {output_dir} to UID={uid} GID={gid}")
    except PermissionError:
        print(
            f"[WARN] Could not restore ownership for {output_dir}.",
            file=sys.stderr,
        )


def stop_monitor(proc, timeout_seconds):
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=timeout_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.terminate()
    try:
        proc.wait(timeout=2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    proc.wait(timeout=2.0)


def parse_alerts(log_path, run_id):
    alerts = []
    for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.startswith(ALERT_PREFIX):
            continue
        payload = raw_line[len(ALERT_PREFIX) :].strip()
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if obj.get("run_id") != run_id:
            continue
        alerts.append(obj)
    return alerts


def compute_prediction(alerts, expected_comm):
    if not alerts:
        return False, 0
    if not expected_comm:
        return True, len(alerts)
    matching = [a for a in alerts if a.get("comm") == expected_comm]
    return bool(matching), len(matching)


def main():
    args = parse_args()
    ensure_root()
    repo_root = Path(__file__).resolve().parents[1]
    scenarios_path = (repo_root / args.scenarios).resolve()
    output_dir = (repo_root / args.output_dir).resolve()
    logs_dir = output_dir / "logs"
    runs_dir = output_dir / "runs"
    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    try:
        scenarios = load_scenarios(scenarios_path)
        results = []

        for repeat_idx in range(1, args.repeats + 1):
            for scenario in scenarios:
                run_id = f"{scenario['id']}_r{repeat_idx:02d}"
                run_dir = runs_dir / run_id
                run_dir.mkdir(parents=True, exist_ok=True)
                monitor_log = logs_dir / f"{run_id}.monitor.log"
                workload_stdout = logs_dir / f"{run_id}.workload.stdout.log"
                workload_stderr = logs_dir / f"{run_id}.workload.stderr.log"

                monitor_env = os.environ.copy()
                monitor_env["ALERT_JSON"] = "1"
                monitor_env["RUN_ID"] = run_id
                monitor_env["PYTHONUNBUFFERED"] = "1"

                with monitor_log.open("w", encoding="utf-8") as monitor_log_handle:
                    monitor_proc = subprocess.Popen(
                        ["python3", "-u", "agent/main.py"],
                        cwd=str(repo_root),
                        stdout=monitor_log_handle,
                        stderr=subprocess.STDOUT,
                        env=monitor_env,
                    )
                    time.sleep(args.startup_delay)

                    timed_out = False
                    exit_code = None
                    try:
                        workload_proc = subprocess.run(
                            ["bash", "-lc", scenario["command"]],
                            cwd=str(run_dir),
                            capture_output=True,
                            text=True,
                            timeout=args.command_timeout,
                        )
                        exit_code = workload_proc.returncode
                        workload_stdout.write_text(
                            workload_proc.stdout or "",
                            encoding="utf-8",
                        )
                        workload_stderr.write_text(
                            workload_proc.stderr or "",
                            encoding="utf-8",
                        )
                    except subprocess.TimeoutExpired as exc:
                        timed_out = True
                        exit_code = 124
                        workload_stdout.write_text(
                            (exc.stdout or ""),
                            encoding="utf-8",
                        )
                        workload_stderr.write_text(
                            (exc.stderr or ""),
                            encoding="utf-8",
                        )

                    time.sleep(args.cooldown_delay)
                    stop_monitor(monitor_proc, timeout_seconds=args.monitor_timeout)

                alerts = parse_alerts(monitor_log, run_id)
                predicted_positive, matching_alerts = compute_prediction(
                    alerts, scenario["expected_comm"]
                )
                actual_positive = scenario["label"] == "positive"

                results.append(
                    {
                        "run_id": run_id,
                        "scenario_id": scenario["id"],
                        "label": scenario["label"],
                        "expected_comm": scenario["expected_comm"],
                        "predicted": "positive" if predicted_positive else "negative",
                        "actual_positive": "1" if actual_positive else "0",
                        "predicted_positive": "1" if predicted_positive else "0",
                        "alerts_total": str(len(alerts)),
                        "alerts_matching_comm": str(matching_alerts),
                        "workload_exit_code": str(exit_code if exit_code is not None else -1),
                        "workload_timed_out": "1" if timed_out else "0",
                        "command": scenario["command"],
                        "notes": scenario["notes"],
                        "monitor_log": str(monitor_log),
                        "workload_stdout": str(workload_stdout),
                        "workload_stderr": str(workload_stderr),
                    }
                )
                print(
                    f"[{run_id}] label={scenario['label']} predicted="
                    f"{'positive' if predicted_positive else 'negative'} "
                    f"alerts={len(alerts)} matching_comm={matching_alerts}"
                )

        results_path = output_dir / "results.csv"
        with results_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

        tp = fp = tn = fn = 0
        for row in results:
            actual_positive = row["actual_positive"] == "1"
            predicted_positive = row["predicted_positive"] == "1"
            if actual_positive and predicted_positive:
                tp += 1
            elif (not actual_positive) and predicted_positive:
                fp += 1
            elif (not actual_positive) and (not predicted_positive):
                tn += 1
            else:
                fn += 1

        print(f"\nWrote {len(results)} run results to {results_path}")
        print(f"Confusion matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        print(
            "Next: python3 experiments/metrics.py "
            f"--results {results_path}"
        )
    finally:
        restore_output_ownership_if_needed(output_dir)


if __name__ == "__main__":
    main()
