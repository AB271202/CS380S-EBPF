#!/usr/bin/env python3
"""Run the monitor as a long-lived background audit session.

This is meant for "use the laptop normally for a while" sanity checks.
It keeps the monitor in simulate mode, records monitor output and structured
ALERT_JSON lines, and produces a small Markdown summary for later inspection.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = REPO_ROOT / "experiments" / "out" / "live_audit"
ALERT_PREFIX = "ALERT_JSON:"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start/stop/summarize a long-running local audit monitor session."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start a detached live-audit monitor session.")
    start.add_argument(
        "--session-name",
        default=None,
        help="Optional human-friendly suffix for the session directory.",
    )
    start.add_argument(
        "--output-root",
        default=str(OUT_ROOT),
        help="Root directory for live audit sessions.",
    )
    start.add_argument(
        "--verbose",
        action="store_true",
        help="Also log every traced event. Not recommended for long sessions.",
    )
    start.add_argument(
        "--perf-page-cnt",
        type=int,
        default=4096,
        help="Perf buffer page count passed to the monitor via PERF_PAGE_CNT.",
    )

    stop = sub.add_parser("stop", help="Stop a running live-audit session.")
    stop.add_argument("session_dir", help="Session directory printed by the start command.")

    status = sub.add_parser("status", help="Check whether a session is still running.")
    status.add_argument("session_dir", help="Session directory printed by the start command.")

    summarize = sub.add_parser("summarize", help="Summarize alerts for a completed or running session.")
    summarize.add_argument("session_dir", help="Session directory printed by the start command.")

    return parser.parse_args()


def ensure_root() -> None:
    if os.geteuid() != 0:
        print(
            "This helper must run as root because it launches the eBPF monitor.",
            file=sys.stderr,
        )
        print(
            "Try: sudo -E python3 experiments/live_audit.py start",
            file=sys.stderr,
        )
        sys.exit(2)


def restore_output_ownership_if_needed(path: Path) -> None:
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
        for root, dirs, files in os.walk(path):
            os.chown(root, uid, gid)
            for name in dirs:
                os.chown(os.path.join(root, name), uid, gid)
            for name in files:
                os.chown(os.path.join(root, name), uid, gid)
    except PermissionError:
        print(f"[WARN] Could not restore ownership for {path}.", file=sys.stderr)


def timestamp_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def session_dir_from_args(output_root: str, session_name: str | None) -> Path:
    slug = timestamp_slug()
    if session_name:
        suffix = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in session_name)
        slug = f"{slug}_{suffix}"
    return Path(output_root).resolve() / slug


def metadata_path(session_dir: Path) -> Path:
    return session_dir / "session.json"


def pid_path(session_dir: Path) -> Path:
    return session_dir / "monitor.pid"


def monitor_log_path(session_dir: Path) -> Path:
    return session_dir / "monitor.log"


def alerts_jsonl_path(session_dir: Path) -> Path:
    return session_dir / "alerts.jsonl"


def summary_md_path(session_dir: Path) -> Path:
    return session_dir / "summary.md"


def summary_csv_path(session_dir: Path) -> Path:
    return session_dir / "alerts.csv"


def load_metadata(session_dir: Path) -> Dict:
    return json.loads(metadata_path(session_dir).read_text(encoding="utf-8"))


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def start_session(args: argparse.Namespace) -> None:
    ensure_root()

    session_dir = session_dir_from_args(args.output_root, args.session_name)
    session_dir.mkdir(parents=True, exist_ok=False)

    run_id = session_dir.name
    log_path = monitor_log_path(session_dir)
    pidfile = pid_path(session_dir)
    meta = {
        "run_id": run_id,
        "started_at": dt.datetime.now().astimezone().isoformat(),
        "action_mode": "simulate",
        "verbose": bool(args.verbose),
        "perf_page_cnt": int(args.perf_page_cnt),
        "repo_root": str(REPO_ROOT),
    }
    metadata_path(session_dir).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    env = os.environ.copy()
    env["ALERT_JSON"] = "1"
    env["RUN_ID"] = run_id
    env["PYTHONUNBUFFERED"] = "1"
    env["PERF_PAGE_CNT"] = str(args.perf_page_cnt)

    cmd = ["python3", "-u", "agent/main.py", "--action-mode", "simulate"]
    if args.verbose:
        cmd.append("--verbose")

    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=handle,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )

    pidfile.write_text(f"{proc.pid}\n", encoding="utf-8")
    restore_output_ownership_if_needed(session_dir)

    print(f"Started live audit session: {session_dir}")
    print(f"Monitor PID: {proc.pid}")
    print(f"Monitor log: {log_path}")
    print("Stop later with:")
    print(f"  sudo -E python3 experiments/live_audit.py stop {session_dir}")
    print("Summarize later with:")
    print(f"  sudo -E python3 experiments/live_audit.py summarize {session_dir}")


def stop_session(args: argparse.Namespace) -> None:
    ensure_root()

    session_dir = Path(args.session_dir).resolve()
    pidfile = pid_path(session_dir)
    if not pidfile.exists():
        raise SystemExit(f"No pid file found in {session_dir}")

    pid = int(pidfile.read_text(encoding="utf-8").strip())
    if not process_alive(pid):
        print(f"Monitor PID {pid} is already stopped.")
        summarize_session(session_dir)
        restore_output_ownership_if_needed(session_dir)
        return

    os.kill(pid, signal.SIGINT)
    for _ in range(20):
        if not process_alive(pid):
            break
        import time
        time.sleep(0.5)
    else:
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            if not process_alive(pid):
                break
            import time
            time.sleep(0.5)
        else:
            os.kill(pid, signal.SIGKILL)

    print(f"Stopped monitor PID {pid} for session {session_dir}")
    summarize_session(session_dir)
    restore_output_ownership_if_needed(session_dir)


def status_session(args: argparse.Namespace) -> None:
    session_dir = Path(args.session_dir).resolve()
    pidfile = pid_path(session_dir)
    if not pidfile.exists():
        raise SystemExit(f"No pid file found in {session_dir}")
    pid = int(pidfile.read_text(encoding="utf-8").strip())
    state = "running" if process_alive(pid) else "stopped"
    print(f"{session_dir}: PID {pid} is {state}")


def parse_alerts(session_dir: Path) -> List[Dict]:
    log_path = monitor_log_path(session_dir)
    if not log_path.exists():
        return []
    metadata = load_metadata(session_dir)
    run_id = metadata["run_id"]
    alerts: List[Dict] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith(ALERT_PREFIX):
            continue
        payload = line[len(ALERT_PREFIX):].strip()
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if obj.get("run_id") != run_id:
            continue
        alerts.append(obj)
    return alerts


def write_alerts_jsonl(session_dir: Path, alerts: Iterable[Dict]) -> None:
    path = alerts_jsonl_path(session_dir)
    lines = [json.dumps(alert, sort_keys=True) for alert in alerts]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_alerts_csv(session_dir: Path, alerts: List[Dict]) -> None:
    path = summary_csv_path(session_dir)
    fieldnames = [
        "ts",
        "run_id",
        "pid",
        "comm",
        "reason",
        "severity",
        "alert_type",
        "attributed",
        "attributed_from_comm",
        "attributed_from_pid",
        "avg_entropy",
        "unique_files",
        "unique_dirs",
        "filename",
        "deleted_file",
        "scanned_dirs",
        "lineage",
        "exe_path",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row = {field: alert.get(field, "") for field in fieldnames}
            writer.writerow(row)


def summarize_counts(alerts: List[Dict], key: str) -> List[tuple[str, int]]:
    counts: Dict[str, int] = {}
    for alert in alerts:
        value = str(alert.get(key, "(missing)"))
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def summarize_session(session_dir: Path) -> None:
    metadata = load_metadata(session_dir)
    alerts = parse_alerts(session_dir)
    write_alerts_jsonl(session_dir, alerts)
    write_alerts_csv(session_dir, alerts)

    by_reason = summarize_counts(alerts, "reason")
    by_comm = summarize_counts(alerts, "comm")
    critical = [a for a in alerts if a.get("severity") == "critical"]
    high = [a for a in alerts if a.get("severity") == "high"]
    attributed = [a for a in alerts if a.get("attributed")]

    lines = [
        "# Live Audit Summary",
        "",
        f"- Session: `{session_dir.name}`",
        f"- Started at: `{metadata.get('started_at', '')}`",
        f"- Action mode: `{metadata.get('action_mode', '')}`",
        f"- Verbose event logging: `{metadata.get('verbose', False)}`",
        f"- Total alerts: `{len(alerts)}`",
        f"- Critical alerts: `{len(critical)}`",
        f"- High alerts: `{len(high)}`",
        f"- Attributed alerts: `{len(attributed)}`",
        "",
        "## Alerts by Reason",
        "",
        "| Reason | Count |",
        "|---|---:|",
    ]
    for reason, count in by_reason:
        lines.append(f"| {reason} | {count} |")

    lines.extend([
        "",
        "## Alerts by Process Name",
        "",
        "| Comm | Count |",
        "|---|---:|",
    ])
    for comm, count in by_comm:
        lines.append(f"| {comm} | {count} |")

    lines.extend([
        "",
        "## First 20 Alerts",
        "",
        "| Time | Comm | PID | Reason | Severity |",
        "|---|---|---:|---|---|",
    ])
    for alert in alerts[:20]:
        timestamp = alert.get("ts", "")
        try:
            display_time = dt.datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(timespec="seconds")
        except (TypeError, ValueError, OSError):
            display_time = str(timestamp)
        lines.append(
            f"| {display_time} | {alert.get('comm', '')} | {alert.get('pid', '')} | "
            f"{alert.get('reason', '')} | {alert.get('severity', '')} |"
        )

    summary_md_path(session_dir).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote alert JSONL to {alerts_jsonl_path(session_dir)}")
    print(f"Wrote alert CSV to {summary_csv_path(session_dir)}")
    print(f"Wrote Markdown summary to {summary_md_path(session_dir)}")


def main() -> None:
    args = parse_args()
    if args.command == "start":
        start_session(args)
    elif args.command == "stop":
        stop_session(args)
    elif args.command == "status":
        status_session(args)
    elif args.command == "summarize":
        summarize_session(Path(args.session_dir).resolve())
        restore_output_ownership_if_needed(Path(args.session_dir).resolve())
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
