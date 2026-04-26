from bcc import BPF
import argparse
import os
import signal
import sys
from detector import RansomwareDetector

# Use the correct relative path for the BPF source
BPF_SOURCE_FILE = os.path.join(os.path.dirname(__file__), "..", "bpf", "monitor.bpf.c")

EVENT_TYPES = {
    0: "OPEN",
    1: "WRITE",
    2: "RENAME",
    3: "UNLINK",
    4: "GETDENTS",
    5: "URANDOM_READ",
    6: "KILL",
}

DEFAULT_PERF_PAGE_CNT = 4096


def _env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_path_list(raw):
    if not raw:
        return []
    normalized = raw.replace(";", ",").replace(":", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]

def main():
    parser = argparse.ArgumentParser(description="Ransomware monitor")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every traced filesystem event",
    )
    parser.add_argument(
        "--action-mode",
        choices=["simulate", "suspend", "kill"],
        default="simulate",
        help="Response mode: simulate (log only), suspend (SIGSTOP), kill (full EDR chain)",
    )
    parser.add_argument(
        "--snapshot-cmd",
        type=str,
        default=None,
        help="Shell command for filesystem snapshot on critical alert",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=str,
        default=None,
        help="Directory to quarantine malicious binaries (default: /var/lib/ransomware-monitor/quarantine)",
    )
    parser.add_argument(
        "--enable-network-isolation",
        action="store_true",
        help="Block network access for flagged processes via iptables",
    )
    parser.add_argument(
        "--whitelist-config",
        type=str,
        default=os.getenv("WHITELIST_CONFIG"),
        help=(
            "JSON config file for whitelisted processes, trusted hashes, "
            "and trusted parents (default: $WHITELIST_CONFIG)"
        ),
    )
    parser.add_argument(
        "--canary-dir",
        action="append",
        default=None,
        help=(
            "Directory where canary files should be deployed. "
            "Repeat the flag to add multiple directories."
        ),
    )
    parser.add_argument(
        "--disable-binary-hash-verification",
        action="store_true",
        default=_env_flag("DISABLE_BINARY_HASH_VERIFICATION", False),
        help=(
            "Skip whitelist binary-hash verification "
            "(default can also be set via $DISABLE_BINARY_HASH_VERIFICATION)"
        ),
    )
    parser.add_argument(
        "--disable-lineage-verification",
        action="store_true",
        default=_env_flag("DISABLE_LINEAGE_VERIFICATION", False),
        help=(
            "Skip whitelist lineage verification "
            "(default can also be set via $DISABLE_LINEAGE_VERIFICATION)"
        ),
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This program must be run as root.")
        sys.exit(1)

    if not os.path.exists(BPF_SOURCE_FILE):
        print(f"Error: {BPF_SOURCE_FILE} not found.")
        sys.exit(1)

    print(f"Loading BPF program from {BPF_SOURCE_FILE}...")
    
    try:
        b = BPF(src_file=BPF_SOURCE_FILE)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)

    canary_dirs = list(args.canary_dir or [])
    canary_dirs.extend(_split_path_list(os.getenv("CANARY_DIRS", "")))
    if canary_dirs:
        canary_dirs = list(dict.fromkeys(canary_dirs))

    detector = RansomwareDetector(
        action_mode=args.action_mode,
        snapshot_cmd=args.snapshot_cmd,
        quarantine_dir=args.quarantine_dir,
        enable_network_isolation=args.enable_network_isolation,
        whitelist_config=args.whitelist_config,
        canary_dirs=canary_dirs or None,
        verify_binary_hash=not args.disable_binary_hash_verification,
        verify_lineage=not args.disable_lineage_verification,
    )

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        if args.verbose:
            event_type_str = EVENT_TYPES.get(event.type, "UNKNOWN")
            print(
                f"Event: {event_type_str} PID={event.pid} PPID={event.ppid} "
                f"Comm={event.comm.decode('utf-8', 'replace')} "
                f"File={event.filename.decode('utf-8', 'replace')} "
                f"Size={event.size}"
            )
        detector.analyze_event(event)

    lost_totals = {"count": 0}

    def on_lost_event(cpu, count):
        lost_totals["count"] += count
        print(
            f"[WARN] Lost {count} events on CPU {cpu} "
            f"(total lost: {lost_totals['count']})."
        )

    page_cnt = int(os.getenv("PERF_PAGE_CNT", str(DEFAULT_PERF_PAGE_CNT)))
    b["events"].open_perf_buffer(print_event, page_cnt=page_cnt, lost_cb=on_lost_event)
    
    mode = "verbose" if args.verbose else "alert-only"
    print(
        f"Ransomware monitor started ({mode} mode, action={args.action_mode}, "
        f"perf pages={page_cnt}). Press Ctrl+C to stop."
    )

    def signal_handler(sig, frame):
        print("\nStopping monitor...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
