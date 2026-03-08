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
    3: "UNLINK"
}

DEFAULT_PERF_PAGE_CNT = 4096

def main():
    parser = argparse.ArgumentParser(description="Ransomware monitor")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every traced filesystem event",
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

    detector = RansomwareDetector()

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        if args.verbose:
            event_type_str = EVENT_TYPES.get(event.type, "UNKNOWN")
            print(
                f"Event: {event_type_str} PID={event.pid} "
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
        f"Ransomware monitor started ({mode} mode, perf pages={page_cnt}). "
        "Press Ctrl+C to stop."
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
