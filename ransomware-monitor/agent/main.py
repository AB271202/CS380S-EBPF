from bcc import BPF
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

def main():
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
        event_type_str = EVENT_TYPES.get(event.type, "UNKNOWN")
        # Debug: Print all events to see if they are coming through
        print(f"Event: {event_type_str} PID={event.pid} Comm={event.comm.decode('utf-8', 'replace')} File={event.filename.decode('utf-8', 'replace')} Size={event.size}")
        detector.analyze_event(event)

    # Increase page_cnt to 1024 or higher to avoid lost samples
    b["events"].open_perf_buffer(print_event, page_cnt=2048)
    
    print("Ransomware monitor started. Press Ctrl+C to stop.")

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
