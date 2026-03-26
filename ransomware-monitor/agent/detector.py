import math
import collections
import os
import time

class RansomwareDetector:
    def __init__(self, threshold_entropy=None, threshold_writes=None, time_window=None):
        # Tune defaults for 128-byte write samples from eBPF.
        self.threshold_entropy = float(
            os.getenv("THRESHOLD_ENTROPY", threshold_entropy if threshold_entropy is not None else 6.3)
        )
        self.threshold_writes = int(
            os.getenv("THRESHOLD_WRITES", threshold_writes if threshold_writes is not None else 10)
        )
        self.time_window = float(
            os.getenv("TIME_WINDOW_SEC", time_window if time_window is not None else 1.0)
        )
        # process_stats: { pid: [(timestamp, entropy, filename), ...] }
        self.process_stats = collections.defaultdict(list)
        self.suspicious_extensions = {'.locked', '.crypto', '.encrypted', '.onion', '.lck', '.temp'}

    def calculate_entropy(self, data):
        if not data:
            return 0
        counter = collections.Counter(data)
        probs = [count / len(data) for count in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        return entropy

    def analyze_event(self, event):
        pid = event.pid
        comm = event.comm.decode('utf-8', 'replace')
        filename = event.filename.decode('utf-8', 'replace')
        now = time.time()

        # event.type is an integer mapping to enum event_type
        # 0: OPEN, 1: WRITE, 2: RENAME, 3: UNLINK
        
        if event.type == 0: # OPEN
             _, ext = os.path.splitext(filename)
             if ext in self.suspicious_extensions:
                print(f"[!] ALERT: Suspicious file open '{ext}' detected from {comm} (PID {pid})")
                self.take_action(pid, comm, "Suspicious extension")

        if event.type == 2: # RENAME
             _, ext = os.path.splitext(filename)
             if ext in self.suspicious_extensions:
                print(f"[!] ALERT: Suspicious rename to '{ext}' detected from {comm} (PID {pid})")
                self.take_action(pid, comm, "Suspicious rename")

        if event.type == 1: # WRITE
            sample_len = min(int(event.size), len(event.buffer))
            entropy = self.calculate_entropy(bytes(event.buffer[:sample_len]))
            self.process_stats[pid].append((now, entropy, filename))

            # Clean up old events outside the time window
            self.process_stats[pid] = [
                e for e in self.process_stats[pid] if now - e[0] <= self.time_window
            ]
            
            # Debug: Print stats
            # print(f"DEBUG: PID {pid} Writes: {len(self.process_stats[pid])} Entropy: {entropy:.2f}")

            # Check frequency and entropy
            if len(self.process_stats[pid]) >= self.threshold_writes:
                avg_entropy = sum(e[1] for e in self.process_stats[pid]) / len(self.process_stats[pid])
                if avg_entropy >= self.threshold_entropy:
                    print(f"[!!!] ALERT: Potential ransomware behavior from {comm} (PID {pid})")
                    print(f"      High write frequency ({len(self.process_stats[pid])} in {self.time_window}s) and high entropy ({avg_entropy:.2f})")
                    self.take_action(pid, comm, "High entropy + Frequency")

    def take_action(self, pid, comm, reason):
        print(f"[X] ACTION: Terminating process {comm} (PID {pid}) due to {reason}...")
        try:
            # os.kill(pid, 9) # Commented out for safety during initial testing
            print(f"      (Simulation) Sent SIGKILL to PID {pid}")
        except ProcessLookupError as e:
            print(f"      ProcessLookupError: {e}")

        except Exception as e:
            print(f"      Error terminating process: {e}")
