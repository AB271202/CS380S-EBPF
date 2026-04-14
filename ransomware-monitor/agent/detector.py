import math
import collections
import os
import time
import json


# Well-known magic bytes for common file types.
# Each entry maps a human-readable label to the byte prefix that identifies
# the format.  When a WRITE event overwrites these leading bytes with
# high-entropy data it is a strong signal that the file is being encrypted
# in-place.
MAGIC_BYTES = {
    "PDF":  b"%PDF",
    "PNG":  b"\x89PNG",
    "JPEG": b"\xff\xd8\xff",
    "ZIP":  b"PK\x03\x04",
    "DOCX": b"PK\x03\x04",   # OOXML is ZIP-based
    "GIF":  b"GIF8",
    "ELF":  b"\x7fELF",
    "GZIP": b"\x1f\x8b",
    "BMP":  b"BM",
    "TIFF_LE": b"II\x2a\x00",
    "TIFF_BE": b"MM\x00\x2a",
}

# Default set of process names considered safe.  The whitelist is loaded
# from a JSON config file when one is provided; these are the built-in
# defaults that cover common developer and system tools.
DEFAULT_WHITELISTED_PROCESSES = {
    # Version control
    "git", "git-remote-htt", "git-remote-ssh",
    # Package managers
    "apt", "apt-get", "dpkg", "dnf", "yum", "pacman", "snap", "flatpak",
    "pip", "pip3", "npm", "yarn", "cargo",
    # Compilers / build tools
    "gcc", "g++", "cc1", "cc1plus", "as", "ld", "make", "cmake", "ninja",
    "rustc", "javac", "clang", "clang++",
    # Backup / sync
    "rsync", "rclone", "tar", "gzip", "bzip2", "xz", "zstd",
    # System services
    "systemd", "journald", "systemd-journa", "logrotate", "cron", "anacron",
    "sshd", "dbus-daemon",
    # Editors / IDEs (they do lots of temp-file writes)
    "vim", "nvim", "nano", "code", "codium", "emacs",
    # Databases
    "postgres", "mysqld", "mongod", "redis-server",
}


class RansomwareDetector:
    """Heuristic ransomware detector with false-positive reduction.

    False-positive reduction features
    ----------------------------------
    1. **Process whitelist** – trusted process names are skipped entirely,
       preventing alerts from compilers, package managers, editors, etc.
       The whitelist can be extended at runtime via a JSON config file.
    2. **Canary (honeypot) files** – hidden sentinel files placed in
       sensitive directories.  Any *non-whitelisted* process that touches
       a canary triggers an immediate high-priority alert.
    3. **Magic-byte analysis** – on WRITE events the first bytes of the
       buffer are compared against known file-type signatures.  If a
       recognised header is being overwritten with high-entropy data the
       alert confidence is elevated.
    """

    def __init__(
        self,
        threshold_entropy=None,
        threshold_writes=None,
        threshold_unlinks=None,
        time_window=None,
        whitelist_config=None,
        canary_dirs=None,
    ):
        # Tune defaults for 128-byte write samples from eBPF.
        self.threshold_entropy = float(
            os.getenv(
                "THRESHOLD_ENTROPY",
                threshold_entropy if threshold_entropy is not None else 6.3,
            )
        )
        self.threshold_writes = int(
            os.getenv(
                "THRESHOLD_WRITES",
                threshold_writes if threshold_writes is not None else 10,
            )
        )
        self.threshold_unlinks = int(
            os.getenv(
                "THRESHOLD_UNLINKS",
                threshold_unlinks if threshold_unlinks is not None else 5,
            )
        )
        self.time_window = float(
            os.getenv(
                "TIME_WINDOW_SEC",
                time_window if time_window is not None else 1.0,
            )
        )

        # process_stats: { pid: [(timestamp, entropy, filename), ...] }
        self.process_stats = collections.defaultdict(list)
        # unlink_stats: { pid: [timestamp, ...] }
        self.unlink_stats = collections.defaultdict(list)
        self.suspicious_extensions = {
            ".locked", ".crypto", ".encrypted", ".onion", ".lck", ".temp",
        }

        # --- False-positive reduction ---

        # 1. Process whitelist
        self.whitelisted_processes = set(DEFAULT_WHITELISTED_PROCESSES)
        if whitelist_config:
            self._load_whitelist(whitelist_config)

        # 2. Canary files
        self.canary_paths: set[str] = set()
        if canary_dirs:
            for d in canary_dirs:
                self.deploy_canaries(d)

        # Alerts list – useful for programmatic inspection in tests.
        self.alerts: list[dict] = []

    # ------------------------------------------------------------------
    # Whitelist helpers
    # ------------------------------------------------------------------

    def _load_whitelist(self, config_path):
        """Merge additional process names from a JSON config file.

        Expected format::

            {
                "whitelisted_processes": ["mybackup", "custom-tool"]
            }
        """
        try:
            with open(config_path, "r") as fh:
                cfg = json.load(fh)
            extra = cfg.get("whitelisted_processes", [])
            self.whitelisted_processes.update(extra)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load whitelist config {config_path}: {exc}")

    def is_whitelisted(self, comm):
        """Return True if *comm* is in the trusted process whitelist."""
        return comm in self.whitelisted_processes

    # ------------------------------------------------------------------
    # Canary (honeypot) files
    # ------------------------------------------------------------------

    def deploy_canaries(self, directory, filenames=None):
        """Create hidden canary files inside *directory*.

        Returns the list of created canary paths.
        """
        if filenames is None:
            filenames = [
                ".~canary_doc.docx",
                ".~canary_photo.jpg",
                ".~canary_data.xlsx",
            ]
        created = []
        os.makedirs(directory, exist_ok=True)
        for name in filenames:
            path = os.path.join(directory, name)
            try:
                with open(path, "w") as fh:
                    fh.write("CANARY")
                self.canary_paths.add(os.path.abspath(path))
                created.append(path)
            except OSError as exc:
                print(f"[WARN] Could not create canary {path}: {exc}")
        return created

    def is_canary(self, filename):
        """Check whether *filename* matches a deployed canary path."""
        try:
            return os.path.abspath(filename) in self.canary_paths
        except (ValueError, OSError):
            return False

    # ------------------------------------------------------------------
    # Magic-byte / file-header analysis
    # ------------------------------------------------------------------

    @staticmethod
    def check_magic_bytes(buffer_data):
        """Return the file-type label if *buffer_data* starts with a
        recognised magic-byte sequence, otherwise ``None``."""
        for label, magic in MAGIC_BYTES.items():
            if buffer_data[: len(magic)] == magic:
                return label
        return None

    @staticmethod
    def magic_bytes_destroyed(buffer_data, entropy, entropy_floor=6.0):
        """Return True when a buffer that *used to* contain a known header
        now appears to be high-entropy (encrypted) data.

        The heuristic: if the first 4 bytes do **not** match any known
        magic *and* the overall entropy exceeds *entropy_floor*, the
        header was likely overwritten by ciphertext.

        The default floor of 6.0 is tuned for the 128-byte samples that
        the eBPF probe captures — ``os.urandom(128)`` typically yields
        entropy in the 6.3-6.8 range.
        """
        has_known_header = RansomwareDetector.check_magic_bytes(buffer_data) is not None
        return (not has_known_header) and entropy > entropy_floor

    # ------------------------------------------------------------------
    # Entropy calculation
    # ------------------------------------------------------------------

    def calculate_entropy(self, data):
        if not data:
            return 0
        counter = collections.Counter(data)
        probs = [count / len(data) for count in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        return entropy

    # ------------------------------------------------------------------
    # Alert recording
    # ------------------------------------------------------------------

    def _record_alert(self, pid, comm, reason, severity="high", **extra):
        """Store an alert dict and print it."""
        alert = {
            "pid": pid,
            "comm": comm,
            "reason": reason,
            "severity": severity,
            "timestamp": time.time(),
            **extra,
        }
        self.alerts.append(alert)
        return alert

    # ------------------------------------------------------------------
    # Core event analysis
    # ------------------------------------------------------------------

    def analyze_event(self, event):
        pid = event.pid
        comm = event.comm.decode("utf-8", "replace")
        filename = event.filename.decode("utf-8", "replace")
        now = time.time()

        # --- Whitelist check (false-positive reduction) ---
        # Canary access from whitelisted processes is still flagged.
        is_canary_access = self.is_canary(filename)
        if self.is_whitelisted(comm) and not is_canary_access:
            return

        # --- Canary file access (high-priority) ---
        if is_canary_access:
            msg = (
                f"[!!!] CANARY ALERT: Process {comm} (PID {pid}) "
                f"accessed canary file '{filename}'"
            )
            print(msg)
            self._record_alert(pid, comm, "Canary file access", severity="critical")
            self.take_action(pid, comm, "Canary file access")
            return

        # event.type is an integer mapping to enum event_type
        # 0: OPEN, 1: WRITE, 2: RENAME, 3: UNLINK

        if event.type == 0:  # OPEN
            _, ext = os.path.splitext(filename)
            if ext in self.suspicious_extensions:
                print(
                    f"[!] ALERT: Suspicious file open '{ext}' "
                    f"detected from {comm} (PID {pid})"
                )
                self._record_alert(pid, comm, "Suspicious extension", severity="medium")
                self.take_action(pid, comm, "Suspicious extension")

        elif event.type == 2:  # RENAME
            _, ext = os.path.splitext(filename)
            if ext in self.suspicious_extensions:
                print(
                    f"[!] ALERT: Suspicious rename to '{ext}' "
                    f"detected from {comm} (PID {pid})"
                )
                self._record_alert(pid, comm, "Suspicious rename", severity="medium")
                self.take_action(pid, comm, "Suspicious rename")

        elif event.type == 1:  # WRITE
            sample_len = min(int(event.size), len(event.buffer))
            buffer_bytes = bytes(event.buffer[:sample_len])
            entropy = self.calculate_entropy(buffer_bytes)
            self.process_stats[pid].append((now, entropy, filename))

            # Clean up old events outside the time window
            self.process_stats[pid] = [
                e for e in self.process_stats[pid] if now - e[0] <= self.time_window
            ]

            # --- Magic-byte analysis (false-positive reduction) ---
            if self.magic_bytes_destroyed(buffer_bytes, entropy):
                print(
                    f"[!!!] ALERT: File header overwritten with encrypted data "
                    f"by {comm} (PID {pid}) on '{filename}' "
                    f"(entropy {entropy:.2f})"
                )
                self._record_alert(
                    pid, comm, "Magic bytes destroyed",
                    severity="critical", entropy=entropy, filename=filename,
                )
                self.take_action(pid, comm, "Magic bytes destroyed")
                return

            # Check frequency and entropy
            if len(self.process_stats[pid]) >= self.threshold_writes:
                avg_entropy = sum(e[1] for e in self.process_stats[pid]) / len(
                    self.process_stats[pid]
                )
                if avg_entropy >= self.threshold_entropy:
                    print(
                        f"[!!!] ALERT: Potential ransomware behavior "
                        f"from {comm} (PID {pid})"
                    )
                    print(
                        f"      High write frequency "
                        f"({len(self.process_stats[pid])} in "
                        f"{self.time_window}s) and high entropy "
                        f"({avg_entropy:.2f})"
                    )
                    self._record_alert(
                        pid, comm, "High entropy + Frequency",
                        severity="high", avg_entropy=avg_entropy,
                    )
                    self.take_action(pid, comm, "High entropy + Frequency")

        elif event.type == 3:  # UNLINK
            self.unlink_stats[pid].append(now)

            # Clean up old events
            self.unlink_stats[pid] = [
                t for t in self.unlink_stats[pid] if now - t <= self.time_window
            ]

            if len(self.unlink_stats[pid]) >= self.threshold_unlinks:
                print(
                    f"[!!!] ALERT: Potential ransomware behavior "
                    f"from {comm} (PID {pid})"
                )
                print(
                    f"      High unlink frequency "
                    f"({len(self.unlink_stats[pid])} in "
                    f"{self.time_window}s)"
                )
                self._record_alert(pid, comm, "High unlink frequency")
                self.take_action(pid, comm, "High unlink frequency")

    def take_action(self, pid, comm, reason):
        print(
            f"[X] ACTION: Terminating process {comm} (PID {pid}) "
            f"due to {reason}..."
        )
        try:
            # os.kill(pid, 9)  # Commented out for safety during testing
            print(f"      (Simulation) Sent SIGKILL to PID {pid}")
        except ProcessLookupError as exc:
            print(f"      ProcessLookupError: {exc}")
        except Exception as exc:
            print(f"      Error terminating process: {exc}")
