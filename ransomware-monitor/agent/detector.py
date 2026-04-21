import math
import collections
import hashlib
import logging
import os
import shutil
import signal as signal_mod
import stat
import subprocess
import time
import json
from typing import Dict, List, Optional, Set, Tuple


# Well-known magic bytes for common file types.
# When a WRITE event overwrites these leading bytes with high-entropy
#  data it is a strong signal that the file is being encrypted in-place.
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
    "rsync", "rclone", "tar", "gzip", "bzip2", "xz", "zstd", "ccencrypt",
    # System services
    "systemd", "journald", "systemd-journa", "logrotate", "cron", "anacron",
    "sshd", "dbus-daemon",
    # Editors / IDEs (they do lots of temp-file writes)
    "vim", "nvim", "nano", "code", "codium", "emacs",
    # Databases
    "postgres", "mysqld", "mongod", "redis-server",
    # Core utilities that are never ransomware attack vectors
    "dd", "head", "cat", "cp", "sort", "shuf",
    # Media processing (high-entropy output but not attack tools)
    "ffmpeg", "ffprobe", "avconv",
    "convert", "mogrify",  # ImageMagick
    "sox",                  # Audio processing
    "x264", "x265", "vpxenc",
    "handbrake", "HandBrakeCLI",
    # Parallel compression variants (never used as attack tools)
    "pigz", "pbzip2", "pixz", "lz4", "lzop",
}

# Prefixes that identify non-user-file write targets.  Writes to these
# paths are typical of defragmenters, databases, and system services and
# should NOT contribute to the ransomware entropy/frequency heuristic.
SYSTEM_PATH_PREFIXES = (
    "/dev/",        # Block / character devices
    "/proc/",       # Procfs
    "/sys/",        # Sysfs
    "/run/",        # Runtime state
    "/tmp/.",       # Hidden temp files (e.g. .nfs locks)
    "/var/log/",    # Log files
    "/var/lib/",    # Package / database state
    "/var/cache/",  # Caches
)

# Common user-file extensions that ransomware targets.  Used by the file
# diversity scorer to weight alerts — a process touching many *different*
# user-document types across directories is far more suspicious than one
# writing to a single extension in /tmp.
USER_FILE_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".rtf", ".odt", ".ods",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".rs", ".go",
    ".html", ".css", ".json", ".xml", ".yaml", ".yml",
    ".sql", ".db", ".sqlite",
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
    4. **Binary hash verification** – for whitelisted process names the
       SHA-256 of the on-disk executable is compared against a set of
       known-good digests.  A mismatch means the binary was replaced or
       tampered with and the process is treated as untrusted.
    5. **Process lineage validation** – the parent-process chain is walked
       via ``/proc/<pid>/status``.  If none of the ancestors are in the
       set of trusted parent names the process is treated as untrusted,
       catching scenarios where a dropper spawns a process that happens
       to share a whitelisted name.
    6. **File diversity scoring** – tracks how many unique file paths and
       unique parent directories a PID writes to within the time window.
       A high count across many directories is a strong ransomware signal
       that separates it from defragmenters or databases.
    7. **Directory traversal detection** – monitors ``getdents64`` calls.
       Rapid directory listing combined with subsequent writes is a
       signature of ransomware scanning for targets.
    8. **Write target classification** – writes to block devices, procfs,
       sysfs, and other system paths are excluded from the entropy and
       frequency heuristics, preventing false positives from
       defragmenters and system services.
    """

    def __init__(
        self,
        threshold_entropy=None,
        threshold_writes=None,
        threshold_unlinks=None,
        time_window=None,
        whitelist_config=None,
        canary_dirs=None,
        trusted_hashes=None,
        trusted_parents=None,
        verify_binary_hash=True,
        verify_lineage=True,
        threshold_unique_files=None,
        threshold_unique_dirs=None,
        threshold_dir_scans=None,
        action_mode="simulate",
        snapshot_cmd=None,
        quarantine_dir=None,
        enable_network_isolation=False,
        cumulative_score_threshold=None,
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
        self.attribution_window = float(
            os.getenv(
                "ATTRIBUTION_WINDOW_SEC",
                max(self.time_window, 10.0),
            )
        )
        self.alert_json = os.getenv("ALERT_JSON", "0") == "1"
        self.alert_json_prefix = os.getenv("ALERT_JSON_PREFIX", "ALERT_JSON")
        self.run_id = os.getenv("RUN_ID", "")

        # --- Behavioral analysis thresholds ---
        self.threshold_unique_files = int(
            os.getenv(
                "THRESHOLD_UNIQUE_FILES",
                threshold_unique_files if threshold_unique_files is not None else 8,
            )
        )
        self.threshold_unique_dirs = int(
            os.getenv(
                "THRESHOLD_UNIQUE_DIRS",
                threshold_unique_dirs if threshold_unique_dirs is not None else 3,
            )
        )
        self.threshold_dir_scans = int(
            os.getenv(
                "THRESHOLD_DIR_SCANS",
                threshold_dir_scans if threshold_dir_scans is not None else 5,
            )
        )

        # process_stats: { pid: [(timestamp, entropy, filename), ...] }
        self.process_stats = collections.defaultdict(list)
        # unlink_stats: { pid: [timestamp, ...] }
        self.unlink_stats = collections.defaultdict(list)
        # dir_scan_stats: { pid: [(timestamp, directory), ...] }
        self.dir_scan_stats = collections.defaultdict(list)
        # open_tracker: { pid: {filename: timestamp, ...} }
        # Tracks files opened (not created) for in-place overwrite detection.
        self.open_tracker: Dict[int, Dict[str, float]] = collections.defaultdict(dict)
        # write_targets: { pid: [(timestamp, source_file, dest_file), ...] }
        # Tracks recent high-entropy write targets for unlink correlation.
        self.write_targets: Dict[int, List[Tuple[float, str]]] = collections.defaultdict(list)
        self.suspicious_extensions = {
            ".locked", ".crypto", ".encrypted", ".onion", ".lck", ".temp", ".cl0p",
        }

        # --- Cumulative per-process profile (slow-burn detection) ---
        # Unlike the sliding-window trackers above, these are never pruned.
        # They accumulate lifetime behavior so that a process encrypting
        # one file per minute still triggers after enough files.
        self.cumulative_score_threshold = int(
            os.getenv(
                "CUMULATIVE_SCORE_THRESHOLD",
                cumulative_score_threshold if cumulative_score_threshold is not None else 15,
            )
        )
        self._process_profiles: dict[int, dict] = {}
        self._cumulative_alerted: set[int] = set()  # PIDs already alerted

        # --- False-positive reduction ---

        # 1. Process whitelist
        self.whitelisted_processes = set(DEFAULT_WHITELISTED_PROCESSES)

        # 2. Canary files
        self.canary_paths: Set[str] = set()
        if canary_dirs:
            for d in canary_dirs:
                self.deploy_canaries(d)

        # 3. Binary hash verification
        self.verify_binary_hash = verify_binary_hash
        self.trusted_hashes: Dict[str, Set[str]] = {}
        if trusted_hashes:
            for path, hashes in trusted_hashes.items():
                if isinstance(hashes, str):
                    hashes = [hashes]
                self.trusted_hashes[path] = set(hashes)
        self._hash_cache: Dict[Tuple[int, str], str] = {}
        self._parent_pid_cache: Dict[int, Optional[int]] = {}
        self._comm_cache: Dict[int, str] = {}
        self._pid_identity_cache: Dict[int, Tuple[float, str]] = {}

        # 4. Process lineage validation
        self.verify_lineage = verify_lineage
        self.trusted_parents: Set[str] = trusted_parents if trusted_parents is not None else {
            "bash", "sh", "zsh", "fish", "dash",
            "python", "python3",
            "sshd", "login", "su", "sudo",
            "systemd", "init",
            "make", "cmake", "ninja",
            "cron", "anacron", "atd",
            "screen", "tmux",
            "docker", "containerd", "containerd-shim",
        }
        self._lineage_cache: Dict[int, bool] = {}

        # Load all config from a single file (whitelist, hashes, parents)
        if whitelist_config:
            self._load_config(whitelist_config)

        # Alerts list – useful for programmatic inspection in tests.
        self.alerts: List[dict] = []

        # --- Response configuration ---
        # "simulate" = log only, "suspend" = SIGSTOP, "kill" = full EDR chain
        self.action_mode = action_mode
        self.snapshot_cmd = snapshot_cmd
        self._snapshot_triggered = False
        self.quarantine_dir = quarantine_dir or "/var/lib/ransomware-monitor/quarantine"
        self.enable_network_isolation = enable_network_isolation
        # Track quarantined binaries for the blocklist
        self.blocklist: Set[str] = set()
        # Track files modified by flagged PIDs for remediation
        self._pid_modified_files: Dict[int, List[str]] = collections.defaultdict(list)

    # ------------------------------------------------------------------
    # Whitelist helpers
    # ------------------------------------------------------------------

    def _load_config(self, config_path):
        """Load all configuration from a single JSON file.

        Expected format::

            {
                "whitelisted_processes": ["mybackup", "custom-tool"],
                "trusted_hashes": {"/usr/bin/mybackup": ["sha256_digest"]},
                "trusted_parents": ["orchestrator"]
            }
        """
        try:
            with open(config_path, "r") as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load config {config_path}: {exc}")
            return

        self.whitelisted_processes.update(cfg.get("whitelisted_processes", []))
        self.trusted_parents.update(cfg.get("trusted_parents", []))

        for exe_path, hashes in cfg.get("trusted_hashes", {}).items():
            if isinstance(hashes, str):
                hashes = [hashes]
            self.trusted_hashes.setdefault(exe_path, set()).update(hashes)

    def is_whitelisted(self, comm, pid=None):
        """Return True if *comm* is in the trusted process whitelist.

        When *pid* is provided **and** binary-hash or lineage verification
        is enabled, the name-based match is hardened:

        * **Binary hash** – the SHA-256 of ``/proc/<pid>/exe`` must appear
          in ``self.trusted_hashes`` for that executable path.  If no
          hashes are registered for the path the check is skipped (open
          trust).  A mismatch revokes the whitelist.
        * **Lineage** – at least one ancestor in the process tree must
          have a comm name in ``self.trusted_parents``.  If none do, the
          whitelist is revoked.

        Either check failing causes the method to return ``False`` and
        record a warning alert so the operator knows the whitelist was
        bypassed.
        """
        if comm not in self.whitelisted_processes:
            return False

        # Name matched — apply hardening when a PID is available.
        if pid is None:
            return True

        # --- Binary hash verification ---
        if self.verify_binary_hash:
            if not self._verify_hash(pid, comm):
                return False

        # --- Process lineage validation ---
        if self.verify_lineage:
            if not self._verify_lineage(pid, comm):
                return False

        return True

    # ------------------------------------------------------------------
    # Binary hash verification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_cstring(value):
        """Decode a NUL-padded C string from BPF/perf event fields."""
        if isinstance(value, bytes):
            value = value.split(b"\x00", 1)[0]
            return value.decode("utf-8", "replace")
        return str(value)

    @staticmethod
    def _resolve_exe(pid):
        """Return the real path of the executable for *pid*, or None."""
        link = f"/proc/{pid}/exe"
        try:
            return os.path.realpath(link)
        except OSError:
            return None

    @staticmethod
    def hash_binary(path):
        """Return the SHA-256 hex digest of the file at *path*."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def _verify_hash(self, pid, comm):
        """Check the on-disk binary hash for *pid*.

        Returns True (trusted) when:
        * ``/proc/<pid>/exe`` cannot be read (container / short-lived proc)
        * No hashes are registered for the resolved path (open trust)
        * The computed hash matches one of the registered digests

        Returns False (untrusted) when a hash **is** registered but does
        not match — indicating the binary was tampered with.
        """
        exe_path = self._resolve_exe(pid)
        if exe_path is None:
            return True  # Cannot verify — give benefit of the doubt

        cache_key = (pid, exe_path)
        if cache_key not in self._hash_cache:
            digest = self.hash_binary(exe_path)
            if digest is not None:
                self._hash_cache[cache_key] = digest
            else:
                return True  # Unreadable binary — skip check

        digest = self._hash_cache[cache_key]

        # If no hashes are registered for this path, open-trust applies.
        allowed = self.trusted_hashes.get(exe_path)
        if allowed is None:
            return True

        if digest not in allowed:
            print(
                f"[!!] WHITELIST REVOKED: {comm} (PID {pid}) binary hash "
                f"mismatch for {exe_path} (got {digest[:16]}…)"
            )
            self._record_alert(
                pid, comm, "Binary hash mismatch",
                severity="high", exe_path=exe_path, digest=digest,
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Process lineage validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ppid(pid):
        """Read the parent PID from ``/proc/<pid>/status``."""
        try:
            with open(f"/proc/{pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        return int(line.split(":")[1].strip())
        except (OSError, ValueError):
            pass
        return None

    @staticmethod
    def _get_comm(pid):
        """Read the comm (process name) from ``/proc/<pid>/comm``."""
        try:
            with open(f"/proc/{pid}/comm", "r") as fh:
                return fh.read().strip()
        except OSError:
            return None

    def get_parent_pid(self, pid):
        """Read and cache the parent PID for *pid*."""
        if pid in self._parent_pid_cache:
            return self._parent_pid_cache[pid]
        parent = self._get_ppid(pid)
        self._parent_pid_cache[pid] = parent
        return parent

    def _read_proc_comm(self, pid):
        """Read and cache the comm for *pid*."""
        if pid in self._comm_cache:
            return self._comm_cache[pid]
        comm = self._get_comm(pid)
        if comm is not None:
            self._comm_cache[pid] = comm
        return comm

    def get_process_lineage(self, pid, max_depth=10):
        """Walk the parent chain and return a list of ``(pid, comm)`` tuples.

        Stops at PID 0/1 or after *max_depth* hops to avoid infinite loops.
        """
        lineage = []
        current = pid
        for _ in range(max_depth):
            ppid = self.get_parent_pid(current)
            if ppid is None or ppid == 0:
                break
            parent_comm = self._read_proc_comm(ppid)
            lineage.append((ppid, parent_comm))
            if ppid == 1:
                break
            current = ppid
        return lineage

    def _has_active_behavioral_profile(self, pid, now):
        """Return True if *pid* has recent behavioral state.

        We treat recent write, scan, unlink, or open-tracker state as an
        "active profile" so delegated child writes can be attributed to an
        orchestrator that is already interacting with the filesystem.
        """
        process_entries = [
            e for e in self.process_stats.get(pid, [])
            if now - e[0] <= self.attribution_window
        ]
        if process_entries:
            self.process_stats[pid] = process_entries
            return True
        if pid in self.process_stats:
            self.process_stats[pid] = process_entries

        scan_entries = [
            e for e in self.dir_scan_stats.get(pid, [])
            if now - e[0] <= self.attribution_window
        ]
        if scan_entries:
            self.dir_scan_stats[pid] = scan_entries
            return True
        if pid in self.dir_scan_stats:
            self.dir_scan_stats[pid] = scan_entries

        unlink_entries = [
            t for t in self.unlink_stats.get(pid, [])
            if now - t <= self.attribution_window
        ]
        if unlink_entries:
            self.unlink_stats[pid] = unlink_entries
            return True
        if pid in self.unlink_stats:
            self.unlink_stats[pid] = unlink_entries

        opened = {
            path: ts for path, ts in self.open_tracker.get(pid, {}).items()
            if now - ts <= self.attribution_window
        }
        if opened:
            self.open_tracker[pid] = opened
            return True
        if pid in self.open_tracker:
            self.open_tracker[pid] = opened

        return False

    def _remember_behavioral_identity(self, pid, comm, now):
        """Remember the last recent non-whitelisted identity for *pid*."""
        if comm in self.whitelisted_processes:
            return
        self._pid_identity_cache[pid] = (now, comm)

    def _get_recent_behavioral_identity(self, pid, now):
        """Return the recent non-whitelisted identity for *pid*, if any."""
        entry = self._pid_identity_cache.get(pid)
        if not entry:
            return None
        timestamp, comm = entry
        if now - timestamp > self.attribution_window:
            self._pid_identity_cache.pop(pid, None)
            return None
        return comm

    def _find_attributable_ancestor(self, pid, now=None, direct_parent_pid=None):
        """Find the nearest non-whitelisted ancestor with live behavioral state."""
        if now is None:
            now = time.time()

        current = pid
        next_parent = direct_parent_pid
        for _ in range(5):
            parent = next_parent if next_parent is not None else self.get_parent_pid(current)
            next_parent = None
            if parent is None or parent <= 1:
                return None
            parent_comm = self._read_proc_comm(parent)
            if not parent_comm:
                return None
            if (
                not self.is_whitelisted(parent_comm, pid=parent)
                and self._has_active_behavioral_profile(parent, now)
            ):
                return parent
            current = parent
        return None

    def _find_attributable_subject(self, pid, now=None, direct_parent_pid=None):
        """Find the best process identity to receive a trusted child's write.

        Preference order:
        1. Parent orchestrator, when a freshly-forked helper PID recently
           carried the same non-whitelisted identity before exec.
        2. Nearest non-whitelisted ancestor with recent behavioral state.
        """
        if now is None:
            now = time.time()

        current_identity = self._get_recent_behavioral_identity(pid, now)
        if current_identity:
            parent_pid = (
                direct_parent_pid
                if direct_parent_pid is not None
                else self.get_parent_pid(pid)
            )
            if parent_pid is not None and parent_pid > 1:
                parent_identity = (
                    self._get_recent_behavioral_identity(parent_pid, now)
                    or self._read_proc_comm(parent_pid)
                )
                if (
                    parent_identity == current_identity
                    and parent_identity not in self.whitelisted_processes
                ):
                    return parent_pid, current_identity, "process_tree"

        ancestor_pid = self._find_attributable_ancestor(
            pid,
            now=now,
            direct_parent_pid=direct_parent_pid,
        )
        if ancestor_pid is None:
            return None

        ancestor_comm = (
            self._get_recent_behavioral_identity(ancestor_pid, now)
            or self._read_proc_comm(ancestor_pid)
            or f"pid_{ancestor_pid}"
        )
        return ancestor_pid, ancestor_comm, "process_tree"

    def _verify_lineage(self, pid, comm):
        """Check that at least one ancestor of *pid* is a trusted parent.

        Returns True (trusted) when:
        * The lineage cache already approved this PID
        * At least one ancestor comm is in ``self.trusted_parents``
        * The lineage cannot be read (short-lived process, container)

        Returns False (untrusted) when the full ancestor chain contains
        no trusted parent — suggesting the process was spawned by an
        unknown or malicious launcher.
        """
        if pid in self._lineage_cache:
            return self._lineage_cache[pid]

        lineage = self.get_process_lineage(pid)

        # If we cannot read lineage at all, give benefit of the doubt.
        if not lineage:
            self._lineage_cache[pid] = True
            return True

        parent_comms = {c for _, c in lineage if c is not None}
        if not parent_comms:
            self._lineage_cache[pid] = True
            return True
        if parent_comms & self.trusted_parents:
            self._lineage_cache[pid] = True
            return True

        # No trusted ancestor found.
        parent_desc = " → ".join(
            f"{c}({p})" for p, c in lineage if c is not None
        )
        print(
            f"[!!] WHITELIST REVOKED: {comm} (PID {pid}) has no trusted "
            f"ancestor. Lineage: {parent_desc}"
        )
        self._record_alert(
            pid, comm, "Untrusted process lineage",
            severity="high", lineage=parent_desc,
        )
        self._lineage_cache[pid] = False
        return False

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
    # Write target classification
    # ------------------------------------------------------------------

    @staticmethod
    def is_user_file(filepath):
        """Return True if *filepath* looks like a regular user file rather
        than a block device, procfs entry, or other system path.

        Writes to system paths are excluded from the entropy/frequency
        heuristic so that defragmenters, databases, and system services
        do not trigger false positives.
        """
        for prefix in SYSTEM_PATH_PREFIXES:
            if filepath.startswith(prefix):
                return False
        return True

    @staticmethod
    def is_user_document(filepath):
        """Return True if *filepath* has a common user-document extension."""
        _, ext = os.path.splitext(filepath)
        return ext.lower() in USER_FILE_EXTENSIONS

    # ------------------------------------------------------------------
    # File diversity scoring
    # ------------------------------------------------------------------

    def get_file_diversity(self, pid):
        """Return ``(unique_files, unique_dirs)`` for recent writes by *pid*.

        Computed from the current ``process_stats[pid]`` window (already
        pruned to the time window by ``analyze_event``).
        """
        entries = self.process_stats.get(pid, [])
        files = {e[2] for e in entries}
        dirs = {os.path.dirname(e[2]) for e in entries}
        return len(files), len(dirs)

    # ------------------------------------------------------------------
    # Cumulative per-process profile (slow-burn detection)
    # ------------------------------------------------------------------

    def _get_profile(self, pid):
        """Return the cumulative profile dict for *pid*, creating it if needed."""
        if pid not in self._process_profiles:
            self._process_profiles[pid] = {
                "high_entropy_files": set(),
                "high_entropy_dirs": set(),
                "unlinked_sources": 0,   # Unlinks of files NOT written by this PID
                "in_place_overwrites": set(),
                "score": 0.0,
            }
        return self._process_profiles[pid]

    def _update_profile_write(self, pid, filename, entropy, is_overwrite):
        """Update the cumulative profile after a high-entropy write."""
        if entropy <= self.threshold_entropy:
            return
        if not self.is_user_file(filename):
            return

        profile = self._get_profile(pid)
        directory = os.path.dirname(filename)

        if filename not in profile["high_entropy_files"]:
            profile["high_entropy_files"].add(filename)
            profile["score"] += 1.0  # New unique file

        if directory not in profile["high_entropy_dirs"]:
            profile["high_entropy_dirs"].add(directory)
            profile["score"] += 2.0  # New unique directory

        if is_overwrite and filename not in profile["in_place_overwrites"]:
            profile["in_place_overwrites"].add(filename)
            profile["score"] += 5.0  # In-place overwrite is very suspicious

    def _update_profile_unlink(self, pid, filename):
        """Update the cumulative profile after an unlink.

        Only scores unlinks of files the PID did NOT recently write to
        (i.e., deleting originals after encrypting copies).
        """
        profile = self._get_profile(pid)
        recent_writes = profile["high_entropy_files"]
        if filename not in recent_writes:
            profile["unlinked_sources"] += 1
            profile["score"] += 3.0  # Deleting a file you didn't write = suspicious

    def _check_cumulative_alert(self, pid, comm):
        """Fire an alert if the cumulative score exceeds the threshold."""
        if pid in self._cumulative_alerted:
            return  # Already alerted for this PID
        profile = self._get_profile(pid)
        if profile["score"] >= self.cumulative_score_threshold:
            self._cumulative_alerted.add(pid)
            n_files = len(profile["high_entropy_files"])
            n_dirs = len(profile["high_entropy_dirs"])
            n_overwrites = len(profile["in_place_overwrites"])
            n_unlinks = profile["unlinked_sources"]
            print(
                f"[!!!] ALERT: Slow-burn ransomware behavior from "
                f"{comm} (PID {pid})"
            )
            print(
                f"      Cumulative score {profile['score']:.0f} "
                f"(threshold {self.cumulative_score_threshold}): "
                f"{n_files} encrypted files across {n_dirs} dirs, "
                f"{n_overwrites} in-place overwrites, "
                f"{n_unlinks} source deletions"
            )
            self._record_alert(
                pid, comm, "Slow-burn ransomware",
                severity="critical",
                cumulative_score=profile["score"],
                encrypted_files=n_files,
                encrypted_dirs=n_dirs,
                in_place_overwrites=n_overwrites,
                source_deletions=n_unlinks,
            )
            self.take_action(pid, comm, "Slow-burn ransomware")

    # ------------------------------------------------------------------
    # In-place overwrite detection
    # ------------------------------------------------------------------

    def is_in_place_overwrite(self, pid, filename):
        """Return True if *pid* previously opened *filename* (not created)
        and is now writing high-entropy data back to it.

        Legitimate tools create *new* output files.  Ransomware overwrites
        the original in-place.
        """
        opened = self.open_tracker.get(pid, {})
        return filename in opened

    # ------------------------------------------------------------------
    # Output-to-input path correlation
    # ------------------------------------------------------------------

    # Extensions that legitimate compression / encryption tools append.
    LEGIT_OUTPUT_SUFFIXES = (
        ".gz", ".bz2", ".xz", ".zst", ".lz4", ".lzo", ".lz",
        ".zip", ".tar", ".tgz", ".tbz2", ".txz",
        ".gpg", ".pgp", ".asc", ".enc", ".age",
        ".7z", ".rar",
    )

    @staticmethod
    def is_legitimate_output_name(write_path, opened_paths):
        """Return True if *write_path* looks like a legitimate compressed
        or encrypted derivative of one of the *opened_paths*.

        Legitimate pattern: ``report.docx`` → ``report.docx.gz``
        Ransomware pattern: ``report.docx`` → ``report.docx.locked``
        """
        for src in opened_paths:
            # Check if write_path == src + known_suffix
            for suffix in RansomwareDetector.LEGIT_OUTPUT_SUFFIXES:
                if write_path == src + suffix:
                    return True
            # Also allow base-name match: report.docx → report.zip
            src_base = os.path.splitext(src)[0]
            write_base, write_ext = os.path.splitext(write_path)
            if src_base == write_base and write_ext in (".gz", ".zip", ".7z",
                                                         ".gpg", ".enc", ".xz",
                                                         ".bz2", ".zst", ".rar"):
                return True
        return False

    # ------------------------------------------------------------------
    # Write-then-unlink correlation
    # ------------------------------------------------------------------

    def check_write_then_unlink(self, pid, unlinked_file, now):
        """Return True if *pid* recently wrote high-entropy data to other
        files and is now deleting *unlinked_file* — the "encrypt copy then
        delete original" pattern.

        Legitimate tools (``gzip``) also delete the source after
        compression, but they do so for *one* file at a time.  Ransomware
        does it in bulk.  This method only flags when the PID has written
        to **multiple distinct** files recently.
        """
        # Prune old entries
        self.write_targets[pid] = [
            (ts, f) for ts, f in self.write_targets[pid]
            if now - ts <= self.time_window
        ]
        recent_write_files = {f for _, f in self.write_targets[pid]}

        # The unlinked file should NOT be one of the write targets
        # (ransomware deletes the *original*, not the encrypted copy).
        if unlinked_file in recent_write_files:
            return False

        # Need multiple distinct write targets to distinguish from gzip.
        return len(recent_write_files) >= 3

    # ------------------------------------------------------------------
    # Entropy calculation
    # ------------------------------------------------------------------

    def emit_alert(self, pid, comm, reason, severity="high", **extra):
        if not self.alert_json:
            return
        payload = {
            "ts": time.time(),
            "run_id": self.run_id,
            "pid": int(pid),
            "comm": comm,
            "reason": reason,
            "severity": severity,
            "alert_type": extra.pop(
                "alert_type",
                reason.lower().replace(" ", "_").replace("-", "_"),
            ),
            **extra,
        }
        print(f"{self.alert_json_prefix}:{json.dumps(payload, sort_keys=True)}", flush=True)

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
        self.emit_alert(pid, comm, reason, severity=severity, **extra)
        return alert

    def _record_write_signal(self, pid, filename, entropy, now):
        """Record a write sample so accumulated heuristics can inspect it."""
        self.process_stats[pid].append((now, entropy, filename))
        self.process_stats[pid] = [
            e for e in self.process_stats[pid]
            if now - e[0] <= self.time_window
        ]
        self._pid_modified_files[pid].append(filename)

        if entropy > self.threshold_entropy:
            self.write_targets[pid].append((now, filename))
        self.write_targets[pid] = [
            entry for entry in self.write_targets[pid]
            if now - entry[0] <= self.time_window
        ]

    def _check_behavioral_heuristics(
        self,
        pid,
        comm=None,
        now=None,
        attributed_from=None,
        attribution_mode=None,
    ):
        """Run write-accumulation heuristics for *pid*.

        When *attributed_from* is provided, the resulting alerts are tagged
        so the operator can distinguish inherited child-write evidence from
        direct writes by the alerted PID.
        """
        if now is None:
            now = time.time()
        if comm is None:
            comm = self._read_proc_comm(pid) or f"pid_{pid}"

        self.process_stats[pid] = [
            e for e in self.process_stats.get(pid, [])
            if now - e[0] <= self.time_window
        ]
        if not self.process_stats[pid]:
            return None

        extra = {}
        suffix = ""
        if attributed_from is not None:
            child_pid, child_comm = attributed_from
            extra.update(
                {
                    "attributed": True,
                    "attributed_from_pid": child_pid,
                    "attributed_from_comm": child_comm,
                }
            )
            if attribution_mode is not None:
                extra["attribution_mode"] = attribution_mode
            suffix = f" (attributed from child {child_comm} PID {child_pid})"

        unique_files, unique_dirs = self.get_file_diversity(pid)
        if (
            unique_files >= self.threshold_unique_files
            and unique_dirs >= self.threshold_unique_dirs
        ):
            avg_entropy = sum(e[1] for e in self.process_stats[pid]) / len(
                self.process_stats[pid]
            )
            if avg_entropy >= self.threshold_entropy:
                print(
                    f"[!!!] ALERT: Ransomware-like file diversity from "
                    f"{comm} (PID {pid}){suffix}"
                )
                print(
                    f"      {unique_files} unique files across "
                    f"{unique_dirs} directories in {self.time_window}s "
                    f"(avg entropy {avg_entropy:.2f})"
                )
                self._record_alert(
                    pid, comm, "High file diversity + Entropy",
                    severity="critical",
                    unique_files=unique_files,
                    unique_dirs=unique_dirs,
                    avg_entropy=avg_entropy,
                    **extra,
                )
                self.take_action(pid, comm, "High file diversity + Entropy")
                return "diversity"

        if len(self.process_stats[pid]) >= self.threshold_writes:
            recent_files = {e[2] for e in self.process_stats[pid]}
            if len(recent_files) < 2:
                return None
            avg_entropy = sum(e[1] for e in self.process_stats[pid]) / len(
                self.process_stats[pid]
            )
            if avg_entropy >= self.threshold_entropy:
                print(
                    f"[!!!] ALERT: Potential ransomware behavior "
                    f"from {comm} (PID {pid}){suffix}"
                )
                print(
                    f"      High write frequency "
                    f"({len(self.process_stats[pid])} in "
                    f"{self.time_window}s) and high entropy "
                    f"({avg_entropy:.2f})"
                )
                self._record_alert(
                    pid, comm, "High entropy + Frequency",
                    severity="high", avg_entropy=avg_entropy, **extra,
                )
                self.take_action(pid, comm, "High entropy + Frequency")
                return "frequency"

        return None

    def _attribute_child_write(self, event, pid, comm, filename, now):
        """Propagate a trusted child's write signal to an attributable ancestor."""
        if not self.is_user_file(filename):
            return False

        direct_parent_pid = getattr(event, "ppid", 0) or self._parent_pid_cache.get(pid)
        subject = self._find_attributable_subject(
            pid,
            now=now,
            direct_parent_pid=direct_parent_pid,
        )
        if subject is None:
            return False
        subject_pid, subject_comm, attribution_mode = subject

        sample_len = min(int(event.size), len(event.buffer))
        if sample_len <= 0:
            return False

        entropy = self.calculate_entropy(bytes(event.buffer[:sample_len]))
        self._record_write_signal(subject_pid, filename, entropy, now)
        self._check_behavioral_heuristics(
            subject_pid,
            comm=subject_comm,
            now=now,
            attributed_from=(pid, comm),
            attribution_mode=attribution_mode,
        )
        return True

    def _should_suppress_whitelisted_helper(self, pid, now=None, direct_parent_pid=None):
        """Return True when a trusted helper is acting under an attributable parent.

        This keeps the helper itself quiet while allowing the parent
        orchestrator to accumulate the delegated behavioral signal.
        """
        subject = self._find_attributable_subject(
            pid,
            now=now,
            direct_parent_pid=direct_parent_pid,
        )
        return subject is not None and subject[0] != pid

    # ------------------------------------------------------------------
    # Core event analysis
    # ------------------------------------------------------------------

    def analyze_event(self, event):
        pid = event.pid
        ppid = getattr(event, "ppid", 0) or None
        comm = self._decode_cstring(event.comm)
        filename = self._decode_cstring(event.filename)
        now = time.time()
        if ppid is not None:
            self._parent_pid_cache[pid] = ppid
        self._comm_cache[pid] = comm
        self._remember_behavioral_identity(pid, comm, now)
        is_canary_access = self.is_canary(filename)

        # Name-whitelisted helper tools stay quiet themselves, but their
        # WRITE signals can be inherited by a non-whitelisted ancestor that
        # is actively traversing or modifying the filesystem.
        if (
            event.type == 1
            and comm in self.whitelisted_processes
            and not is_canary_access
        ):
            if self._attribute_child_write(event, pid, comm, filename, now):
                return

        if (
            comm in self.whitelisted_processes
            and not is_canary_access
            and self._should_suppress_whitelisted_helper(
                pid,
                now=now,
                direct_parent_pid=ppid,
            )
        ):
            return

        # --- Whitelist check (false-positive reduction) ---
        # Canary access from whitelisted processes is still flagged.
        if self.is_whitelisted(comm, pid=pid) and not is_canary_access:
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
        # 0: OPEN, 1: WRITE, 2: RENAME, 3: UNLINK, 4: GETDENTS

        if event.type == 0:  # OPEN
            # Track opened files for in-place overwrite detection.
            # The eBPF layer only emits OPEN events for O_CREAT, but we
            # record the filename anyway so that the fd_to_filename map
            # correlation in the WRITE handler can be cross-referenced.
            # For non-O_CREAT opens (tracked via fd_to_filename in BPF),
            # we rely on the write-path not being a new file.
            self.open_tracker[pid][filename] = now

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
            # --- Write target classification (false-positive reduction) ---
            if not self.is_user_file(filename):
                return

            sample_len = min(int(event.size), len(event.buffer))
            buffer_bytes = bytes(event.buffer[:sample_len])
            entropy = self.calculate_entropy(buffer_bytes)
            self._record_write_signal(pid, filename, entropy, now)

            # --- Magic-byte and in-place overwrite checks ---
            # Both require multi-file in-place overwrites to fire (single-
            # file encryption like ccencrypt is legitimate).
            is_overwrite = self.is_in_place_overwrite(pid, filename)
            overwritten_count = 0
            if is_overwrite and entropy > self.threshold_entropy:
                overwritten_count = len({
                    e[2] for e in self.process_stats[pid]
                    if e[1] > self.threshold_entropy
                    and self.is_in_place_overwrite(pid, e[2])
                })

            if (
                self.magic_bytes_destroyed(buffer_bytes, entropy)
                and is_overwrite
                and overwritten_count >= 2
            ):
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

            if is_overwrite and entropy > self.threshold_entropy and overwritten_count >= 2:
                opened_files = list(self.open_tracker.get(pid, {}).keys())
                if not self.is_legitimate_output_name(filename, opened_files):
                    print(
                        f"[!!!] ALERT: In-place overwrite of '{filename}' "
                        f"with high-entropy data by {comm} (PID {pid}) "
                        f"(entropy {entropy:.2f})"
                    )
                    self._record_alert(
                        pid, comm, "In-place overwrite",
                        severity="critical", entropy=entropy, filename=filename,
                    )
                    self.take_action(pid, comm, "In-place overwrite")

            # --- Cumulative profile update (slow-burn detection) ---
            self._update_profile_write(pid, filename, entropy, is_overwrite)
            self._check_cumulative_alert(pid, comm)

            self._check_behavioral_heuristics(pid, comm=comm, now=now)

        elif event.type == 3:  # UNLINK
            self.unlink_stats[pid].append(now)

            # Clean up old events
            self.unlink_stats[pid] = [
                t for t in self.unlink_stats[pid] if now - t <= self.time_window
            ]

            # --- Write-then-unlink correlation ---
            if self.check_write_then_unlink(pid, filename, now):
                print(
                    f"[!!!] ALERT: Write-then-delete pattern from "
                    f"{comm} (PID {pid}): deleting '{filename}' after "
                    f"writing to multiple other files"
                )
                self._record_alert(
                    pid, comm, "Write-then-delete",
                    severity="critical", deleted_file=filename,
                )
                self.take_action(pid, comm, "Write-then-delete")

            # --- Cumulative profile update (slow-burn detection) ---
            self._update_profile_unlink(pid, filename)
            self._check_cumulative_alert(pid, comm)

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

        elif event.type == 4:  # GETDENTS (directory listing)
            directory = os.path.dirname(filename) if filename else filename
            self.dir_scan_stats[pid].append((now, directory))

            # Clean up old events
            self.dir_scan_stats[pid] = [
                e for e in self.dir_scan_stats[pid]
                if now - e[0] <= self.time_window
            ]

            unique_scanned = {e[1] for e in self.dir_scan_stats[pid]}
            has_recent_writes = len(self.process_stats.get(pid, [])) > 0

            if (
                len(unique_scanned) >= self.threshold_dir_scans
                and has_recent_writes
            ):
                print(
                    f"[!!!] ALERT: Directory traversal + write activity "
                    f"from {comm} (PID {pid})"
                )
                print(
                    f"      Scanned {len(unique_scanned)} directories "
                    f"in {self.time_window}s with active writes"
                )
                self._record_alert(
                    pid, comm, "Directory traversal + Writes",
                    severity="critical",
                    scanned_dirs=len(unique_scanned),
                )
                self.take_action(pid, comm, "Directory traversal + Writes")

    # ------------------------------------------------------------------
    # EDR Response Chain
    # ------------------------------------------------------------------

    def take_action(self, pid, comm, reason):
        """Execute the graduated EDR response chain.

        The six steps mirror production AV/EDR tools:
        1. Process Kill — terminate the process tree
        2. Quarantine — move the binary to a secure location
        3. Network Isolation — block the PID's network access
        4. Remediation — log modified files for recovery
        5. Rollback — trigger a filesystem snapshot
        6. Binary Hardening — strip exec bit, add to blocklist

        In ``simulate`` mode, all steps are logged but not executed.
        In ``suspend`` mode, only step 1 uses SIGSTOP instead of SIGKILL.
        In ``kill`` mode, the full chain executes.
        """
        severity = "unknown"
        for a in reversed(self.alerts):
            if a.get("pid") == pid:
                severity = a.get("severity", "unknown")
                break

        print(
            f"[X] ACTION ({self.action_mode}): {comm} (PID {pid}) — "
            f"{reason} [severity={severity}]"
        )

        if self.action_mode == "simulate":
            print(f"      [simulate] Would execute full EDR chain for PID {pid}")
            return

        # --- Step 1: Process Kill / Suspend ---
        self._step_kill_process(pid, comm)

        # --- Step 2: Quarantine the binary ---
        exe_path = self._resolve_exe(pid)
        quarantined_path = self._step_quarantine(pid, comm, exe_path)

        # --- Step 3: Network Isolation ---
        self._step_network_isolate(pid, comm)

        # --- Step 4: Remediation (log modified files) ---
        self._step_remediate(pid, comm)

        # --- Step 5: Rollback (filesystem snapshot) ---
        if severity == "critical":
            self._step_rollback(pid, comm)

        # --- Step 6: Binary Hardening ---
        self._step_harden_binary(pid, comm, exe_path, quarantined_path)

    def _step_kill_process(self, pid, comm):
        """Step 1: Kill or suspend the process and its children."""
        sig = signal_mod.SIGSTOP if self.action_mode == "suspend" else signal_mod.SIGKILL
        sig_name = "SIGSTOP" if self.action_mode == "suspend" else "SIGKILL"

        # Kill children first (best-effort via /proc/<pid>/task/*/children)
        children = self._get_child_pids(pid)
        for cpid in children:
            try:
                os.kill(cpid, sig)
                print(f"      [step1] Sent {sig_name} to child PID {cpid}")
            except (ProcessLookupError, PermissionError):
                pass

        # Kill the main process
        try:
            os.kill(pid, sig)
            print(f"      [step1] Sent {sig_name} to PID {pid} ({comm})")
        except ProcessLookupError:
            print(f"      [step1] PID {pid} already exited")
        except PermissionError:
            print(f"      [step1] Permission denied for PID {pid}")
        except Exception as exc:
            print(f"      [step1] Error signaling PID {pid}: {exc}")

    @staticmethod
    def _get_child_pids(pid):
        """Return a list of child PIDs for *pid* via /proc."""
        children = []
        try:
            children_path = f"/proc/{pid}/task/{pid}/children"
            with open(children_path, "r") as fh:
                children = [int(p) for p in fh.read().split() if p.strip()]
        except (OSError, ValueError):
            pass
        return children

    def _step_quarantine(self, pid, comm, exe_path):
        """Step 2: Move the offending binary to the quarantine directory.

        Returns the quarantined path, or None if quarantine failed.
        """
        if not exe_path or not os.path.isfile(exe_path):
            print(f"      [step2] Cannot quarantine: binary not found for PID {pid}")
            return None

        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            quarantined = os.path.join(
                self.quarantine_dir,
                f"{comm}_{pid}_{int(time.time())}_{os.path.basename(exe_path)}",
            )
            shutil.copy2(exe_path, quarantined)
            # Strip all permission bits from the quarantined copy
            os.chmod(quarantined, 0o000)
            print(f"      [step2] Quarantined {exe_path} → {quarantined}")
            return quarantined
        except (OSError, shutil.Error) as exc:
            print(f"      [step2] Quarantine failed for {exe_path}: {exc}")
            return None

    def _step_network_isolate(self, pid, comm):
        """Step 3: Block network access for the offending process via iptables.

        Uses the owner match module to drop all outbound packets from the
        process's UID.  This prevents C2 communication and data exfiltration.
        """
        if not self.enable_network_isolation:
            print(f"      [step3] Network isolation disabled (use --enable-network-isolation)")
            return

        # Get the UID of the process
        uid = self._get_pid_uid(pid)
        if uid is None:
            print(f"      [step3] Cannot determine UID for PID {pid}")
            return

        try:
            # Block outbound traffic from this UID
            subprocess.run(
                [
                    "iptables", "-A", "OUTPUT",
                    "-m", "owner", "--uid-owner", str(uid),
                    "-j", "DROP",
                ],
                capture_output=True, text=True, timeout=5,
            )
            print(f"      [step3] Blocked outbound traffic for UID {uid} (PID {pid})")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            print(f"      [step3] Network isolation failed: {exc}")

    @staticmethod
    def _get_pid_uid(pid):
        """Read the real UID of *pid* from /proc/<pid>/status."""
        try:
            with open(f"/proc/{pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        return None

    def _step_remediate(self, pid, comm):
        """Step 4: Log all files modified by the flagged process.

        In a full implementation this would revert changes (restore from
        backup, undo renames).  Currently we log the list for manual or
        automated recovery.
        """
        modified = self._pid_modified_files.get(pid, [])
        if not modified:
            print(f"      [step4] No tracked file modifications for PID {pid}")
            return

        unique_files = list(dict.fromkeys(modified))  # Deduplicate, preserve order
        print(f"      [step4] {len(unique_files)} files modified by {comm} (PID {pid}):")
        for f in unique_files[:20]:  # Print first 20
            print(f"              - {f}")
        if len(unique_files) > 20:
            print(f"              ... and {len(unique_files) - 20} more")

    def _step_rollback(self, pid, comm):
        """Step 5: Trigger a filesystem snapshot for rollback."""
        if not self.snapshot_cmd:
            print(f"      [step5] No snapshot command configured (use --snapshot-cmd)")
            return

        if self._snapshot_triggered:
            print(f"      [step5] Snapshot already triggered this session")
            return

        self._snapshot_triggered = True
        print(f"      [step5] Running snapshot: {self.snapshot_cmd}")
        try:
            result = subprocess.run(
                self.snapshot_cmd, shell=True, timeout=30,
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(f"      [step5] Snapshot created successfully")
            else:
                print(f"      [step5] Snapshot command exited with code {result.returncode}")
                if result.stderr:
                    print(f"              stderr: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"      [step5] Snapshot command timed out")
        except Exception as exc:
            print(f"      [step5] Snapshot failed: {exc}")

    def _step_harden_binary(self, pid, comm, exe_path, quarantined_path):
        """Step 6: Strip execute permission and add to persistent blocklist."""
        if exe_path and os.path.isfile(exe_path):
            try:
                current = os.stat(exe_path).st_mode
                os.chmod(exe_path, current & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                print(f"      [step6] Stripped exec bit from {exe_path}")
            except OSError as exc:
                print(f"      [step6] Cannot strip exec bit from {exe_path}: {exc}")

        # Add to persistent blocklist
        if exe_path:
            self.blocklist.add(exe_path)
            print(f"      [step6] Added {exe_path} to blocklist ({len(self.blocklist)} entries)")
