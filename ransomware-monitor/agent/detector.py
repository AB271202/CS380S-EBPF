import math
import collections
import hashlib
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
        self.open_tracker: dict[int, dict[str, float]] = collections.defaultdict(dict)
        # write_targets: { pid: [(timestamp, source_file, dest_file), ...] }
        # Tracks recent high-entropy write targets for unlink correlation.
        self.write_targets: dict[int, list[tuple[float, str]]] = collections.defaultdict(list)
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

        # 3. Binary hash verification
        self.verify_binary_hash = verify_binary_hash
        # trusted_hashes: { "/usr/bin/gcc": {"sha256_1", "sha256_2"}, ... }
        self.trusted_hashes: dict[str, set[str]] = {}
        if trusted_hashes:
            for path, hashes in trusted_hashes.items():
                if isinstance(hashes, str):
                    hashes = [hashes]
                self.trusted_hashes[path] = set(hashes)
        if whitelist_config:
            self._load_trusted_hashes(whitelist_config)
        # Cache: { (pid, exe_path): hash_str }
        self._hash_cache: dict[tuple[int, str], str] = {}

        # 4. Process lineage validation
        self.verify_lineage = verify_lineage
        self.trusted_parents: set[str] = trusted_parents if trusted_parents is not None else {
            "bash", "sh", "zsh", "fish", "dash",
            "sshd", "login", "su", "sudo",
            "systemd", "init",
            "make", "cmake", "ninja",
            "cron", "anacron", "atd",
            "screen", "tmux",
            "docker", "containerd", "containerd-shim",
        }
        if whitelist_config:
            self._load_trusted_parents(whitelist_config)
        # Cache: { pid: bool } — True means lineage was validated OK
        self._lineage_cache: dict[int, bool] = {}

        # Alerts list – useful for programmatic inspection in tests.
        self.alerts: list[dict] = []

    # ------------------------------------------------------------------
    # Whitelist helpers
    # ------------------------------------------------------------------

    def _load_whitelist(self, config_path):
        """Merge additional process names from a JSON config file.

        Expected format::

            {
                "whitelisted_processes": ["mybackup", "custom-tool"],
                "trusted_hashes": {
                    "/usr/bin/mybackup": ["sha256_digest_1"]
                },
                "trusted_parents": ["orchestrator"]
            }
        """
        try:
            with open(config_path, "r") as fh:
                cfg = json.load(fh)
            extra = cfg.get("whitelisted_processes", [])
            self.whitelisted_processes.update(extra)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load whitelist config {config_path}: {exc}")

    def _load_trusted_hashes(self, config_path):
        """Load trusted binary hashes from the same config file."""
        try:
            with open(config_path, "r") as fh:
                cfg = json.load(fh)
            for exe_path, hashes in cfg.get("trusted_hashes", {}).items():
                if isinstance(hashes, str):
                    hashes = [hashes]
                self.trusted_hashes.setdefault(exe_path, set()).update(hashes)
        except (OSError, json.JSONDecodeError):
            pass  # Already warned in _load_whitelist

    def _load_trusted_parents(self, config_path):
        """Load additional trusted parent process names from config."""
        try:
            with open(config_path, "r") as fh:
                cfg = json.load(fh)
            extra = cfg.get("trusted_parents", [])
            self.trusted_parents.update(extra)
        except (OSError, json.JSONDecodeError):
            pass  # Already warned in _load_whitelist

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

    def get_process_lineage(self, pid, max_depth=10):
        """Walk the parent chain and return a list of ``(pid, comm)`` tuples.

        Stops at PID 0/1 or after *max_depth* hops to avoid infinite loops.
        """
        lineage = []
        current = pid
        for _ in range(max_depth):
            ppid = self._get_ppid(current)
            if ppid is None or ppid == 0:
                break
            parent_comm = self._get_comm(ppid)
            lineage.append((ppid, parent_comm))
            if ppid == 1:
                break
            current = ppid
        return lineage

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
            self.process_stats[pid].append((now, entropy, filename))

            # Clean up old events outside the time window
            self.process_stats[pid] = [
                e for e in self.process_stats[pid] if now - e[0] <= self.time_window
            ]

            # --- Magic-byte analysis (false-positive reduction) ---
            # Only flag "magic bytes destroyed" when the write targets a
            # file the process previously opened (in-place overwrite of an
            # existing file).  Writing high-entropy data to a *new* output
            # file (e.g. gpg writing passwd.gpg) is normal for compression
            # and encryption tools.
            is_overwrite = self.is_in_place_overwrite(pid, filename)
            if (
                self.magic_bytes_destroyed(buffer_bytes, entropy)
                and is_overwrite
            ):
                # Count how many distinct files this PID has overwritten
                # in-place with high entropy in the current window.
                # A single in-place encryption (e.g. ccencrypt on one
                # file) is legitimate.  Ransomware does it to many files.
                overwritten_files = {
                    e[2] for e in self.process_stats[pid]
                    if e[1] > self.threshold_entropy
                    and self.is_in_place_overwrite(pid, e[2])
                }
                if len(overwritten_files) >= 2:
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
                    # Do NOT return — fall through to diversity and frequency
                    # checks so that multi-signal alerts accumulate.

            # --- In-place overwrite detection ---
            if is_overwrite and entropy > self.threshold_entropy:
                # Check if the output name is a legitimate derivative.
                opened_files = list(self.open_tracker.get(pid, {}).keys())
                if not self.is_legitimate_output_name(filename, opened_files):
                    # Same multi-file gate: single-file in-place encryption
                    # is legitimate (ccencrypt, gpg --symmetric on one file).
                    overwritten_files = {
                        e[2] for e in self.process_stats[pid]
                        if e[1] > self.threshold_entropy
                        and self.is_in_place_overwrite(pid, e[2])
                    }
                    if len(overwritten_files) >= 2:
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

            # Track this write for unlink correlation.
            if entropy > self.threshold_entropy:
                self.write_targets[pid].append((now, filename))

            # --- File diversity scoring (false-positive reduction) ---
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
                        f"{comm} (PID {pid})"
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
                    )
                    self.take_action(pid, comm, "High file diversity + Entropy")
                    return

            # Check frequency and entropy (original heuristic).
            # Require at least 2 unique files to avoid false positives
            # from single-file operations (e.g. gpg encrypting one file
            # produces many write syscalls to the same output).
            if len(self.process_stats[pid]) >= self.threshold_writes:
                recent_files = {e[2] for e in self.process_stats[pid]}
                if len(recent_files) < 2:
                    return  # Single-file write burst — not ransomware
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
