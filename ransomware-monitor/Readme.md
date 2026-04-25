**The High-Level Pathway**
To build a ransomware monitor, you need a pipeline that extracts context from the kernel, filters it, and passes it to user space for analysis and potential enforcement.

1. *Kernel Space: The eBPF Hooks*
You will write an eBPF program (typically in restricted C) that attaches to specific tracepoints or kprobes in the Linux kernel.

Target Syscalls: You will want to monitor file I/O operations like openat, read, write, rename, and close.

Context Gathering: For every intercepted call, your eBPF program collects the Process ID (PID), the process name (comm), the file path being accessed, and potentially a sample of the data buffer being written.

In-Kernel Filtering: To avoid overwhelming your user-space program with every single disk write, you can use an eBPF Map (like a Hash Map) to track state inside the kernel. For example, you can track how many unique files a specific PID has opened in the last second.

2. *The Bridge: eBPF Maps*
You need a fast, asynchronous way to send suspicious events from the kernel to your user-space monitor.

Ring Buffers (BPF_MAP_TYPE_RINGBUF): This is the modern standard for streaming event data. When your in-kernel filter decides a process is acting suspiciously (e.g., it crossed a threshold of 50 file writes in 1 second), it writes an event struct to the ring buffer.

3. *User Space: The Analysis Engine*
This is your primary application, usually written in C/Python using libraries like libbpf (C/Rust). It continuously polls the ring buffer for new events.

Heuristics & Entropy: The user-space engine evaluates the events. Is the process renaming .docx files to .locked? Is the data being written highly randomized? (High entropy in a write buffer is a strong indicator of encryption).

Deletion Patterns: Is the process deleting a large number of files in a short period? Ransomware often deletes original files after encrypting them.

Enforcement: If the monitor determines a PID is acting like ransomware, it can take immediate action, such as issuing a SIGKILL to terminate the process before it encrypts more files.

**File Structure**
What goes where in the Python/C paradigm:
* bpf/monitor.bpf.c: This contains pure, restricted C code. It defines the tracepoints (e.g., hooking into sys_enter_write) and the structure of the data you want to send up to Python.

* agent/main.py: This script uses the bcc Python library. It will initialize the BPF system, read monitor.c from disk, attach the C functions to the kernel hooks, and then sit in a loop listening to the eBPF perf buffer or ring buffer.

* agent/detector.py: Your Python heuristics engine. As main.py hands it events (PID 1234 wrote 4KB to /home/user/doc.txt), this module updates its internal trackers. If it detects a ransomware pattern, it uses Python's os.kill() to terminate the process.

* requirements.txt: You will primarily need bcc (the Python bindings for the BPF Compiler Collection).

A note on the naming convention
The libbpf (Modern) Standard: In the Go/Rust/C world using modern libbpf (which we originally discussed), the .bpf.c extension is practically mandatory. It tells the compiler (Clang) and your Makefile, "Hey, compile this to the BPF bytecode target, not a standard x86/ARM executable."

The BCC (Python) Quirk: BCC is a bit of a rebel. When you use Python with BCC, the Python script literally reads your C file as a giant raw text string and compiles it on the fly using its own internal LLVM engine. Because Python just sees it as text, it doesn't care if you name it monitor.c, monitor.bpf.c, or monitor.txt. Older BCC tutorials often just use .c.

---

## Quick Start & Verification

### 1. Installation
Install the necessary eBPF tools and Python dependencies:
```bash
make deps
```

### 2. Run the Monitor
The monitor requires root privileges to load the eBPF program into the kernel:
```bash
make run
```
You should see output indicating that the BPF program is loading and the monitor has started.

### 3. Verify Detection
Open a separate terminal and use the provided test targets to simulate ransomware-like behavior and trigger alerts.

**Detection by Suspicious Extension:**
Run the following command to simulate creating and renaming files with suspicious extensions (like `.locked` or `.crypto`):
```bash
make test-extension
```
The monitor will output:
`[!] ALERT: Suspicious file open '.locked' detected from touch (PID XXXX)`
`[!] ALERT: Suspicious rename to '.crypto' detected from mv (PID XXXX)`

**Detection by Entropy (Encryption Simulation):**
Run the following command to simulate high-frequency, high-entropy writes (e.g., random data being written quickly):
```bash
make test-entropy
```
The monitor will detect the high frequency and high entropy of the writes:
`[!!!] ALERT: Potential ransomware behavior from python3 (PID XXXX)`
`      High write frequency (10 in 1.0s) and high entropy (7.xx)`
`[X] ACTION: Terminating process python3 (PID XXXX) due to High entropy + Frequency...`
`      (Simulation) Sent SIGKILL to PID XXXX`

**Detection by Deletion (High-Frequency Unlink Simulation):**
Run the following command to simulate a process deleting a large number of files in a short period:
```bash
make test-unlink
```
The monitor will detect the high-frequency deletions:
`[!!!] ALERT: Potential ransomware behavior from python3 (PID XXXX)`
`      High unlink frequency (10 in 1.0s)`
`[X] ACTION: Terminating process python3 (PID XXXX) due to High unlink frequency...`

### 4. Results & Actions
The `agent/detector.py` script is currently configured to **simulate** process termination. It will print an `[X] ACTION` message but will not actually kill the process unless you uncomment `os.kill(pid, 9)` in the `take_action` method.


---

## False-Positive Reduction

The detector includes three mechanisms to reduce false positives from legitimate high-I/O applications (compilers, databases, backup tools, editors) while improving detection confidence for actual ransomware.

### 1. Process Whitelist

A built-in set of trusted process names is skipped during analysis. This prevents alerts from common developer and system tools such as `git`, `gcc`, `make`, `apt`, `rsync`, `vim`, `postgres`, and many others.

The whitelist is hardened with two additional verification layers (see sections 4 and 5 below) to prevent adversaries from abusing whitelisted process names.

The whitelist can be extended at runtime via a JSON configuration file:

```json
{
    "whitelisted_processes": ["my-backup-tool", "custom-sync"],
    "trusted_hashes": {
        "/usr/bin/my-backup-tool": ["sha256_hex_digest_here"]
    },
    "trusted_parents": ["my-orchestrator"]
}
```

Pass the config path when constructing the detector:

```python
detector = RansomwareDetector(whitelist_config="/etc/ransomware-monitor/whitelist.json")
```

Or from `main.py` by adding a `--whitelist` CLI argument.

**Key behaviour:** Even whitelisted processes will trigger an alert if they access a canary file (see below). The whitelist only suppresses the standard heuristic checks.

### 2. Canary (Honeypot) Files

Hidden sentinel files are deployed into sensitive directories. Any non-whitelisted process that opens, writes, renames, or deletes a canary triggers an immediate **critical** alert — regardless of entropy or frequency thresholds.

Deploy canaries by passing directories at init time:

```python
detector = RansomwareDetector(canary_dirs=[
    os.path.expanduser("~/Documents"),
    "/srv/shared",
])
```

Default canary filenames: `.~canary_doc.docx`, `.~canary_photo.jpg`, `.~canary_data.xlsx`. Custom names can be provided via `deploy_canaries(directory, filenames=[...])`.

### 3. File Header (Magic Bytes) Analysis

On every WRITE event the detector inspects the first bytes of the write buffer against a table of known file-type signatures (PDF, PNG, JPEG, ZIP/DOCX, GIF, ELF, GZIP, BMP, TIFF). If the buffer does **not** match any known header **and** the entropy exceeds 6.0, the write is flagged as a **critical** "Magic bytes destroyed" alert — a strong signal that an existing file's header is being overwritten with ciphertext.

This check fires per-write and is independent of the frequency/entropy accumulation window, giving faster detection for in-place encryption attacks.

### 4. Binary Hash Verification

A name-based whitelist alone can be bypassed if an adversary replaces or injects code into a trusted binary (e.g., swapping `/usr/bin/gcc` with a malicious executable, or using `LD_PRELOAD` hijacking). To counter this, the detector computes the SHA-256 hash of the on-disk executable (`/proc/<pid>/exe`) for every whitelisted process and compares it against a set of known-good digests.

**How it works:**
- When a whitelisted process name is seen, the detector resolves `/proc/<pid>/exe` to the real binary path.
- The SHA-256 of that binary is computed and compared against registered trusted hashes.
- If the hash does **not** match, the whitelist is **revoked** for that process and a `"Binary hash mismatch"` alert is recorded. The process then goes through full heuristic analysis.
- Results are cached per `(pid, exe_path)` to avoid re-hashing on every event.

**Open trust model:** If no hashes are registered for a given binary path, the check is skipped (the process is trusted by name alone). This allows gradual adoption — you only need to register hashes for binaries you want to lock down.

Register trusted hashes via the config file:

```json
{
    "trusted_hashes": {
        "/usr/bin/gcc-12": ["e3b0c44298fc1c149afbf4c8996fb924..."],
        "/usr/bin/rsync": ["a1b2c3d4..."]
    }
}
```

Or programmatically:

```python
detector = RansomwareDetector(
    trusted_hashes={"/usr/bin/gcc-12": ["sha256_hex_digest"]},
)
```

Generate a hash for a binary: `sha256sum /usr/bin/gcc-12`

### 5. Process Lineage Validation

Even with hash verification, an adversary could compile a clean copy of `gcc` and run it from a malicious dropper. To catch this, the detector walks the parent-process chain via `/proc/<pid>/status` and checks that at least one ancestor has a comm name in the set of trusted parents.

**How it works:**
- The parent chain is walked up to 10 levels (configurable).
- If at least one ancestor is in the trusted parents set (`bash`, `sh`, `make`, `systemd`, `sshd`, `sudo`, `cron`, `docker`, etc.), the process is considered legitimate.
- If **no** trusted ancestor is found, the whitelist is **revoked** and an `"Untrusted process lineage"` alert is recorded.
- Results are cached per PID.

**Default trusted parents:** `bash`, `sh`, `zsh`, `fish`, `dash`, `sshd`, `login`, `su`, `sudo`, `systemd`, `init`, `make`, `cmake`, `ninja`, `cron`, `anacron`, `atd`, `screen`, `tmux`, `docker`, `containerd`, `containerd-shim`.

Extend via config:

```json
{
    "trusted_parents": ["my-orchestrator", "custom-scheduler"]
}
```

Or programmatically:

```python
detector = RansomwareDetector(
    trusted_parents={"bash", "my_orchestrator"},
)
```

**Both checks must pass.** If the binary hash matches but the lineage is untrusted (or vice versa), the whitelist is revoked. Either verification can be independently disabled via `verify_binary_hash=False` or `verify_lineage=False`.

### 6. File Diversity Scoring

Raw write frequency and entropy alone cannot distinguish ransomware from a disk defragmenter or database — both produce high-entropy writes at high frequency. The key difference is *what* they write to.

The detector now tracks how many **unique file paths** and **unique parent directories** each PID writes to within the time window. A process touching `report.docx`, `photo.jpg`, and `budget.xlsx` across `/home/user/Documents`, `/home/user/Pictures`, and `/home/user/Desktop` is far more suspicious than one writing to `/dev/sda1` fifty times.

**Thresholds (configurable):**
- `threshold_unique_files` (default: 8) — minimum unique file paths in the window
- `threshold_unique_dirs` (default: 3) — minimum unique parent directories

Both thresholds must be exceeded *and* the average entropy must be above `threshold_entropy` for the alert to fire. This means:
- A defragmenter writing to the same file or block device repeatedly → **no alert**
- A database writing many files under `/var/lib/` → **no alert** (system path, see below)
- Ransomware encrypting files across `~/Documents`, `~/Pictures`, `~/Desktop` → **alert**

### 7. Directory Traversal Detection

Ransomware typically scans the filesystem for targets before encrypting. The eBPF layer now hooks `getdents64` (the syscall behind `readdir`) and sends `GETDENTS` events (type 4) to user space.

The detector tracks how many **unique directories** a PID has listed within the time window. If the count exceeds `threshold_dir_scans` (default: 5) **and** the process has recent write activity, a critical `"Directory traversal + Writes"` alert fires.

This catches the "scan then encrypt" pattern that is a strong ransomware signature. A tool like `find` or `ls -R` that only reads directories without writing will not trigger the alert.

### 8. Write Target Classification

Writes to system paths are now excluded from all entropy, frequency, and diversity heuristics. The following path prefixes are classified as non-user targets:

- `/dev/` — block and character devices
- `/proc/` — procfs
- `/sys/` — sysfs
- `/run/` — runtime state
- `/tmp/.` — hidden temp files
- `/var/log/` — log files
- `/var/lib/` — package and database state
- `/var/cache/` — caches

This means a defragmenter writing high-entropy data to `/dev/sda1`, or a database writing to `/var/lib/postgresql/`, will produce **zero alerts** regardless of frequency or entropy. Only writes to user-accessible paths (e.g., `/home/`, `/srv/`, `/opt/`) are analyzed.

### 9. In-Place Overwrite Detection

Legitimate encryption and compression tools read a source file and write to a **new** output file (`report.docx` → `report.docx.gz`). Ransomware opens a file and writes ciphertext **back to the same file**, destroying the original in-place.

The detector tracks OPEN events per PID. When a subsequent WRITE targets the same file path with high-entropy data, and the output name is not a legitimate derivative of any opened file (see section 10), a critical `"In-place overwrite"` alert fires.

This catches the most destructive ransomware pattern — in-place encryption — while allowing normal editor saves (low entropy) and compression tools (different output path) to pass through silently.

### 10. Output-to-Input Path Correlation

Legitimate tools produce output files with predictable naming derived from the input:
- `gzip`: `data.csv` → `data.csv.gz`
- `gpg`: `secret.txt` → `secret.txt.gpg`
- `zip`: `report.docx` → `report.zip`
- `xz`: `dump.sql` → `dump.sql.xz`

Ransomware renames to unrelated extensions: `photo.jpg` → `photo.jpg.locked`, `report.docx` → `report.docx.a1b2c3`.

The detector maintains a list of known legitimate output suffixes (`.gz`, `.bz2`, `.xz`, `.zst`, `.zip`, `.gpg`, `.enc`, `.7z`, `.rar`, etc.) and checks whether a high-entropy write target is a plausible derivative of a recently-opened file. If it is, the in-place overwrite alert is suppressed.

### 11. Write-Then-Delete Correlation

Ransomware often follows an "encrypt copy, then delete original" pattern: write `photo.jpg.locked`, then `unlink("photo.jpg")`. Legitimate tools like `gzip` do this too, but for **one file at a time**.

The detector tracks recent high-entropy write targets per PID. When an UNLINK event occurs for a file that is **not** one of the recent write targets (i.e., the original, not the encrypted copy), and the PID has written to **3 or more distinct** files recently, a critical `"Write-then-delete"` alert fires.

This threshold of 3 ensures that single-file compression (`gzip data.csv` → delete `data.csv`) passes silently, while bulk encrypt-then-delete operations are caught.

### Running the Unit Tests

The detection engine is covered by four test modules in `tests/`:

\begin{itemize}
    \item \texttt{test\_basic\_detection.py} — entropy, frequency, extensions, unlinks, magic bytes, combined scenarios
    \item \texttt{test\_false\_positive\_reduction.py} — whitelist, hash verification, lineage, canary files, write classification, diversity, traversal, in-place overwrite, path correlation, write-then-delete, defrag vs ransomware, legitimate encryption
    \item \texttt{test\_advanced\_detection.py} — process-tree attribution, slow-burn profiling, urandom tracking, kill signal detection
    \item \texttt{test\_mitigation.py} — EDR response chain (kill/suspend, quarantine, network isolation, remediation, rollback)
\end{itemize}

Run them with:

```bash
make unit-test
# or
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Test categories:
- **TestProcessWhitelist** — verifies trusted processes are silent, unknown processes still alert, config loading, and error handling.
- **TestBinaryHashVerification** — SHA-256 computation, matching/mismatched hashes, open trust when no hashes registered, caching, end-to-end tampered binary detection, config loading.
- **TestProcessLineageValidation** — trusted/untrusted parent chains, empty lineage handling, caching, end-to-end untrusted lineage detection, custom parents, config loading, smoke test on real PID.
- **TestHashAndLineageCombined** — both-pass, hash-pass/lineage-fail, hash-fail/lineage-pass, both-fail scenarios.
- **TestCanaryFiles** — canary deployment, critical alerts on access, whitelisted-process canary access still alerts, non-canary files are not flagged.
- **TestMagicByteAnalysis** — magic-byte identification for PDF/PNG/JPEG/ZIP, destroyed-header detection, end-to-end WRITE event triggering critical alerts.
- **TestWriteTargetClassification** — system paths (`/dev/`, `/proc/`, `/var/lib/`) excluded, user paths (`/home/`, `/srv/`) included, end-to-end defrag and database silence.
- **TestFileDiversityScoring** — diverse writes across directories trigger alerts, single-directory writes do not, low-entropy diverse writes do not, defragmenter repeated writes do not.
- **TestDirectoryTraversalDetection** — scan + write triggers alert, scan-only does not, below-threshold does not, time-window expiry works.
- **TestDefragVsRansomware** — end-to-end scenarios: block-device defrag (no alerts), single-file defrag (no alerts), multi-directory ransomware encryption (alert), scan-then-encrypt (alert), database writes (no alerts).
- **TestInPlaceOverwriteDetection** — overwriting an opened file with high-entropy data triggers alert, writing to new files does not, low-entropy overwrites do not, legitimate .gz output does not.
- **TestOutputPathCorrelation** — `.gz`, `.gpg`, `.xz`, `.enc`, `.zip` base-name matches are legitimate; `.locked`, random extensions, unrelated names are not.
- **TestWriteThenUnlinkCorrelation** — writing to 3+ files then deleting a different file triggers alert, deleting own write target does not, single-file gzip pattern does not, low-entropy writes do not, time-window expiry works.
- **TestLegitEncryptionVsRansomware** — end-to-end: gzip single file (no alerts), gpg encrypt (no alerts), zip archive (no alerts), tar|gzip pipeline (no alerts), ransomware in-place encrypt (alert), ransomware encrypt-then-delete (alert).
- **TestEntropyCalculation** — entropy edge cases (empty, uniform, random, max).
- **TestHighEntropyWriteDetection** — frequency + entropy burst detection regression.
- **TestSuspiciousExtensionDetection** — OPEN/RENAME with `.locked`/`.crypto` extensions.
- **TestUnlinkDetection** — high-frequency deletion alerts and time-window expiry.
- **TestCombinedScenarios** — realistic multi-signal scenarios: gcc compilation (no alerts), rsync mass-delete (no alerts), full ransomware attack chain (multiple alerts).
