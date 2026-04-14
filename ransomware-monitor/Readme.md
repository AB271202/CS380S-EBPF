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

The whitelist can be extended at runtime via a JSON configuration file:

```json
{
    "whitelisted_processes": ["my-backup-tool", "custom-sync"]
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

### Running the Unit Tests

The false-positive reduction features are covered by `tests/test_detector.py` (41 tests). Run them with:

```bash
python3 -m unittest tests/test_detector.py -v
```

Test categories:
- **TestProcessWhitelist** — verifies trusted processes are silent, unknown processes still alert, config loading, and error handling.
- **TestCanaryFiles** — canary deployment, critical alerts on access, whitelisted-process canary access still alerts, non-canary files are not flagged.
- **TestMagicByteAnalysis** — magic-byte identification for PDF/PNG/JPEG/ZIP, destroyed-header detection, end-to-end WRITE event triggering critical alerts.
- **TestEntropyCalculation** — entropy edge cases (empty, uniform, random, max).
- **TestHighEntropyWriteDetection** — frequency + entropy burst detection regression.
- **TestSuspiciousExtensionDetection** — OPEN/RENAME with `.locked`/`.crypto` extensions.
- **TestUnlinkDetection** — high-frequency deletion alerts and time-window expiry.
- **TestCombinedScenarios** — realistic multi-signal scenarios: gcc compilation (no alerts), rsync mass-delete (no alerts), full ransomware attack chain (multiple alerts).
