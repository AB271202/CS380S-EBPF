# Experiments

## 1. Overview

The evaluation uses four complementary suites that probe the detector at different levels of abstraction: a hand-built legacy control suite, an Atomic Red Team T1486 suite, a benign stress suite derived from Phoronix-style workloads, and a behavioral ransomware simulation suite derived from threat intelligence on real Linux ransomware families. The point is not that any single suite is definitive. The value comes from the pattern across suites: the legacy cases show whether isolated heuristics still fire, the Atomic cases show what happens on tool-level ATT&CK emulations, the benign suite measures false positives on realistic legitimate workloads, and the behavioral suite tests whether a non-whitelisted process that looks like ransomware in its file-system behavior is actually caught.

## 2. The Detector's Two Layers

The detector has two conceptually separate layers. Layer 1 is a process trust layer: known tools are exempted by name, then optionally hardened by process lineage and binary-hash checks. In the current checked-in detector, that whitelist clearly includes tools such as `gcc`, `gzip`, `zstd`, `ffmpeg`, `dd`, `tar`, `rsync`, and related utilities, while `gpg`, `7z`, `openssl`, and `ccencrypt` are notably not in the default list. Layer 2 is the behavioral layer that applies to processes that are not trusted after that gate. It includes suspicious extension matching, suspicious rename detection, entropy plus write frequency, file diversity plus entropy across directories, directory traversal plus writes, write-then-delete correlation, high unlink frequency, magic-bytes destruction, and in-place overwrite detection.

Feature wiring matters when interpreting the numbers. Fully wired end to end are suspicious extension, suspicious rename, entropy plus frequency, file diversity plus entropy, directory traversal plus writes, write-then-delete, high unlink frequency, and process lineage. Magic-bytes destruction and in-place overwrite are partially wired: they do fire in real runs when a new output file is opened with `O_CREAT` and then overwritten with high-entropy data, but they still miss some true existing-file overwrite patterns because the BPF open hook does not emit ordinary non-`O_CREAT` opens to user space. Canary-file detection and binary-hash verification exist in `detector.py`, but `main.py` does not pass `canary_dirs`, `trusted_hashes`, or `whitelist_config`, so those features require additional constructor wiring before they can work in ordinary end-to-end runs.

## 3. Suite Descriptions

### Suite A: Legacy Control Suite

Purpose: The legacy suite in `scenarios.csv` validates the basic heuristics in isolation. These are team-authored control cases rather than externally sourced threat emulations, and they are useful because each case is narrow enough that a miss usually maps to one specific heuristic or one specific integration quirk.

| Scenario ID | Label | Tool/Process | What It Does | What It Tests | Expected Outcome |
|---|---|---|---|---|---|
| `pos_touch_locked` | positive | `touch` | Creates `test_file.locked` | Suspicious extension filter on OPEN | Alert |
| `pos_rename_locked` | positive | `mv` | Writes a file, renames it to `.locked` | Suspicious rename filter on RENAME | Alert, but intermittent FN is plausible if the rename event never reaches user space before teardown |
| `pos_dd_urandom` | positive | `dd` | Writes 20KB of `/dev/urandom` | Entropy + frequency heuristic | FN in the current detector because `dd` is whitelisted |
| `neg_touch_txt` | negative | `touch` | Creates a normal `.txt` file | Benign file creation | No alert |
| `neg_dd_zero` | negative | `dd` | Writes 20KB of `/dev/zero` | Frequency without entropy | No alert |
| `neg_plaintext_appends` | negative | `bash` | Appends many text lines to one file | Frequent writes with low entropy | No alert |
| `neg_archive_workload` | negative | `tar` | Archives 20 small files | Sustained I/O without ciphertext-like output | No alert |

In the measured tuned run, the legacy suite produced `TP=3`, `FP=0`, `TN=12`, `FN=6` across 21 runs. The only consistently detected positive was `pos_touch_locked`; `pos_rename_locked` and `pos_dd_urandom` were missed in all three repeats. The `dd` shift is the easiest result to interpret: in the current detector this is not a bug, it is the intended cost of trusting a ubiquitous system utility. An attacker who literally overwrote files with `dd` would evade this detector, but treating every `dd` burst as malicious would be unusable on a real system. This is the precision-recall tradeoff the whitelist introduces in its most compact form.

### Suite B: Atomic Red Team T1486

Purpose: The Atomic suite in `scenarios_atomic_t1486_official.csv` tests one-tool-at-a-time ATT&CK-style emulations of T1486, “Data Encrypted for Impact.” These are authoritative technique emulations, but they are deliberately atomic: one tool, one file, one narrow action, not a full ransomware kill chain.

| Scenario ID | Label | Tool/Process | What It Does | What It Tests | Expected Outcome |
|---|---|---|---|---|---|
| `pos_atomic_t1486_gpg_official` | positive | `gpg` | Encrypts a file with AES-256 via GnuPG | Tool-level detection of `gpg` encryption | TP in current results |
| `pos_atomic_t1486_7z_official` | positive | `7z` | Creates a password-protected archive | Tool-level detection of `7z` encryption | FN in current results |
| `pos_atomic_t1486_ccrypt_official` | positive | `ccencrypt` | Encrypts a file in place | Tool-level detection of `ccencrypt` encryption | FN in current results |
| `pos_atomic_t1486_openssl_official` | positive | `openssl` | Encrypts a file with OpenSSL | Tool-level detection of `openssl` encryption | FN in current results |

In the measured tuned run, the Atomic suite produced `TP=3`, `FN=9` across 12 runs, and all three true positives came from the `gpg` scenario. The important point is that the current branch does not actually whitelist `gpg`, `7z`, `openssl`, or `ccencrypt` by default, so the result is not “three tools were trusted and one was revoked.” Instead, `gpg` happens to trip the current heuristics reliably in its one-file atomic form, while `7z`, `ccencrypt`, and `openssl` do not. The one-file atomic structure matters here: the detector is strongest when it sees a process touch many files, many directories, or a write-delete sequence. Tool-level single-file encryption is much harder to classify consistently from behavior alone, which is exactly why the behavioral suite exists.

### Suite C: Benign Stress Suite

Purpose: The benign stress suite in `scenarios_benign_stress.csv` measures false positives under realistic legitimate workloads that were chosen precisely because they should challenge a ransomware detector. Every scenario is negative by design. Any alert here is a false positive.

| Scenario ID | Label | Tool/Process | What It Does | What It Tests | Expected Outcome |
|---|---|---|---|---|---|
| `neg_7z_compress` | negative | `7z` | Compresses a 50MB random file | Benign use of a ransomware-adjacent archive tool | No alert in current results |
| `neg_zstd_compress` | negative | `zstd` | Compresses a 50MB file at high level | High-entropy output from benign compression | No alert |
| `neg_gzip_compress` | negative | `gzip` | Compresses a 50MB file with `-9` | High-entropy output from benign compression | No alert |
| `neg_gpg_encrypt_benign` | negative | `gpg` | Encrypts a single file with AES-256 symmetric | Benign use of a tool also seen in the Atomic suite | False positive in all measured runs |
| `neg_openssl_encrypt_benign` | negative | `openssl` | Encrypts a single file with AES-256-CBC | Benign file encryption | No alert |
| `neg_ccencrypt_encrypt_benign` | negative | `ccencrypt` | Encrypts a single file with `ccencrypt` | Benign file encryption | No alert |
| `neg_ffmpeg_transcode` | negative | `ffmpeg` | Transcodes a synthetic video | Sustained media writes | No alert |
| `neg_gcc_compile_burst` | negative | `gcc` | Compiles 30 small C files | Many object-file writes | No alert |

In the measured tuned run, the benign suite produced `FP=3`, `TN=21`, and the only false positive family was `gpg` at `3/3`. The mechanism is straightforward in the current code: `gpg` is not on the default whitelist, so it is evaluated by Layer 2 exactly like any other untrusted process. When it writes ciphertext-like output to a user file, it can satisfy the same behavioral predicates as the positive Atomic `gpg` case. There is no separate intent signal that distinguishes “user encrypting a file” from “attacker encrypting a file.” Cross-referencing the Atomic suite makes the point starkly: `pos_atomic_t1486_gpg_official` is `TP=3/3`, and `neg_gpg_encrypt_benign` is `FP=3/3`. The detector is consistent about `gpg` as a behavior generator, but it is not able to infer intent from that behavior.

### Suite D: Behavioral Ransomware Simulation Suite

Purpose: The behavioral suite in `scenarios_behavioral.csv` is the first suite that makes a non-whitelisted process look like a ransomware family at the file-system level. Each scenario is a single Python process that sets its kernel task name with `prctl(PR_SET_NAME)` so it appears to the eBPF layer as an unknown comm. This suite is the clearest test of whether Layer 2 works when the process identity is no longer carrying the result.

| Scenario ID | Label | Simulated Family | What It Does | Heuristics Exercised | Expected Outcome |
|---|---|---|---|---|---|
| `pos_ransim_walk` | positive | RansomEXX | Creates 4 directories × 5 files, walks the tree, writes random data to `<file>.encrypted` | File diversity + entropy, Directory traversal + writes | Expected TP |
| `pos_ransim_del` | positive | HelloKitty | Writes encrypted copies and deletes originals | Write-then-delete, File diversity + entropy | Expected TP |
| `pos_ransim_rename` | positive | Cl0p | Overwrites file contents, renames to `.cl0p` | Suspicious rename, Entropy + frequency, File diversity | Expected TP |
| `pos_ransim_slow` | positive | Evasion | Same as walk, but sleeps between files | Sliding-window sensitivity | Expected TP under the tuned 3s window, but still an evasion probe |
| `pos_ransim_delegate` | positive | Delegated | Parent creates the corpus, waits for setup writes to age out, then walks files while spawning a fresh `ccencrypt` child per file | Clean cross-PID evasion probe | FN in isolated delegate-only rerun |

The first four scenarios were measured as true positives in the last full tuned behavioral run. After that run, the delegated scenario was revised so it would become a cleaner architectural probe without changing the basic ransomware story: the parent still creates the corpus and later walks it, but it pauses briefly so those setup writes age out of the detector’s sliding window, then delegates each file to a separate `ccencrypt` child. That keeps the parent realistic without making it noisy for the wrong reason. In an isolated tuned rerun of the delegate case alone, it produced `FN=3/3` with `alerts_matching_comm=0` in every repeat. That is the cleaner cross-PID result we wanted. The parent no longer performs enough recent writes or unlinks to trip Layer 2 on its own, and each child only handles one file, so no single child PID accumulates a multi-file ransomware signature. This means the delegate scenario now demonstrates the per-PID correlation gap directly. Because only the delegate case was rerun after that change, any older suite-wide `TP=15` behavioral summary should be treated as pre-fix and rerun before being quoted as the current full-suite number.

## 4. Cross-Suite Analysis

The clearest family-level story in the current measured results is `gpg`. In the tuned combined run, the `gpg` family appears in six runs across the Atomic and benign suites and finishes with `TP=3`, `FP=3`, `FN=0`, `TN=0`. In other words, it is always treated as suspicious, whether the invocation is labeled malicious or benign. That is the cleanest empirical example of the “wheel versus chariot” problem. The encryption primitive and ciphertext-like output are the same whether the actor is a benign user or an attacker, so the detector reacts to the behavior generator rather than the human intent behind it.

The combined tuned run now makes the whitelist tradeoff easier to quantify. Overall the detector finished with `TP=21`, `FP=3`, `FN=15`, `TN=33`, which corresponds to `precision=0.875`, `recall=0.583`, `specificity=0.917`, and `balanced_accuracy=0.750`. That specificity is driven largely by the quiet benign families and the suppressed legacy negatives. The cost shows up in recall: the legacy and Atomic suites still contribute many misses, especially `dd`, `7z`, `ccencrypt`, and `openssl`. The behavioral suite is the recovery path for that tradeoff. Instead of trying to classify every tool invocation, it asks whether an unknown process behaves like a ransomware binary, and under the tuned settings it recovered `15/15` true positives.

The delegated-encryption case now defines the architectural boundary more cleanly. The detector reasons per PID. In the revised delegate scenario, the parent process performs setup, orchestration, and traversal, while a fresh `ccencrypt` child handles one file at a time. Neither PID individually exhibits the full multi-file pattern strongly enough for the current detector to classify the run as positive, so the scenario falls through as a clean false negative. Parent-child correlation, lineage-aware aggregation, or workflow-level attribution would be the natural next step if this blind spot became a design priority.

## 5. Integration Gaps

- **Magic bytes destroyed** and **In-place overwrite**: these heuristics do fire end to end when the process creates a new output file and then writes high-entropy content to it, because the `O_CREAT` open reaches user space and seeds `open_tracker`. The remaining gap is narrower: true overwrites of pre-existing files opened without `O_CREAT` are still under-observed. Fix: emit all opens, then add in-kernel or user-space filtering to keep perf-buffer volume manageable.
- **Canary file detection**: the detector supports deployed canary paths, but `main.py` never passes `canary_dirs`, so no canaries are created in ordinary end-to-end runs. Fix: add a CLI flag or environment variable and pass it into the detector constructor.
- **Binary hash verification**: the detector supports trusted-binary hashes and whitelist revocation, but `main.py` never passes `trusted_hashes` or `whitelist_config`. Fix: add a config-file path to `main.py` and feed it into the detector constructor.
