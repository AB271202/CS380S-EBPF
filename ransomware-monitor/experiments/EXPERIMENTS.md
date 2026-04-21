# Experiments

## 1. Overview

The evaluation uses four complementary suites that probe the detector at different levels of abstraction: a hand-built legacy control suite, an Atomic Red Team T1486 suite, a benign stress suite derived from Phoronix-style workloads, and a behavioral ransomware suite whose process behaviors are inspired by documented Linux ransomware families. The point is not that any single suite is definitive. The value comes from the pattern across suites: the legacy cases show whether isolated heuristics still fire, the Atomic cases show what happens on tool-level ATT&CK emulations, the benign suite measures false positives on realistic legitimate workloads, and the behavioral suite tests whether a non-whitelisted process that looks like ransomware in its file-system behavior is actually caught.

## 2. The Detector's Two Layers

The detector has two conceptually separate layers. Layer 1 is a process trust layer: known tools are exempted by name, then optionally hardened by process lineage and binary-hash checks. In the current checked-in detector, that whitelist clearly includes many common utilities such as `gcc`, `gzip`, `zstd`, `ffmpeg`, `dd`, `tar`, `rsync`, and `gpg`. Layer 2 is the behavioral layer that applies to processes that are not trusted after that gate. It includes suspicious extension matching, suspicious rename detection, entropy plus write frequency, file diversity plus entropy across directories, directory traversal plus writes, write-then-delete correlation, high unlink frequency, magic-bytes destruction, in-place overwrite detection, and process-tree attribution of trusted child writes back to a non-whitelisted parent.

Feature wiring matters when interpreting the numbers. In the current branch, suspicious extension, suspicious rename, entropy plus frequency, file diversity plus entropy, directory traversal plus writes, write-then-delete, high unlink frequency, magic-bytes destruction, in-place overwrite, process lineage, canary-file detection, and process-tree attribution are all wired end to end. The BPF layer now emits ordinary open events as well as creations, so overwrite-oriented heuristics can observe pre-existing files opened in place rather than relying only on `O_CREAT` paths. `main.py` also now passes canary directories and whitelist configuration into the detector, so canaries, configured trusted hashes, and custom trust policy are available in ordinary runs when the operator supplies those inputs. The remaining caveat for binary-hash verification is policy rather than plumbing: the mechanism is active, but it only constrains processes that have trusted digests configured in the whitelist JSON.

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
| `pos_atomic_t1486_gpg_official` | positive | `gpg` | Encrypts a file with AES-256 via GnuPG | Tool-level detection of `gpg` encryption | FN under the current trust policy |
| `pos_atomic_t1486_7z_official` | positive | `7z` | Creates a password-protected archive | Tool-level detection of `7z` encryption | FN under the current trust policy |
| `pos_atomic_t1486_ccrypt_official` | positive | `ccencrypt` | Encrypts a file in place | Tool-level detection of `ccencrypt` encryption | FN under the current trust policy |
| `pos_atomic_t1486_openssl_official` | positive | `openssl` | Encrypts a file with OpenSSL | Tool-level detection of `openssl` encryption | FN under the current trust policy |

In the measured tuned run, the Atomic suite produced `TP=0`, `FN=12` across 12 runs. Under the current trust policy, that all-miss outcome is intentional rather than accidental: single invocations of trusted encryption or archival tools are no longer treated as a detection target. This makes the suite useful as a boundary marker instead of a score booster. The detector is not trying to infer malicious intent from one trusted tool touching one file; it is trying to recognize untrusted processes that behave like ransomware across many files and directories. The cost of that policy is zero tool-level Atomic recall. The benefit is a much cleaner benign suite and a much sharper separation between trusted utility use and behavioral ransomware detection.

### Suite C: Benign Stress Suite

Purpose: The benign stress suite in `scenarios_benign_stress.csv` measures false positives under realistic legitimate workloads that were chosen precisely because they should challenge a ransomware detector. Every scenario is negative by design. Any alert here is a false positive.

| Scenario ID | Label | Tool/Process | What It Does | What It Tests | Expected Outcome |
|---|---|---|---|---|---|
| `neg_7z_compress` | negative | `7z` | Compresses a 50MB random file | Benign use of a ransomware-adjacent archive tool | No alert |
| `neg_zstd_compress` | negative | `zstd` | Compresses a 50MB file at high level | High-entropy output from benign compression | No alert |
| `neg_gzip_compress` | negative | `gzip` | Compresses a 50MB file with `-9` | High-entropy output from benign compression | No alert |
| `neg_gpg_encrypt_benign` | negative | `gpg` | Encrypts a single file with AES-256 symmetric | Benign use of a tool also seen in the Atomic suite | No alert |
| `neg_openssl_encrypt_benign` | negative | `openssl` | Encrypts a single file with AES-256-CBC | Benign file encryption | No alert |
| `neg_ccencrypt_encrypt_benign` | negative | `ccencrypt` | Encrypts a single file with `ccencrypt` | Benign file encryption | No alert |
| `neg_ffmpeg_transcode` | negative | `ffmpeg` | Transcodes a synthetic video | Sustained media writes | No alert |
| `neg_gcc_compile_burst` | negative | `gcc` | Compiles 30 small C files | Many object-file writes | No alert |

In the measured tuned run, the benign suite produced `FP=0`, `TN=24`. This is the cleanest false-positive result the project has produced so far: all eight benign workload families stayed quiet across all three repeats. That quiet result is the mirror image of the Atomic suite. Once common encryption and archival tools are trusted as legitimate user utilities, the detector stops trying to distinguish benign from malicious one-file uses of those tools at the tool level. Instead, the burden of recall shifts to the behavioral suite, where the detector looks for ransomware-like kill chains from processes that are not trusted by name.

### Suite D: Behavioral Ransomware Simulation Suite

Purpose: The behavioral suite in `scenarios_behavioral.csv` is the first suite that makes a non-whitelisted process look like a ransomware family at the file-system level. Each scenario is a single Python process that sets its kernel task name with `prctl(PR_SET_NAME)` so it appears to the eBPF layer as an unknown comm. This suite is the clearest test of whether Layer 2 works when the process identity is no longer carrying the result.

| Scenario ID | Label | Simulated Family | What It Does | Heuristics Exercised | Expected Outcome |
|---|---|---|---|---|---|
| `pos_ransim_walk` | positive | RansomEXX-inspired | Creates 4 directories × 5 files, walks the tree, writes random data to `<file>.encrypted` | File diversity + entropy, Directory traversal + writes | TP |
| `pos_ransim_del` | positive | HelloKitty-inspired | Writes encrypted copies and deletes originals | Write-then-delete, File diversity + entropy | TP |
| `pos_ransim_rename` | positive | Cl0p-inspired | Overwrites file contents, renames to `.cl0p` | Suspicious rename, Entropy + frequency, File diversity | TP |
| `pos_ransim_slow` | positive | Evasion probe | Same as walk, but sleeps between files | Sliding-window sensitivity | TP |
| `pos_ransim_delegate` | positive | Delegated | Parent creates the corpus, waits for setup writes to age out, then walks files while spawning a fresh `ccencrypt` child per file | Process-tree attribution of trusted child writes | TP |
| `pos_ransim_inplace` | positive | RansomEXX high-fidelity variant | Walks realistic user directories and overwrites existing files in place with high-entropy data, appending extra key-like bytes | Cosmetic-signal-free detection of in-place overwrite behavior | TP |
| `pos_ransim_inplace_del` | positive | Wiper high-fidelity variant | Overwrites each existing file in place with high-entropy data, then deletes it | In-place overwrite plus destructive deletion | TP |
| `pos_ransim_inplace_slow` | positive | Evasion high-fidelity variant | Same as in-place overwrite, but throttled with sleeps between files | Sliding-window robustness without renames or new output files | TP |

In the measured tuned run after the high-fidelity additions, the behavioral suite produced `TP=24`, `FN=0` across all eight scenarios and all 24 runs. The delegated scenario is part of that clean sweep: `TP=3/3`, no workload timeouts, and matching alerts belong to `ransim_dlg`. The delegated case remains a useful architectural probe without changing the basic ransomware story: the parent still creates the corpus and later walks it, but it pauses briefly so those setup writes age out of the detector’s sliding window, then delegates each file to a separate `ccencrypt` child. The key difference is process-tree attribution. The detector now captures the child's parent PID in-kernel at syscall time and uses that to attribute each trusted child write back to the nearest non-whitelisted ancestor with an active behavioral profile. In the delegate logs, that means `ccencrypt` itself stays quiet while `ransim_dlg` accumulates attributed `High entropy + Frequency` and `High file diversity + Entropy` alerts.

The new high-fidelity variants answer a stricter question: would the detector still fire if the attacker removed cosmetic signals such as renamed outputs, suspicious extensions, or ransom-note-like artifacts and simply traversed directories while destroying file contents in place? In the current run, the answer is yes. All three higher-fidelity variants remained `TP=3/3`, which is stronger evidence that the detector is responding to the underlying overwrite behavior rather than to cosmetic clues. Because the BPF layer now emits ordinary open events as well as creations, overwrite-oriented heuristics can observe the later in-place pass directly instead of depending on renamed outputs or freshly created ciphertext files.

## 4. Cross-Suite Analysis

The clearest cross-suite pattern in the current measured results is the gap between tool-level and workflow-level evaluation. Under the current trust policy, the Atomic and benign suites now separate cleanly: trusted one-file encryption and archival workloads are suppressed in both cases, so the Atomic suite becomes an all-miss tool-level boundary while the benign suite becomes an all-quiet false-positive check. The behavioral suite, in contrast, shows that the detector is much more decisive when it sees a process exhibit a fuller ransomware-style file-system kill chain.

The combined tuned run now makes the whitelist tradeoff easier to quantify. Overall the detector finished with `TP=27`, `FP=0`, `FN=18`, `TN=36`, which corresponds to `precision=1.000`, `recall=0.600`, `specificity=1.000`, and `balanced_accuracy=0.800`. That is a much cleaner operating point than the earlier branch state: the false positives are gone entirely, but the cost is explicit in recall. The Atomic suite contributes no true positives at all, and the legacy suite still misses `dd`-style overwrites and rename timing cases. The behavioral suite is the recovery path for that tradeoff. Instead of trying to classify every invocation of a trusted tool, it asks whether an unknown process behaves like a ransomware binary, and under the tuned settings it recovered `24/24` true positives.

The delegated-encryption case now shows what parent-child correlation buys the detector. The detector captures the parent PID in-kernel at syscall time via `bpf_get_current_task()->real_parent->tgid`, so a short-lived helper can still be linked back to the orchestrator even if the child has already exited by the time user space handles the perf-buffer event. When a trusted child process performs a high-entropy write, the detector attributes that write to the nearest non-whitelisted ancestor with an active behavioral profile instead of alerting on the child. In the validated full tuned run, that produces attributed `ransim_dlg` alerts and flips the scenario from false negative to true positive without making the `ccencrypt` child itself noisy.

The remaining boundary is narrower but still real. Attribution only activates when the ancestor already has an active behavioral profile, and the walk is intentionally shallow. A pure launcher that does nothing but spawn helper children and never emits its own traversal, open, write, or unlink context could still evade this mechanism. The other deliberate boundary is policy-level: once common encryption and archival tools are trusted, one-file ATT&CK-style tool invocations are expected misses. Those are much smaller blind spots than the original per-PID model, but they are still the next architectural boundaries if workflow-level attacks become a design priority.

## 5. Remaining Boundaries

The earlier constructor-wiring and open-event visibility gaps are closed in this branch. What remains are design boundaries rather than missing plumbing:

- **Trusted one-file tool invocations are intentionally missed**: under the current trust policy, single invocations of trusted tools such as `gpg`, `7z`, `ccencrypt`, and `openssl` are not treated as positive detections. Catching those cases would require weakening the whitelist or adding richer context than one trusted PID touching one file.
- **Process-tree attribution still requires an active ancestor profile**: attribution only activates when the nearest non-whitelisted ancestor has already built up some behavioral state. A pure launcher that does nothing but spawn helper children and otherwise stays behaviorally quiet can still evade.
- **Metadata-only denial tactics are outside the current event model**: the current BPF path observes open, write, rename, unlink, and directory-scan activity. Tactics based primarily on ownership or permission changes would require additional hooks and a broader behavior model.
