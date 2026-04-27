# Whitelist Stage 1 Review

This document reviews all 78 entries currently present in `DEFAULT_WHITELISTED_PROCESSES` and gives a reasoned keep-or-drop recommendation for a tightened broader-use whitelist.

The recommendations below assume the current detector shape:

- ordinary `OPEN` events are visible,
- broader child-write attribution is available,
- recursive scan plus writes can trigger `Directory traversal + Writes` even without high-entropy data,
- repeated high-entropy outputs can trigger `High entropy + Frequency` or `High file diversity + Entropy`,
- bulk source deletion can trigger `Write-then-delete` or `High unlink frequency`.

`Include` means the tool still looks like a realistic false-positive threat in ordinary benign use and aligns with the whitelist's purpose. `Exclude` does **not** mean the tool is suspicious; it means the tool is either unlikely to trigger the detector under current heuristics or is outside the intended scope of a tightened behavioral whitelist.

## Summary

- Recommended `Include`: `38`
- Recommended `Exclude`: `40`

## Version control and transport

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `git` | Cloning, fetching, checking out, and garbage-collecting repositories | Medium | Include | `git` can recursively materialize or rewrite many files and compressed pack objects, so broad project operations can resemble traversal-plus-write workflows. |
| `git-remote-htt` | Git transport helper for HTTP/HTTPS remotes | Low | Exclude | This helper mostly mediates network transport while `git` itself owns the interesting file writes, so blanket trust here is not doing much false-positive work. |
| `git-remote-ssh` | Git transport helper for SSH remotes | Low | Exclude | Like the HTTP helper, it is mainly a transport subprocess and is not itself a strong source of ransomware-like file I/O. |

## Package managers and dependency installers

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `apt` | Debian-family package installation and upgrades | Medium | Include | Package installs unpack and replace many files across directories, so a non-whitelisted `apt` run can look like recursive write-heavy workflow activity. |
| `apt-get` | Scriptable Debian-family package installation and upgrades | Medium | Include | It has the same recursive unpack-and-replace profile as `apt`, so it fits the whitelist's false-positive-reduction purpose. |
| `dpkg` | Low-level Debian package unpacking and file replacement | Medium | Include | `dpkg` writes and replaces many payload files directly, which is close to the detector's bulk file-operation patterns. |
| `dnf` | Fedora/RHEL package installation and upgrades | Medium | Include | Like other package managers, it drives large multi-directory file writes and cleanup that can resemble ransomware-like filesystem churn. |
| `yum` | Legacy RHEL/CentOS package installation and upgrades | Medium | Include | It sits in the same bulk package-deployment class as `dnf`, so removing trust would create avoidable noise in admin workflows. |
| `pacman` | Arch Linux package installation and upgrades | Medium | Include | Recursive package extraction and replacement are a plausible source of traversal-plus-write false positives. |
| `snap` | Snap application install/update/remove workflows | Medium | Include | Snap operations create and replace many files and metadata entries in one run, which aligns with the kinds of benign bulk I/O the whitelist should protect. |
| `flatpak` | Flatpak application/runtime installation and updates | Medium | Include | Flatpak expands and rewrites many runtime files across trees, making it a realistic benign traversal-and-write workload. |
| `pip` | Python package installation into system or user environments | Medium | Include | `pip` can unpack many files into site-packages and delete or replace older artifacts, so it is a reasonable false-positive threat under directory traversal plus writes. |
| `pip3` | Python 3 package installation into system or user environments | Medium | Include | It has the same install/unpack profile as `pip`, so the whitelist value is similar. |
| `npm` | Node.js dependency installation and updates | Medium | Include | `npm` can materialize huge dependency trees, so even low-entropy writes can still trigger the traversal-plus-writes side of the detector. |
| `yarn` | Node.js dependency installation and updates | Medium | Include | `yarn` has the same recursive dependency-tree write pattern as `npm`, so it aligns with the whitelist's purpose. |
| `cargo` | Rust dependency download, build orchestration, and install workflows | Medium | Include | `cargo` is both a package manager and a build orchestrator, so with broadened attribution it can inherit child build activity and become noisy if untrusted. |

## Build orchestration and compiler toolchain

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `make` | Build orchestration across many source and output files | Medium | Include | `make` can walk project trees and coordinate many child writes, so broadened attribution makes it a plausible parent-side false-positive target. |
| `cmake` | Build-system generation and configuration | Medium | Include | `cmake` scans project trees and rewrites build directories, which can trip directory-traversal-plus-write logic in large projects. |
| `ninja` | Fast build orchestration over many artifacts | Medium | Include | As a top-level build driver, `ninja` can accumulate broad child-write behavior in complex builds and fits the whitelist's orchestration rationale. |
| `gcc` | C compilation and linking | Low | Exclude | Direct `gcc` processes usually produce one artifact per invocation, and your own compile-burst testing showed the finer-grained heuristics already suppress that benign pattern. |
| `g++` | C++ compilation and linking | Low | Exclude | It shares `gcc`'s per-invocation artifact pattern, so it does not currently look like a strong standalone false-positive threat. |
| `cc1` | Internal GCC C compilation stage | Low | Exclude | This internal compiler phase is typically one-source-to-one-object and is too narrow to justify blanket trust on its own. |
| `cc1plus` | Internal GCC C++ compilation stage | Low | Exclude | Like `cc1`, it is a narrow internal stage rather than a common standalone benign workflow. |
| `as` | Assembler stage for object generation | Low | Exclude | The assembler typically writes one output object file and does not strongly match the detector's multi-file ransomware patterns. |
| `ld` | Linker stage for binaries and shared libraries | Low | Exclude | `ld` usually produces one linked artifact per invocation, so the current monitor is unlikely to mistake it for ransomware often enough to warrant blanket trust. |
| `clang` | C compilation and linking | Low | Exclude | It behaves similarly to `gcc` for the detector's purposes and is not a strong direct false-positive source under current thresholds. |
| `clang++` | C++ compilation and linking | Low | Exclude | As with `clang`, typical output patterns are too narrow to justify keeping it in a tightened whitelist. |
| `rustc` | Rust compilation | Low | Exclude | `rustc` generally emits one or a small number of artifacts per process and is less threatening than the top-level `cargo` orchestrator. |
| `javac` | Java source compilation | Low | Exclude | `javac` writes class files but usually in predictable low-entropy development patterns that do not strongly resemble ransomware. |

## Compression, encryption, and archiving tools

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `gzip` | File compression, often with source deletion | High | Include | `gzip` directly creates high-entropy outputs and can remove originals, which is extremely close to ransomware-like write-and-delete behavior. |
| `bzip2` | File compression, often with source deletion | High | Include | It shares the same high-entropy output and optional source-deletion profile as `gzip`, so the false-positive risk is real. |
| `xz` | File compression, often for archives and distributions | High | Include | `xz` produces high-entropy compressed outputs and can participate in bulk archival workflows that overlap with ransomware heuristics. |
| `zstd` | High-speed file compression | High | Include | `zstd` was experimentally necessary and is also a textbook high-entropy benign output producer. |
| `lz4` | Fast compression of files and data streams | High | Include | `lz4` writes opaque compressed outputs that the detector can easily confuse with ciphertext-like file writes. |
| `lzop` | Fast compression of files and data streams | High | Include | It has the same general high-entropy compressed-output risk profile as the other compression utilities. |
| `pigz` | Parallel `gzip` compression | High | Include | It is a bulk high-entropy compression tool, so removing trust would recreate the same benign compression problem as `gzip`. |
| `pbzip2` | Parallel `bzip2` compression | High | Include | Parallel compression still looks like repeated benign ciphertext-like output to the detector, so whitelist protection remains appropriate. |
| `pixz` | Parallel `xz` compression | High | Include | `pixz` is another direct high-entropy compression path and fits the whitelist's purpose well. |
| `gpg` | User-driven file encryption and decryption | High | Include | `gpg` is both a standard benign encryption tool and an experimentally confirmed false-positive source when removed. |
| `ccencrypt` | User-driven file encryption and decryption | High | Include | `ccencrypt` is also experimentally confirmed to be indispensable for suppressing benign direct-use false positives. |
| `tar` | Recursive archiving of directory trees | Medium | Include | `tar` can recursively traverse many directories while creating a large archive output, so it fits the traversal-plus-write risk model even if the simple control test stayed quiet. |

## File copy and synchronization tools

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `rsync` | Recursive synchronization and backup, often with deletes | High | Include | `rsync` is one of the clearest benign bulk-file workflows and can legitimately look like ransomware from the detector's point of view. |
| `rclone` | Recursive local/cloud synchronization and copy jobs | High | Include | `rclone` performs the same kind of multi-file, multi-directory synchronization work as `rsync`, making false positives plausible without trust. |
| `cp` | Direct file copies, including recursive `cp -r` | Medium | Include | Recursive copies over media, archives, and binaries can mimic traversal-plus-write behavior closely enough that `cp` belongs in a broader operational whitelist. |
| `dd` | Disk imaging, file imaging, zeroing, and random-data generation | Medium | Include | `dd` can generate or copy opaque data at high write rates, and your own legacy case showed that it can fall directly into ransomware-like write heuristics. |
| `cat` | Concatenating or copying streams/files | Low | Exclude | `cat` usually writes one output stream or file and does not naturally create the multi-file patterns the detector cares about. |
| `head` | Truncating or sampling file input to output | Low | Exclude | `head` is typically a one-output utility with little resemblance to ransomware-like bulk file modification. |
| `sort` | Sorting text streams/files, often using temp files | Low | Exclude | `sort` primarily handles low-entropy text and is not a strong match for the detector's ransomware-oriented heuristics. |
| `shuf` | Randomly reordering text lines or records | Low | Exclude | `shuf` has little direct overlap with the detector's high-entropy or recursive modification signals. |

## Media and image processing tools

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `ffmpeg` | Audio/video transcoding and remuxing | Low | Exclude | In practice it usually writes one output file per process, and your benign transcode case already stayed quiet without needing whitelist help. |
| `avconv` | Audio/video transcoding and remuxing | Low | Exclude | It is in the same one-output-per-process class as `ffmpeg`, so the current heuristics are unlikely to overfire on it often enough to justify trust. |
| `ffprobe` | Media metadata inspection | Low | Exclude | `ffprobe` is primarily read-only and is not a credible false-positive threat under the current file-write-heavy detector. |
| `sox` | Audio processing and format conversion | Low | Exclude | `sox` normally produces one transformed output at a time and does not strongly resemble ransomware-like bulk file destruction. |
| `x264` | Video encoding | Low | Exclude | It typically writes one encoded stream/output file per process, which is too narrow for the detector's multi-file behavioral paths. |
| `x265` | Video encoding | Low | Exclude | Like `x264`, it is a focused encoder rather than a recursive multi-file workflow. |
| `vpxenc` | VP8/VP9 video encoding | Low | Exclude | `vpxenc` usually emits a single encoded output and is not a strong false-positive source under current heuristics. |
| `HandBrakeCLI` | Command-line video transcoding | Low | Exclude | Typical use is one media output per run, which does not align well with the detector's multi-file ransomware model. |
| `handbrake` | GUI/video-transcoding backend use | Low | Exclude | Its file I/O is closer to one-off media conversion than to recursive ransomware-like modification. |
| `convert` | Single-shot image conversion via ImageMagick | Low | Exclude | `convert` generally reads one image and writes one derived image, which is too narrow to justify blanket trust. |
| `mogrify` | Batch in-place image rewriting/resizing | Medium | Include | `mogrify` can overwrite many existing image files in place, making it one of the rare legitimate tools that genuinely overlaps with overwrite-style ransomware heuristics. |

## Editors and IDEs

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `vim` | Terminal text editing with temp/swap files | Low | Exclude | `vim` mostly edits one file at a time with low-entropy content, so it no longer aligns strongly with the monitor's bulk-ransomware patterns. |
| `nvim` | Terminal text editing with temp/swap files | Low | Exclude | `nvim` has the same one-file, low-entropy editing profile as `vim`, making blanket trust harder to justify. |
| `nano` | Terminal text editing | Low | Exclude | `nano` writes simple low-entropy edits and is unlikely to trigger the current heuristics often enough to need whitelist protection. |
| `emacs` | Text editing, project editing, and Lisp tooling | Low | Exclude | Although `emacs` can do complex workflows, its direct file-write pattern is usually still low-entropy and not especially ransomware-like. |
| `code` | IDE/editor, extension installs, workspace tooling | Low | Exclude | The broad whitelist originally protected VS Code for temp-file churn, but the current detector's finer-grained rules make that rationale much weaker. |
| `codium` | IDE/editor, extension installs, workspace tooling | Low | Exclude | `codium` shares `code`'s profile, and under the current heuristics it no longer looks like a strong direct false-positive threat. |

## System services, schedulers, and maintenance helpers

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `systemd` | Service manager and system bootstrap | Low | Exclude | `systemd` is important operationally, but its own file I/O pattern is not a good match for the whitelist's “ransomware-like benign tool” purpose. |
| `systemd-journa` | Truncated comm for `systemd-journald` | Low | Exclude | Journal writing is specialized service behavior and better treated as service policy than as part of a tightened behavioral-tool whitelist. |
| `journald` | System log collection and journal writing | Low | Exclude | Like `systemd-journald`, it mainly manages logging state rather than acting like a user-initiated ransomware-adjacent tool. |
| `dbus-daemon` | System/user message bus service | Low | Exclude | It is not a meaningful source of ransomware-like file operations in ordinary benign use. |
| `sshd` | Remote login daemon | Low | Exclude | `sshd` is mostly connection/session handling rather than bulk file modification, so it does not fit the whitelist's purpose well. |
| `cron` | Scheduled job launcher | Low | Exclude | `cron` itself is mostly an orchestrator of external jobs and is not a strong direct file-I/O false-positive source. |
| `anacron` | Catch-up scheduled job launcher | Low | Exclude | Like `cron`, it mostly starts other programs and does not itself warrant blanket trust in a tightened behavioral whitelist. |
| `logrotate` | Rotating, renaming, compressing, and pruning log files | Medium | Include | `logrotate` legitimately renames, compresses, and deletes multiple files in one run, which overlaps directly with the detector's destructive file-operation signals. |

## Datastores and databases

| Entry | Standard benign use-case | FP risk if removed | Recommendation | Rationale |
|---|---|---|---|---|
| `postgres` | PostgreSQL database engine with data files and WAL segments | Medium | Include | PostgreSQL writes opaque page and WAL data across multiple files, so heavy checkpoints or maintenance can look like benign high-entropy storage churn. |
| `mysqld` | MySQL/MariaDB database engine | Medium | Include | `mysqld` maintains binary tablespaces, redo logs, and temp files, which makes it a plausible false-positive target under broad file-write heuristics. |
| `mongod` | MongoDB document store engine | Medium | Include | `mongod` writes journals, data files, and compaction outputs that can look like bulk opaque file activity rather than ordinary user-document editing. |
| `redis-server` | Redis in-memory store with AOF/RDB persistence | Low | Exclude | Redis persistence is usually concentrated in one or a few files, so it is less aligned with the detector's multi-file ransomware patterns than the other database engines. |
