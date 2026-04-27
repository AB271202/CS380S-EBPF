# Whitelist

This document records the built-in whitelist for the detector in
[detector.py](../agent/detector.py).

This default whitelist is intended for ordinary use of the detector. A separate
experiment-context minimal policy is documented in
[WHITELIST_ABLATION.md](WHITELIST_ABLATION.md).

The whitelist below is aligned with the detector's behavior:

- traversal now arms suspicion instead of alerting directly,
- generic launchers such as `bash` and `python3` no longer inherit child writes loosely,
- slow-burn ransomware alerts now require entropy-backed anchors.

The remaining whitelist entries are the tools that still have a strong, direct
overlap with the detector's surviving ransomware-oriented heuristics.

## Summary

- Default whitelist size: `32`

## Version control

| Entry | Standard benign use-case | Why keep it whitelisted |
|---|---|---|
| `git` | Cloning, checkout, reset, clean, and garbage collection in repositories | `git` legitimately materializes, rewrites, and deletes many files and packed objects in one workflow, so it can still resemble destructive bulk file activity. |

## Package managers and dependency installers

| Entry | Standard benign use-case | Why keep it whitelisted |
|---|---|---|
| `apt` | Debian-family package installation and upgrades | Package installation replaces and prunes many payload files quickly, which still overlaps with delete-heavy ransomware signals. |
| `apt-get` | Scriptable Debian-family package installation and upgrades | It has the same broad unpack-and-replace behavior as `apt`, so the same false-positive argument applies. |
| `dpkg` | Low-level Debian package unpacking and replacement | `dpkg` directly owns payload replacement and cleanup, keeping it close to the detector's destructive file-operation paths. |
| `dnf` | Fedora/RHEL package installation and upgrades | `dnf` performs broad file replacement and cleanup across many paths, which remains operationally close to destructive multi-file behavior. |
| `yum` | Legacy RHEL/CentOS package installation and upgrades | `yum` stays in the same bulk replace-and-prune class as `dnf`, so it still fits the whitelist's purpose. |
| `pacman` | Arch Linux package installation and upgrades | `pacman` can rapidly replace many files and metadata entries, which is still a plausible benign source of delete-heavy alerts. |
| `snap` | Snap application install, update, and removal | Snap lifecycle operations create, replace, and remove many real files in a tight window, which overlaps with the detector's destructive side. |
| `flatpak` | Flatpak runtime and application install/update | Flatpak expands and replaces large runtime trees, so its benign filesystem churn is still substantial enough to justify trust. |
| `pip` | Python package installation into system or user environments | `pip` can remove and rewrite many package artifacts during upgrades, which remains close to multi-file destructive behavior. |
| `pip3` | Python 3 package installation into system or user environments | It shares `pip`'s replace-and-prune profile, so the same whitelist rationale applies. |
| `npm` | Node.js dependency installation and updates | `npm` can materialize and replace huge dependency trees, so it remains a realistic benign bulk-write source. |
| `yarn` | Node.js dependency installation and updates | `yarn` has the same large dependency-tree replacement pattern as `npm`, making false positives plausible without trust. |

## Compression and encryption

| Entry | Standard benign use-case | Why keep it whitelisted |
|---|---|---|
| `gzip` | File compression, often with source deletion | `gzip` directly emits opaque outputs and may delete originals, which is a textbook benign overlap with ransomware-like write-and-delete behavior. |
| `bzip2` | File compression, often with source deletion | It remains in the same compressed-output plus optional-delete class as `gzip`. |
| `xz` | File compression and archival packaging | `xz` produces high-entropy outputs that still look ciphertext-like to the detector's direct write heuristics. |
| `zstd` | High-speed file compression | `zstd` was experimentally necessary and is also a direct high-entropy benign output producer. |
| `lz4` | Fast compression of files and streams | `lz4` writes opaque compressed outputs that remain easy to confuse with ciphertext-like writes. |
| `lzop` | Fast compression of files and streams | It shares the same direct compressed-output risk class as the other high-entropy compression utilities. |
| `pigz` | Parallel `gzip` compression | Parallel compression does not become less detector-confusing, so `pigz` still aligns with the whitelist's purpose. |
| `pbzip2` | Parallel `bzip2` compression | It keeps the same direct opaque-output and optional-delete profile as `bzip2`. |
| `pixz` | Parallel `xz` compression | `pixz` remains a direct producer of opaque high-entropy outputs and belongs in the same whitelist class as `xz`. |
| `gpg` | User-driven file encryption and decryption | `gpg` is both experimentally necessary and conceptually aligned with the whitelist's purpose as a standard benign encryption tool. |
| `ccencrypt` | User-driven file encryption and decryption | `ccencrypt` still overlaps directly with the entropy-based write heuristics, and experiments showed its benign direct-use case cannot be ignored safely. |
| `openssl` | User-driven file encryption, decryption, and key operations | `openssl` is a standard benign encryption tool whose direct file-encryption workflows produced false positives when left untrusted. |

## Synchronization and overwrite-capable tools

| Entry | Standard benign use-case | Why keep it whitelisted |
|---|---|---|
| `rsync` | Recursive synchronization and backup, often with deletes | `rsync` combines broad file writes with legitimate bulk deletion semantics, which remains very close to destructive workflow heuristics. |
| `rclone` | Recursive local/cloud synchronization and copy jobs | `rclone` shares `rsync`'s multi-file synchronization and delete-capable profile, so the same whitelist logic applies. |
| `mogrify` | Batch in-place image rewriting/resizing | `mogrify` legitimately overwrites many existing files in place, which is one of the clearest benign overlaps with overwrite-style ransomware signals. |
| `logrotate` | Rotating, renaming, compressing, and pruning log files | `logrotate` directly overlaps with rename, compression, and delete-heavy workflows that the detector otherwise treats as destructive. |

## Databases and datastores

| Entry | Standard benign use-case | Why keep it whitelisted |
|---|---|---|
| `postgres` | PostgreSQL data files and WAL maintenance | PostgreSQL writes opaque state across multiple real files and directories, so legitimate checkpoints and maintenance remain plausible false-positive sources. |
| `mysqld` | MySQL/MariaDB tablespace and log maintenance | `mysqld` maintains redo logs, tablespaces, and temp files in a way that still overlaps with repeated opaque multi-file writes. |
| `mongod` | MongoDB journal, compaction, and data-file maintenance | `mongod` performs journal and compaction churn that can look like bulk opaque file modification rather than ordinary user-document editing. |

## Final note

This whitelist does not treat generic editors, compiler stages, schedulers,
media encoders, or simple one-output tools as blanket-trusted. The remaining
entries are here because they still pose a realistic false-positive threat
under the detector's ransomware-oriented behavior.
