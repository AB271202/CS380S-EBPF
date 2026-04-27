# CS380S eBPF Ransomware Monitor

This project is a Linux ransomware monitor built with eBPF for kernel-side
event capture and Python for user-space detection and response logic.

The monitor is intentionally behavioral rather than signature-based. It watches
filesystem activity, builds short-lived and cumulative process context, and
looks for patterns that are consistent with ransomware impact:

- suspicious extension and rename behavior
- high-entropy multi-file writes
- in-place overwrite of existing files
- write-then-delete cleanup patterns
- `/dev/urandom` plus high-entropy writes
- delegated helper workflows, where a parent orchestrates child writers

The detector is tuned to behave like a ransomware monitor rather than a generic
“destructive activity” monitor:

- directory traversal now arms suspicion instead of firing directly
- generic launchers such as `bash` and `python3` no longer inherit child-write
  alerts too loosely
- slow-burn cumulative alerts now require entropy-backed ransomware anchors

## Repository Layout

- [agent/detector.py](agent/detector.py): heuristic detector and trust policy
- [agent/main.py](agent/main.py): user-space monitor entrypoint
- [agent/mitigator.py](agent/mitigator.py): simulated or real response chain
- [bpf/monitor.bpf.c](bpf/monitor.bpf.c): eBPF event capture
- [experiments/README.md](experiments/README.md): experiment harness usage
- [experiments/EXPERIMENTS.md](experiments/EXPERIMENTS.md): evaluation writeup
- [experiments/WHITELIST.md](experiments/WHITELIST.md): final default whitelist rationale
- [experiments/WHITELIST_ABLATION.md](experiments/WHITELIST_ABLATION.md): minimal test-context whitelist study
- [tests/](tests): unit and detector-regression tests

## Quick Start

Install dependencies:

```bash
make deps
```

Run the monitor:

```bash
make run
```

The monitor requires root privileges to load and attach the eBPF program.

## Detector Design

The detector has two main layers.

### 1. Trust Layer

Some benign tools are trusted by default because their normal workloads still
overlap with ransomware-like file behavior. The built-in whitelist focuses
on:

- package managers and dependency installers
- direct compression and encryption tools
- sync tools with legitimate bulk delete behavior
- batch overwrite tools such as `mogrify`
- multi-file database engines

The exact default list and rationale are documented in
[experiments/WHITELIST.md](experiments/WHITELIST.md).

The trust layer can also be hardened with:

- binary hash verification
- process lineage validation
- custom whitelist JSON policy

### 2. Behavioral Layer

Processes that are not trusted after the first layer are evaluated with
heuristics such as:

- suspicious extension matching
- suspicious rename detection
- entropy plus write frequency
- file diversity plus entropy across directories
- in-place overwrite detection
- magic-bytes destruction
- write-then-delete correlation
- high unlink frequency
- entropy-anchored slow-burn profiling
- process-tree attribution of child writes to an eligible parent

## Response Model

The detector supports both simulated and real response modes. In the default
safe mode used for experiments, it logs what it would do. The response chain
can include:

- killing or suspending a process tree
- quarantining binaries
- network isolation
- remediation logging
- snapshot or rollback hooks

## Experiments

The experiment harness covers four complementary suites:

- a legacy control suite
- official Atomic Red Team Linux `T1486` tests
- a benign stress suite
- a behavioral ransomware simulation suite

Start with:

- [experiments/README.md](experiments/README.md)
- [experiments/EXPERIMENTS.md](experiments/EXPERIMENTS.md)

## Tests

Run the full test suite with:

```bash
make unit-test
```

or:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The main coverage areas are:

- basic suspicious-extension, entropy, and unlink heuristics
- false-positive reduction and whitelist policy
- canary files and path classification
- traversal arming and process-tree attribution
- slow-burn profiling, urandom tracking, and kill-signal handling
- mitigation behavior

## Notes

- The monitor targets Linux and requires kernel support for the eBPF hooks it uses.
- Root is required for ordinary runs because the BPF program must compile and attach.
- The detector behavior is best understood through the source code, the
  experiment docs, and the whitelist note.
