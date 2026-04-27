# Experiments

This folder contains the scripts used to run the ransomware detector against:

- the legacy control suite
- the official Atomic Red Team `T1486` Linux tests
- a benign stress suite derived from Phoronix-style workloads
- a behavioral ransomware simulation suite derived from threat intelligence

The detector also supports selective process-tree attribution. The BPF
event path captures each event's parent PID in-kernel, and the detector can
attribute child-write evidence back to an eligible non-whitelisted
orchestrator whose recent context actually overlaps the child's target paths.

The harness records per-run results, logs, and confusion-matrix metrics.

## Before You Run Anything

From the repo root:

```bash
cd /path/to/CS380S-EBPF
```

Install the normal project dependencies:

```bash
make deps
```

Install the tools needed for the official Atomic `T1486` tests:

```bash
make exp-atomic-deps
```

Install the extra tools used by the benign stress suite:

```bash
make exp-benign-deps
```

Run all experiment commands with `sudo -E`. The monitor loads eBPF programs, so root is required.

## Quick Start

Run the legacy suite:

```bash
make exp-run
```

Show metrics for the legacy suite:

```bash
make exp-metrics
```

Run the official Atomic `T1486` suite:

```bash
make exp-run-atomic
```

Show metrics for the official Atomic suite:

```bash
make exp-metrics-atomic
```

Run the benign stress suite:

```bash
make exp-run-benign
```

Show metrics for the benign stress suite:

```bash
make exp-metrics-benign
```

The benign stress suite is intentionally all `label=negative`. It is meant to
measure realistic false positives from legitimate compression, encryption,
media encoding, and compilation workloads. A detector firing on these cases is
the interesting outcome.

Run the behavioral suite:

```bash
make exp-run-behavioral
```

Show metrics for the behavioral suite:

```bash
make exp-metrics-behavioral
```

## Tuned Official Atomic Settings

Defaults in the detector code were not changed.

The tuned settings that were most useful on the final evaluation setup for the
official `T1486` suite were:

```bash
THRESHOLD_ENTROPY=5.8
THRESHOLD_WRITES=1
TIME_WINDOW_SEC=3.0
```

Run the official Atomic suite with those tuned values:

```bash
sudo -E THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0   python3 experiments/run_experiments.py   --scenarios experiments/scenarios_atomic_t1486_official.csv   --output-dir experiments/out/atomic_t1486_official_tuned   --repeats 3
```

Run the benign stress suite with those tuned values:

```bash
sudo -E THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0 \
  python3 experiments/run_experiments.py \
  --scenarios experiments/scenarios_benign_stress.csv \
  --output-dir experiments/out/benign_tuned \
  --repeats 3
```

Show metrics for the tuned benign stress suite:

```bash
python3 experiments/metrics.py --results experiments/out/benign_tuned/results.csv
```

Run the behavioral suite with those tuned values:

```bash
make exp-run-tuned-behavioral
```

Show metrics for the tuned behavioral suite:

```bash
make exp-metrics-tuned-behavioral
```

If detector logic changes, rerun the suites and regenerate metrics rather than
relying on stale results.

## One-Command Tuned Evaluation

Use this target if you want the tuned settings applied to the legacy, official
Atomic, benign stress, and behavioral suites and want all reports printed
automatically:

```bash
make exp-run-tuned-all
```

That target does all of the following:

- runs the legacy suite with the tuned values
- runs the official Atomic `T1486` suite with the tuned values
- runs the benign stress suite with the tuned values
- runs the behavioral suite with the tuned values
- writes a merged results file
- prints metrics for legacy only, official only, benign only, behavioral only,
  and combined results

Outputs written by this target:

- `experiments/out/legacy_tuned/results.csv`
- `experiments/out/atomic_tuned/results.csv`
- `experiments/out/benign_tuned/results.csv`
- `experiments/out/behavioral_tuned/results.csv`
- `experiments/out/tuned_all/results.csv`

## What the Harness Records

Each run writes:

- `results.csv` with predicted labels and bookkeeping fields
- `logs/*.monitor.log` with monitor output
- `logs/*.workload.stdout.log` and `logs/*.workload.stderr.log`
- `runs/<run_id>/...` with the workload sandbox contents

A run is counted as predicted positive when the monitor emits at least one
`ALERT_JSON:` record for that run. If a scenario sets `expected_comm`, only
alerts from those process names count as matching alerts. `expected_comm` may
be a comma-separated list when a workload intentionally includes helper
processes that should count toward the scenario outcome.

## Scenario Files

The main scenario files are:

- `experiments/scenarios.csv`
- `experiments/scenarios_atomic_t1486_official.csv`
- `experiments/scenarios_benign_stress.csv`
- `experiments/scenarios_behavioral.csv`

`run_experiments.py` preserves extra CSV columns such as `source`, `variant`, and `family` into `results.csv`, and `metrics.py` automatically prints grouped breakdowns when those fields are present.

The benign stress CSV mirrors the Atomic CSV structure:

- `id,label,source,variant,family,expected_comm,command,notes`

It includes:

- compression workloads using `7z`, `zstd`, and `gzip`
- benign encryption workloads using `gpg`, `openssl`, and `ccencrypt`
- a media encode workload using `ffmpeg`
- a compilation burst workload using `gcc`

The behavioral suite mirrors the same CSV structure and contains:

- single-process directory-walk encryption simulations
- encrypt-then-delete simulations
- overwrite-and-rename simulations
- a throttled evasion variant
- a delegated-encryption scenario that shells out to per-file `ccencrypt` child processes and exercises process-tree attribution

## Common Problems

If a run fails, start with the per-run logs in `experiments/out/.../logs/`.

Things to keep in mind on this setup:

- monitor startup takes a few seconds because the BPF program must compile and attach
- some workloads can fail or time out, and `metrics.py` will list them under `Workload Failures`
- helper-heavy benign workloads may legitimately produce alerts even when they
  are labeled negative; that is the point of the false-positive stress suite
- output directories are created under `experiments/out/`, and the harness restores ownership back to the invoking sudo user when possible
- using a quiet VM or WSL instance helps reduce background filesystem noise

## Main Files

- `experiments/run_experiments.py`: runs scenarios and collects results
- `experiments/metrics.py`: computes confusion-matrix metrics from `results.csv`
- `experiments/combine_results.py`: merges multiple `results.csv` files
- `experiments/scenarios_benign_stress.csv`: benign false-positive stress suite
- `experiments/scenarios_behavioral.csv`: behavioral ransomware simulation suite
- `experiments/workloads/t1486_atomic_official.sh`: sandboxed driver for official Linux Atomic `T1486` commands
