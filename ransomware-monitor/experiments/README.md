# Experiments

This folder contains the scripts used to run the ransomware detector against:

- the original legacy control suite
- the official Atomic Red Team `T1486` Linux tests

The harness records per-run results, logs, and confusion-matrix metrics.

## Before You Run Anything

From the repo root:

```bash
cd /home/vaagish/src/CS380S-EBPF/ransomware-monitor
```

Install the normal project dependencies:

```bash
make deps
```

Install the tools needed for the official Atomic `T1486` tests:

```bash
make exp-atomic-deps
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
make exp-run-atomic-t1486-official
```

Show metrics for the official Atomic suite:

```bash
make exp-metrics-atomic-official
```

## Tuned Official Atomic Settings

Defaults in the detector code were not changed.

The best non-default settings found on this WSL setup for the official `T1486` suite were:

```bash
THRESHOLD_ENTROPY=5.8
THRESHOLD_WRITES=1
TIME_WINDOW_SEC=3.0
```

In local testing, these settings improved the official Atomic suite from `1/4` detected to `3/4` detected, while keeping the same legacy-suite outcome as the default baseline:

- legacy `TP=2/3`
- legacy `FP=0`
- legacy `TN=4/4`
- legacy `FN=1`

Run the official Atomic suite with those tuned values:

```bash
sudo -E THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0   python3 experiments/run_experiments.py   --scenarios experiments/scenarios_atomic_t1486_official.csv   --output-dir experiments/out/atomic_t1486_official_tuned   --repeats 3
```

## One-Command Tuned Evaluation

Use this target if you want the tuned settings applied to both suites and want all three reports printed automatically:

```bash
make exp-run-tuned-both
```

That target does all of the following:

- runs the legacy suite with the tuned values
- runs the official Atomic `T1486` suite with the tuned values
- writes a merged results file
- prints metrics for legacy only, official only, and combined results

Outputs written by this target:

- `experiments/out/legacy_tuned/results.csv`
- `experiments/out/atomic_t1486_official_tuned/results.csv`
- `experiments/out/tuned_combined/results.csv`

## What the Harness Records

Each run writes:

- `results.csv` with predicted labels and bookkeeping fields
- `logs/*.monitor.log` with monitor output
- `logs/*.workload.stdout.log` and `logs/*.workload.stderr.log`
- `runs/<run_id>/...` with the workload sandbox contents

A run is counted as predicted positive when the monitor emits at least one `ALERT_JSON:` record for that run. If a scenario sets `expected_comm`, only alerts from that process name count as matching alerts.

## Scenario Files

The main scenario files are:

- `experiments/scenarios.csv`
- `experiments/scenarios_atomic_t1486_official.csv`

`run_experiments.py` preserves extra CSV columns such as `source`, `variant`, and `family` into `results.csv`, and `metrics.py` automatically prints grouped breakdowns when those fields are present.

## Common Problems

If a run fails, start with the per-run logs in `experiments/out/.../logs/`.

Things to keep in mind on this setup:

- monitor startup takes a few seconds because the BPF program must compile and attach
- some workloads can fail or time out, and `metrics.py` will list them under `Workload Failures`
- output directories are created under `experiments/out/`, and the harness restores ownership back to the original sudo user when possible
- using a quiet VM or WSL instance helps reduce background filesystem noise

## Main Files

- `experiments/run_experiments.py`: runs scenarios and collects results
- `experiments/metrics.py`: computes confusion-matrix metrics from `results.csv`
- `experiments/combine_results.py`: merges multiple `results.csv` files
- `experiments/workloads/t1486_atomic_official.sh`: sandboxed driver for official Linux Atomic `T1486` commands
