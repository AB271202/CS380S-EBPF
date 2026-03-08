# Experiment Harness

This folder contains a reproducible process-level evaluation harness for:

- True positives (TP)
- False positives (FP)
- True negatives (TN)
- False negatives (FN)
- Precision / Recall / Specificity / FPR / Accuracy

## 1) Run the labeled workload suite

Run as root because `agent/main.py` loads eBPF:

```bash
cd ransomware-monitor
sudo -E python3 experiments/run_experiments.py \
  --scenarios experiments/scenarios.csv \
  --output-dir experiments/out/latest \
  --repeats 3
```

Optional threshold tuning during experiments:

```bash
sudo -E THRESHOLD_ENTROPY=6.3 THRESHOLD_WRITES=10 TIME_WINDOW_SEC=1.0 \
  PERF_PAGE_CNT=4096 \
  python3 experiments/run_experiments.py --repeats 3
```

## 2) Compute metrics

```bash
python3 experiments/metrics.py \
  --results experiments/out/latest/results.csv
```

Optional JSON export:

```bash
python3 experiments/metrics.py \
  --results experiments/out/latest/results.csv \
  --json-out experiments/out/latest/metrics.json
```

## How scoring works

- Each row in `scenarios.csv` has an expected label: `positive` or `negative`.
- During each run, the monitor emits structured alert lines prefixed with `ALERT_JSON:`.
- A run is predicted `positive` if it has at least one alert for that run ID.
- If `expected_comm` is set, only alerts from that process name count as matching alerts.
- `results.csv` stores per-run predictions and logs.

## Scenario file format

`experiments/scenarios.csv` columns:

- `id`
- `label` (`positive` or `negative`)
- `command`
- `expected_comm` (optional but recommended)
- `notes` (optional)

## Notes

- Use a dedicated test VM/WSL instance to reduce background noise.
- Keep detection thresholds fixed for the final test split.
- If you tune thresholds, report metrics on a separate held-out scenario set.
- `run_experiments.py` restores `experiments/out/...` ownership back to the original sudo user when run via `sudo -E`.
