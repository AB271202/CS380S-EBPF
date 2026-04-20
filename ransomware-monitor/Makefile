.PHONY: run run-verbose deps clean mount test-entropy test-extension test-unlink \
       exp-run exp-metrics exp-metrics-json exp-atomic-deps exp-benign-deps \
       exp-run-atomic exp-metrics-atomic exp-run-benign exp-metrics-benign \
       exp-run-behavioral exp-metrics-behavioral exp-run-tuned-behavioral \
       exp-metrics-tuned-behavioral exp-run-tuned-all unit-test

# --- Tuned threshold overrides (used by exp-run-tuned-*) ---
TUNED_ENV = THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0

# --- Core targets ---

run:
	sudo python3 agent/main.py

run-verbose:
	sudo python3 agent/main.py --verbose

mount:
	sudo mount -t debugfs debugfs /sys/kernel/debug || true
	sudo mount -t tracefs nodev /sys/kernel/debug/tracing || true

unit-test:
	python3 -m unittest tests/test_detector.py -v

deps:
	sudo apt-get update
	@if grep -qi microsoft /proc/version 2>/dev/null; then \
		echo "WSL detected: skipping linux-headers from apt."; \
		sudo apt-get install -y bpfcc-tools python3-bpfcc python3-pip; \
	else \
		sudo apt-get install -y bpfcc-tools linux-headers-$$(uname -r) python3-bpfcc python3-pip; \
	fi
	python3 -m pip install -r requirements.txt

exp-atomic-deps:
	sudo apt-get update && sudo apt-get install -y gnupg p7zip-full ccrypt openssl

exp-benign-deps:
	sudo apt-get update && sudo apt-get install -y zstd ffmpeg

# --- Manual test targets (run alongside 'make run-verbose') ---

test-entropy:
	python3 tests/simulate_ransomware.py --type entropy

test-extension:
	./tests/test_extensions.sh

test-unlink:
	python3 tests/simulate_ransomware.py --type unlink

# --- Experiment suite targets ---

exp-run:
	sudo -E python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios.csv \
		--output-dir experiments/out/latest --repeats 3

exp-metrics:
	python3 experiments/metrics.py --results experiments/out/latest/results.csv

exp-metrics-json:
	python3 experiments/metrics.py --results experiments/out/latest/results.csv \
		--json-out experiments/out/latest/metrics.json

exp-run-atomic:
	sudo -E python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_atomic_t1486_official.csv \
		--output-dir experiments/out/atomic_t1486_official --repeats 3

exp-metrics-atomic:
	python3 experiments/metrics.py --results experiments/out/atomic_t1486_official/results.csv

exp-run-benign:
	sudo -E python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_benign_stress.csv \
		--output-dir experiments/out/benign_stress --repeats 3

exp-metrics-benign:
	python3 experiments/metrics.py --results experiments/out/benign_stress/results.csv

exp-run-behavioral:
	sudo -E python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_behavioral.csv \
		--output-dir experiments/out/behavioral --repeats 3

exp-metrics-behavioral:
	python3 experiments/metrics.py --results experiments/out/behavioral/results.csv

exp-run-tuned-behavioral:
	sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_behavioral.csv \
		--output-dir experiments/out/behavioral_tuned --repeats 3

exp-metrics-tuned-behavioral:
	python3 experiments/metrics.py --results experiments/out/behavioral_tuned/results.csv

# --- Tuned runs (all suites with optimized thresholds) ---

exp-run-tuned-all:
	sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios.csv \
		--output-dir experiments/out/legacy_tuned --repeats 3
	sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_atomic_t1486_official.csv \
		--output-dir experiments/out/atomic_tuned --repeats 3
	sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_benign_stress.csv \
		--output-dir experiments/out/benign_tuned --repeats 3
	sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
		--scenarios experiments/scenarios_behavioral.csv \
		--output-dir experiments/out/behavioral_tuned --repeats 3
	sudo -E python3 experiments/combine_results.py \
		--output experiments/out/tuned_all/results.csv \
		experiments/out/legacy_tuned/results.csv \
		experiments/out/atomic_tuned/results.csv \
		experiments/out/benign_tuned/results.csv \
		experiments/out/behavioral_tuned/results.csv
	sudo chown -R $$(id -u):$$(id -g) experiments/out/tuned_all
	@echo "\n=== Legacy ===" && python3 experiments/metrics.py --results experiments/out/legacy_tuned/results.csv
	@echo "\n=== Atomic ===" && python3 experiments/metrics.py --results experiments/out/atomic_tuned/results.csv
	@echo "\n=== Benign ===" && python3 experiments/metrics.py --results experiments/out/benign_tuned/results.csv
	@echo "\n=== Behavioral ===" && python3 experiments/metrics.py --results experiments/out/behavioral_tuned/results.csv
	@echo "\n=== Combined ===" && python3 experiments/metrics.py --results experiments/out/tuned_all/results.csv

# --- Cleanup ---

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f test_data_*.bin test_file.locked important.crypto normal_file.txt
