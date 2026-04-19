.PHONY: run run-verbose deps clean mount test-entropy test-extension test-unlink exp-run exp-metrics exp-metrics-json exp-atomic-deps exp-run-atomic-t1486-official exp-metrics-atomic-official exp-run-tuned-both

# eBPF programs must be loaded into the kernel as root.
run:
	sudo python3 agent/main.py

run-verbose:
	sudo python3 agent/main.py --verbose

mount:
	sudo mount -t debugfs debugfs /sys/kernel/debug || true
	sudo mount -t tracefs nodev /sys/kernel/debug/tracing || true

# Install system-level BCC dependencies and Python requirements.
# Note: This assumes a Debian/Ubuntu-based system.
deps:
	sudo apt-get update
	if grep -qi microsoft /proc/version; then \
		echo "WSL detected: skipping linux-headers-$$(uname -r) from apt."; \
		echo "Use WSL2 kernel source + modules_prepare for matching build headers."; \
		sudo apt-get install -y bpfcc-tools python3-bpfcc python3-pip; \
	else \
		sudo apt-get install -y bpfcc-tools linux-headers-$$(uname -r) python3-bpfcc python3-pip; \
	fi
	python3 -m pip install -r requirements.txt

exp-run:
	sudo -E python3 experiments/run_experiments.py --scenarios experiments/scenarios.csv --output-dir experiments/out/latest --repeats 3

exp-metrics:
	python3 experiments/metrics.py --results experiments/out/latest/results.csv

exp-metrics-json:
	python3 experiments/metrics.py --results experiments/out/latest/results.csv --json-out experiments/out/latest/metrics.json

exp-atomic-deps:
	sudo apt-get update
	sudo apt-get install -y gnupg p7zip-full ccrypt openssl

exp-run-atomic-t1486-official:
	sudo -E python3 experiments/run_experiments.py --scenarios experiments/scenarios_atomic_t1486_official.csv --output-dir experiments/out/atomic_t1486_official --repeats 3

exp-metrics-atomic-official:
	python3 experiments/metrics.py --results experiments/out/atomic_t1486_official/results.csv

exp-run-tuned-both:
	sudo -E THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0 python3 experiments/run_experiments.py --scenarios experiments/scenarios.csv --output-dir experiments/out/legacy_tuned --repeats 3
	sudo -E THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0 python3 experiments/run_experiments.py --scenarios experiments/scenarios_atomic_t1486_official.csv --output-dir experiments/out/atomic_t1486_official_tuned --repeats 3
	sudo -E python3 experiments/combine_results.py --output experiments/out/tuned_combined/results.csv experiments/out/legacy_tuned/results.csv experiments/out/atomic_t1486_official_tuned/results.csv
	sudo chown -R $$(id -u):$$(id -g) experiments/out/tuned_combined
	@echo ""
	@echo "Legacy Metrics"
	python3 experiments/metrics.py --results experiments/out/legacy_tuned/results.csv
	@echo ""
	@echo "Official Atomic Metrics"
	python3 experiments/metrics.py --results experiments/out/atomic_t1486_official_tuned/results.csv
	@echo ""
	@echo "Combined Metrics"
	python3 experiments/metrics.py --results experiments/out/tuned_combined/results.csv

# --- Test Cases ---

# To use these, run 'make run-verbose' in one terminal and
# then run these targets in another.

# Simulate high-entropy writes (e.g., encryption)
test-entropy:
	python3 tests/simulate_ransomware.py --type entropy

# Simulate suspicious file extension changes
test-extension:
	./tests/test_extensions.sh

# Simulate high-frequency unlinks
test-unlink:
	python3 tests/simulate_ransomware.py --type unlink

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f test_data_*.bin test_file.locked important.crypto normal_file.txt
