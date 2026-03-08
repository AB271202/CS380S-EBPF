.PHONY: run run-verbose deps exp-run exp-metrics exp-metrics-json clean

# eBPF programs must be loaded into the kernel as root.
run:
	sudo python3 agent/main.py

run-verbose:
	sudo python3 agent/main.py --verbose

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

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
