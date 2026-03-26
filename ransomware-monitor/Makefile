.PHONY: run run-verbose deps clean mount test-entropy test-extension

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
	sudo apt-get install -y bpfcc-tools linux-headers-$$(uname -r) python3-bpfcc
	pip3 install -r requirements.txt

# --- Test Cases ---

# To use these, run 'make run-verbose' in one terminal and 
# then run these targets in another.

# Simulate high-entropy writes (e.g., encryption)
test-entropy:
	python3 tests/simulate_ransomware.py

# Simulate suspicious file extension changes
test-extension:
	./tests/test_extensions.sh

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f test_data_*.bin test_file.locked important.crypto normal_file.txt
