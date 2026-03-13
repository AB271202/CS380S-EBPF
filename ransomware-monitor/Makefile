.PHONY: run run-verbose deps clean

# eBPF programs must be loaded into the kernel as root.
run:
	sudo python3 agent/main.py

run-verbose:
	sudo python3 agent/main.py --verbose

mount: 
	sudo mount -t debugfs debugfs /sys/kernel/debug
	sudo mount -t tracefs nodev /sys/kernel/debug/tracing

# Install system-level BCC dependencies and Python requirements.
# Note: This assumes a Debian/Ubuntu-based system.
deps:
	sudo apt-get update
	sudo apt-get install -y bpfcc-tools linux-headers-$$(uname -r) python3-bpfcc
	pip3 install -r requirements.txt

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
