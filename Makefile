.PHONY: run run-verbose deps clean mount unit-test \
        $(addprefix exp-run-,legacy atomic benign behavioral) \
        $(addprefix exp-metrics-,legacy atomic benign behavioral) \
        exp-run-tuned-all exp-clean-tuned

# --- Tuned threshold overrides ---
TUNED_ENV = THRESHOLD_ENTROPY=5.8 THRESHOLD_WRITES=1 TIME_WINDOW_SEC=3.0

SCENARIO_FILES = \
    legacy:experiments/scenarios.csv \
    atomic:experiments/scenarios_atomic_t1486_official.csv \
    benign:experiments/scenarios_benign_stress.csv \
    behavioral:experiments/scenarios_behavioral.csv

define scenario_name
$(word 1,$(subst :, ,$1))
endef
define scenario_file
$(word 2,$(subst :, ,$1))
endef

# --- Core targets ---
run:
	sudo python3 agent/main.py

run-verbose:
	sudo python3 agent/main.py --verbose

mount:
	sudo mount -t debugfs debugfs /sys/kernel/debug || true
	sudo mount -t tracefs nodev /sys/kernel/debug/tracing || true

unit-test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

deps:
	sudo apt-get update
	@if grep -qi microsoft /proc/version 2>/dev/null; then \
		echo "WSL detected: skipping linux-headers from apt."; \
		sudo apt-get install -y bpfcc-tools python3-bpfcc python3-pip; \
	else \
		sudo apt-get install -y bpfcc-tools linux-headers-$$(uname -r) python3-bpfcc python3-pip; \
	fi
	python3 -m pip install -r requirements.txt
	sudo apt-get install -y gnupg p7zip-full ccrypt openssl
	sudo apt-get install -y zstd ffmpeg

# --- Experiment runner macro ---
SUITES = legacy atomic benign behavioral
SUITE_SCENARIO = legacy:experiments/scenarios.csv \
                 atomic:experiments/scenarios_atomic_t1486_official.csv \
                 benign:experiments/scenarios_benign_stress.csv \
                 behavioral:experiments/scenarios_behavioral.csv

RUN_EXP = sudo -E python3 experiments/run_experiments.py \
              --scenarios $(1) --output-dir experiments/out/$(2) --repeats 3

SHOW_METRICS = python3 experiments/metrics.py \
              --results experiments/out/$(1)/results.csv

exp-run-%:
	$(call RUN_EXP,$(call scenario_file,$(filter $*:%,$(SUITE_SCENARIO))),$*)

exp-metrics-%:
	$(call SHOW_METRICS,$*)

# --- Tuned runs ---
exp-run-tuned-all:
	$(foreach s,$(SUITES), \
	  sudo -E $(TUNED_ENV) python3 experiments/run_experiments.py \
	    --scenarios $(call scenario_file,$(filter $s:%,$(SUITE_SCENARIO))) \
	    --output-dir experiments/out/$(s)_tuned --repeats 3;)
	sudo -E python3 experiments/combine_results.py \
	    --output experiments/out/tuned_all/results.csv \
	    $(foreach s,$(SUITES),experiments/out/$(s)_tuned/results.csv)
	sudo chown -R $$(id -u):$$(id -g) experiments/out/tuned_all
	$(foreach s,$(SUITES), \
	  @echo "\n=== $(s) ===" && $(call SHOW_METRICS,$(s)_tuned);)
	@echo "\n=== Combined ===" && $(call SHOW_METRICS,tuned_all)

exp-clean-tuned:
	rm -rf $(foreach s,$(SUITES),experiments/out/$(s)_tuned) \
	       experiments/out/tuned_all

# --- Cleanup ---
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f test_data_*.bin test_file.locked important.crypto normal_file.txt