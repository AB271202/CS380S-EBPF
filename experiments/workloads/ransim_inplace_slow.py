#!/usr/bin/env python3
import argparse
import os
import time

from ransim_common import create_corpus, iter_targets, set_comm


def overwrite_in_place_slowly() -> int:
    processed = 0
    for filepath in iter_targets("."):
        with open(filepath, "r+b") as handle:
            original = handle.read()
            handle.seek(0)
            handle.write(os.urandom(len(original)))
            handle.write(os.urandom(256))
        processed += 1
        time.sleep(0.5)
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="High-fidelity throttled in-place ransomware simulator"
    )
    parser.parse_args()

    set_comm(b"ransim_ips")
    create_corpus()
    processed = overwrite_in_place_slowly()
    print(f"ransim_ips overwrote {processed} files in place slowly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
