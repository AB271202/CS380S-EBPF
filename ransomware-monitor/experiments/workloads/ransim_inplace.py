#!/usr/bin/env python3
import argparse
import os

from ransim_common import create_corpus, iter_targets, set_comm


def overwrite_in_place() -> int:
    processed = 0
    for filepath in iter_targets("."):
        with open(filepath, "r+b") as handle:
            original = handle.read()
            handle.seek(0)
            handle.write(os.urandom(len(original)))
            handle.write(os.urandom(256))
        processed += 1
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="High-fidelity in-place ransomware behavior simulator"
    )
    parser.parse_args()

    set_comm(b"ransim_inp")
    create_corpus()
    processed = overwrite_in_place()
    print(f"ransim_inp overwrote {processed} files in place")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
