#!/usr/bin/env python3
import argparse
import os

from ransim_common import create_corpus, iter_targets, set_comm


def overwrite_then_delete() -> int:
    processed = 0
    for filepath in iter_targets("."):
        with open(filepath, "r+b") as handle:
            original = handle.read()
            handle.seek(0)
            handle.write(os.urandom(len(original)))
        os.unlink(filepath)
        processed += 1
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="High-fidelity in-place overwrite-and-delete simulator"
    )
    parser.parse_args()

    set_comm(b"ransim_ipd")
    create_corpus()
    processed = overwrite_then_delete()
    print(f"ransim_ipd overwrote and deleted {processed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
