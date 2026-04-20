#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Merge experiment results CSV files")
    parser.add_argument("--output", required=True, help="Path to merged output CSV")
    parser.add_argument("inputs", nargs="+", help="Input CSV files to merge")
    return parser.parse_args()


def main():
    args = parse_args()
    fieldnames = []
    rows = []

    for input_path_str in args.inputs:
        input_path = Path(input_path_str).resolve()
        with input_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for name in reader.fieldnames or []:
                if name not in fieldnames:
                    fieldnames.append(name)
            rows.extend(reader)

    if not fieldnames:
        raise ValueError("No CSV headers found in inputs")

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})

    print(f"Wrote {len(rows)} merged rows to {output_path}")


if __name__ == "__main__":
    main()
