#!/usr/bin/env python3
import ctypes
import ctypes.util
import os


CORPUS_FILES = {
    "Documents": [
        "report_q3.docx",
        "budget_2024.xlsx",
        "meeting_notes.txt",
        "query.sql",
        "presentation.pptx",
    ],
    "Pictures": [
        "photo_001.jpg",
        "screenshot.png",
        "family.jpg",
        "vacation_01.png",
        "diagram.pdf",
    ],
    "Desktop": [
        "notes.txt",
        "todo.csv",
        "draft.docx",
        "analysis.py",
        "data.csv",
    ],
    "Projects": [
        "readme.txt",
        "main.py",
        "config.json",
        "output.csv",
        "summary.pdf",
    ],
}

TARGET_EXTENSIONS = {
    ".docx", ".pdf", ".jpg", ".png", ".xlsx",
    ".sql", ".py", ".txt", ".csv", ".pptx", ".json",
}

SKIP_EXTENSIONS = {".exe", ".dll", ".so", ".sys", ".bin"}


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


def _plaintext_for(filename: str) -> str:
    line = (
        f"This is a simulated user file: {filename}\n"
        "The contents are intentionally readable and low entropy so that "
        "in-place overwrites represent a visible destruction of user data.\n"
    )
    return (line * 20)[:1024]


def create_corpus(root="."):
    """Create a realistic directory tree with plaintext user files."""
    created = 0
    for dirname, filenames in CORPUS_FILES.items():
        dirpath = os.path.join(root, dirname)
        os.makedirs(dirpath, exist_ok=True)
        for fname in filenames:
            filepath = os.path.join(dirpath, fname)
            with open(filepath, "w", encoding="utf-8") as handle:
                handle.write(_plaintext_for(fname))
            created += 1
    return created


def iter_targets(root="."):
    """Walk tree, yield paths of files with target extensions."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fname in sorted(filenames):
            _, ext = os.path.splitext(fname)
            lower_ext = ext.lower()
            if lower_ext in SKIP_EXTENSIONS:
                continue
            if lower_ext in TARGET_EXTENSIONS:
                yield os.path.join(dirpath, fname)
