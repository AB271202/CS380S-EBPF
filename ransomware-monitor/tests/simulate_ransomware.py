"""Ransomware simulation suite for testing the monitor.

Simulates various ransomware variants:
  - entropy:     High-frequency, high-entropy writes (big-bang encryption)
  - unlink:      High-frequency file deletions
  - slowburn:    Slow, stealthy encryption over a longer period
  - bigbang:     Rapid encryption of many files across directories
  - rename_only: Renames files to suspicious extensions without encryption
  - chmod_lock:  Rapid chmod calls to lock out users

Also includes false-positive workloads:
  - compile:     Simulates a large C++ compilation
  - grep:        Simulates recursive grep across many files
  - backup:      Simulates an rsync-like backup operation
"""

import os
import random
import shutil
import stat
import tempfile
import time
import argparse


def simulate_high_entropy_writes(num_files=15, write_size=256, interval=0.01):
    """Big-bang: rapid high-entropy writes to many files."""
    print(f"Simulating ransomware behavior: {num_files} high-entropy writes...")
    files = []
    for i in range(num_files):
        filename = f"test_data_{i}.bin"
        files.append(filename)
        data = os.urandom(write_size)
        with open(filename, "wb") as f:
            f.write(data)
            f.flush()
        time.sleep(interval)

    print("Cleanup: removing test files...")
    for filename in files:
        if os.path.exists(filename):
            os.remove(filename)


def simulate_high_frequency_unlinks(num_files=10, interval=0.01):
    """Rapid file deletion pattern."""
    print(f"Simulating ransomware behavior: {num_files} high-frequency unlinks...")
    files = []
    for i in range(num_files):
        filename = f"unlink_test_{i}.tmp"
        files.append(filename)
        with open(filename, "w") as f:
            f.write("temporary file")

    for filename in files:
        if os.path.exists(filename):
            os.remove(filename)
            time.sleep(interval)


def simulate_slowburn(num_files=20, write_size=256, interval=0.5):
    """Slow-burn: encrypt files one at a time with pauses to evade
    frequency-based detection."""
    print(f"Simulating slow-burn encryption: {num_files} files, {interval}s interval...")
    tmpdir = tempfile.mkdtemp(prefix="slowburn_")
    files = []
    # Create target files
    for i in range(num_files):
        path = os.path.join(tmpdir, f"document_{i}.txt")
        with open(path, "w") as f:
            f.write(f"Important document content {i}\n" * 20)
        files.append(path)

    # Encrypt in-place, slowly
    for path in files:
        data = os.urandom(write_size)
        with open(path, "wb") as f:
            f.write(data)
        time.sleep(interval)

    print("Cleanup...")
    shutil.rmtree(tmpdir, ignore_errors=True)


def simulate_bigbang(num_dirs=5, files_per_dir=10, write_size=256):
    """Big-bang: encrypt files across many directories as fast as possible."""
    print(f"Simulating big-bang encryption: {num_dirs} dirs × {files_per_dir} files...")
    tmpdir = tempfile.mkdtemp(prefix="bigbang_")
    all_files = []

    # Create directory tree with files
    for d in range(num_dirs):
        dirpath = os.path.join(tmpdir, f"dir_{d}")
        os.makedirs(dirpath, exist_ok=True)
        for f in range(files_per_dir):
            path = os.path.join(dirpath, f"file_{f}.docx")
            with open(path, "w") as fh:
                fh.write(f"Content {d}-{f}\n" * 10)
            all_files.append(path)

    # Encrypt everything as fast as possible
    for path in all_files:
        data = os.urandom(write_size)
        with open(path, "wb") as fh:
            fh.write(data)
        # Rename to .locked
        locked = path + ".locked"
        os.rename(path, locked)

    print("Cleanup...")
    shutil.rmtree(tmpdir, ignore_errors=True)


def simulate_rename_only(num_files=15):
    """Rename-only: rename files to suspicious extensions without encrypting."""
    print(f"Simulating rename-only attack: {num_files} files...")
    tmpdir = tempfile.mkdtemp(prefix="rename_")
    extensions = [".locked", ".crypto", ".encrypted", ".onion"]

    for i in range(num_files):
        src = os.path.join(tmpdir, f"file_{i}.txt")
        with open(src, "w") as f:
            f.write(f"Content {i}")
        ext = random.choice(extensions)
        dst = src + ext
        os.rename(src, dst)
        time.sleep(0.01)

    print("Cleanup...")
    shutil.rmtree(tmpdir, ignore_errors=True)


def simulate_chmod_lockout(num_files=15):
    """Rapid chmod calls to lock users out of their files."""
    print(f"Simulating chmod lockout: {num_files} files...")
    tmpdir = tempfile.mkdtemp(prefix="chmod_")

    for i in range(num_files):
        path = os.path.join(tmpdir, f"file_{i}.txt")
        with open(path, "w") as f:
            f.write(f"Content {i}")
        os.chmod(path, 0o000)
        time.sleep(0.01)

    print("Cleanup...")
    # Restore permissions before cleanup
    for i in range(num_files):
        path = os.path.join(tmpdir, f"file_{i}.txt")
        if os.path.exists(path):
            os.chmod(path, 0o644)
    shutil.rmtree(tmpdir, ignore_errors=True)


# --- False-positive workloads ---

def simulate_compile(num_files=50, write_size=512):
    """Simulate a large C++ compilation: many .o files with high-entropy content."""
    print(f"Simulating compilation: {num_files} object files...")
    tmpdir = tempfile.mkdtemp(prefix="compile_")

    for i in range(num_files):
        path = os.path.join(tmpdir, f"module_{i}.o")
        # Object files contain high-entropy machine code
        data = os.urandom(write_size)
        with open(path, "wb") as f:
            f.write(data)
        time.sleep(0.005)

    print("Cleanup...")
    shutil.rmtree(tmpdir, ignore_errors=True)


def simulate_grep(num_files=100, num_dirs=10):
    """Simulate recursive grep: create files, read them all rapidly."""
    print(f"Simulating grep -r: {num_dirs} dirs × {num_files // num_dirs} files...")
    tmpdir = tempfile.mkdtemp(prefix="grep_")

    # Create files
    for d in range(num_dirs):
        dirpath = os.path.join(tmpdir, f"src_{d}")
        os.makedirs(dirpath, exist_ok=True)
        for f in range(num_files // num_dirs):
            path = os.path.join(dirpath, f"file_{f}.c")
            with open(path, "w") as fh:
                fh.write(f"// Source file {d}/{f}\nint main() {{ return {f}; }}\n")

    # Read all files (simulating grep)
    for root, dirs, files in os.walk(tmpdir):
        for fname in files:
            path = os.path.join(root, fname)
            with open(path, "r") as fh:
                fh.read()

    print("Cleanup...")
    shutil.rmtree(tmpdir, ignore_errors=True)


def simulate_backup(num_files=30, write_size=1024):
    """Simulate an rsync-like backup: copy files to a backup directory."""
    print(f"Simulating backup: {num_files} files...")
    srcdir = tempfile.mkdtemp(prefix="backup_src_")
    dstdir = tempfile.mkdtemp(prefix="backup_dst_")

    # Create source files
    for i in range(num_files):
        path = os.path.join(srcdir, f"data_{i}.dat")
        with open(path, "wb") as f:
            f.write(os.urandom(write_size))

    # Copy to backup (simulating rsync)
    for fname in os.listdir(srcdir):
        src = os.path.join(srcdir, fname)
        dst = os.path.join(dstdir, fname)
        shutil.copy2(src, dst)
        time.sleep(0.01)

    print("Cleanup...")
    shutil.rmtree(srcdir, ignore_errors=True)
    shutil.rmtree(dstdir, ignore_errors=True)


SIMULATIONS = {
    "entropy": simulate_high_entropy_writes,
    "unlink": simulate_high_frequency_unlinks,
    "slowburn": simulate_slowburn,
    "bigbang": simulate_bigbang,
    "rename_only": simulate_rename_only,
    "chmod_lock": simulate_chmod_lockout,
    "compile": simulate_compile,
    "grep": simulate_grep,
    "backup": simulate_backup,
    "both": None,  # Special: entropy + unlink
    "all_attacks": None,  # Special: all attack types
    "all_benign": None,  # Special: all false-positive workloads
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate ransomware behavior.")
    parser.add_argument(
        "--type",
        choices=list(SIMULATIONS.keys()),
        default="entropy",
        help="Type of behavior to simulate",
    )
    args = parser.parse_args()

    if args.type == "both":
        simulate_high_entropy_writes()
        simulate_high_frequency_unlinks()
    elif args.type == "all_attacks":
        for name in ("entropy", "unlink", "slowburn", "bigbang", "rename_only", "chmod_lock"):
            print(f"\n--- {name} ---")
            SIMULATIONS[name]()
    elif args.type == "all_benign":
        for name in ("compile", "grep", "backup"):
            print(f"\n--- {name} ---")
            SIMULATIONS[name]()
    else:
        SIMULATIONS[args.type]()
