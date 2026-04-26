import os
import random
import time
import argparse

def simulate_high_entropy_writes(num_files=15, write_size=256, interval=0.01):
    print(f"Simulating ransomware behavior: {num_files} high-entropy writes...")
    files = []
    for i in range(num_files):
        filename = f"test_data_{i}.bin"
        files.append(filename)
        # Generate random (high entropy) data
        data = os.urandom(write_size)
        
        with open(filename, "wb") as f:
            f.write(data)
            f.flush()
        
        # Fast writes to trigger frequency threshold
        time.sleep(interval)
    
    print("Cleanup: removing test files...")
    for filename in files:
        if os.path.exists(filename):
            os.remove(filename)

def simulate_high_frequency_unlinks(num_files=10, interval=0.01):
    print(f"Simulating ransomware behavior: {num_files} high-frequency unlinks...")
    # Create files first
    files = []
    for i in range(num_files):
        filename = f"unlink_test_{i}.tmp"
        files.append(filename)
        with open(filename, "w") as f:
            f.write("temporary file")
    
    # Unlink them quickly
    for filename in files:
        if os.path.exists(filename):
            os.remove(filename)
            time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate ransomware behavior.")
    parser.add_argument(
        "--type",
        choices=["entropy", "unlink", "both"],
        default="entropy",
        help="Type of behavior to simulate"
    )
    args = parser.parse_args()

    if args.type == "entropy" or args.type == "both":
        simulate_high_entropy_writes()
    
    if args.type == "unlink" or args.type == "both":
        simulate_high_frequency_unlinks()
