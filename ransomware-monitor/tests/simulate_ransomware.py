import os
import random
import time

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

if __name__ == "__main__":
    simulate_high_entropy_writes()
