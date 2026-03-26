#!/bin/bash
set -e

echo "Simulating suspicious extension activities..."

# Create a file with a suspicious extension (triggres OPEN with O_CREAT)
echo "Creating suspicious file 'test_file.locked'..."
touch test_file.locked
sleep 1

# Rename a file to a suspicious extension
echo "Renaming 'normal_file.txt' to 'important.crypto'..."
echo "Some normal content" > normal_file.txt
mv normal_file.txt important.crypto
sleep 1

# Cleanup
echo "Cleaning up test files..."
rm -f test_file.locked important.crypto

echo "Suspicious extension simulation complete."
