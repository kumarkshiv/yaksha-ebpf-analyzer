#!/bin/bash
set -euo pipefail

echo "Fetching attached bpfman programs..."

# Get program IDs (skip header line)
PROGRAM_IDS=$(sudo bpfman list programs | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}')

if [ -z "$PROGRAM_IDS" ]; then
    echo "No bpfman programs found."
    exit 0
fi

echo "Unloading programs:"
for PID in $PROGRAM_IDS; do
    echo "  -> Unloading program ID $PID"
    sudo bpfman unload "$PID"
done

echo "All bpfman programs unloaded successfully."
