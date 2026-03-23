#!/bin/bash
 
# ── Argument parsing ──────────────────────────────────────────────────────────
while getopts "i:" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        *) echo "Usage: $0 -i <interface>"; exit 1 ;;
    esac
done
 
if [ -z "$INTERFACE" ]; then
    echo "Error: No interface specified."
    echo "Usage: $0 -i <interface>"
    exit 1
fi
 
echo "Starting tcpdump on interface: $INTERFACE"
 
# ── Run tcpdump ───────────────────────────────────────────────────────────────
sudo tcpdump -i "$INTERFACE" -n -v