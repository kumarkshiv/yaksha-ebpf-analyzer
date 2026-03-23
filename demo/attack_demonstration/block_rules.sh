#!/bin/bash

# ── Step 1: Get the map ID for blocked_ports ──────────────────────────────────
MAP_ID=$(sudo bpftool map show | grep -B1 "blocked_ports" | grep -oP '^\d+')

if [ -z "$MAP_ID" ]; then
    echo "Error: Could not find blocked_ports map. Is the XDP program loaded?"
    exit 1
fi

echo "Found blocked_ports map ID: $MAP_ID"

# ── Step 2: Update the map entry for port 8080 ────────────────────────────────
sudo bpftool map update id "$MAP_ID" key 0x90 0x1f 0x00 0x00 value 0x01

if [ $? -eq 0 ]; then
    echo "Success: Port 8080 is now blocked (map id=$MAP_ID)"
else
    echo "Error: Failed to update map id=$MAP_ID"
    exit 1
fi