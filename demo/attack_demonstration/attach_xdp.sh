#!/bin/bash

set -e

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 -f <obj_file> -i <interface> [-p <priority>]"
    echo ""
    echo "  -f  Path to the XDP BPF object file  (e.g., xdp_fw.o)"
    echo "  -i  Network interface to attach to    (e.g., veth669583a)"
    echo "  -p  Attach priority (default: 50)"
    echo ""
    echo "Example:"
    echo "  $0 -f xdp_fw.o -i veth669583a"
    echo "  $0 -f xdp_drop.o -i eth0 -p 100"
    exit 1
}

# ─── Defaults ────────────────────────────────────────────────────────────────
PRIORITY=50

# ─── Argument Parsing ────────────────────────────────────────────────────────
while getopts "f:i:p:h" opt; do
    case $opt in
        f) OBJ_FILE="$OPTARG" ;;
        i) IFACE="$OPTARG" ;;
        p) PRIORITY="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ─── Validation ──────────────────────────────────────────────────────────────
if [ -z "$OBJ_FILE" ] || [ -z "$IFACE" ]; then
    echo "[!] Error: -f <obj_file> and -i <interface> are required."
    echo ""
    usage
fi

if [ ! -f "$OBJ_FILE" ]; then
    echo "[!] Error: Object file '$OBJ_FILE' not found."
    exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
    echo "[!] Error: Interface '$IFACE' does not exist."
    exit 1
fi

# ─── Derive BPF function name from object file ───────────────────────────────
# e.g., xdp_change.o → xdp_change
PROG_NAME=$(basename "$OBJ_FILE" .o)

echo "[*] Object file     : $OBJ_FILE"
echo "[*] BPF program name: $PROG_NAME"
echo "[*] Interface       : $IFACE"
echo "[*] Priority        : $PRIORITY"

# ─── Load ────────────────────────────────────────────────────────────────────
echo "[*] Loading XDP program..."

OUTPUT=$(sudo bpfman load file \
    -p "$OBJ_FILE" \
    --programs xdp:"$PROG_NAME"
)

echo "$OUTPUT"

# ─── Extract Program ID ──────────────────────────────────────────────────────
PROGRAM_ID=$(echo "$OUTPUT" | awk -F: '/Program ID/ {gsub(/ /,"",$2); print $2}')

if [ -z "$PROGRAM_ID" ]; then
    echo "[!] Failed to extract Program ID"
    exit 1
fi

echo "[*] Program ID detected: $PROGRAM_ID"

# ─── Attach ──────────────────────────────────────────────────────────────────
echo "[*] Attaching program to interface $IFACE..."

sudo bpfman attach "$PROGRAM_ID" xdp \
    --iface "$IFACE" \
    --priority "$PRIORITY"

echo "[✓] XDP program '$PROG_NAME' (ID: $PROGRAM_ID) successfully attached to $IFACE"