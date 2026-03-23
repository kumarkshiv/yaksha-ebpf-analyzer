# Overview

This repository contains the code and components required to demonstrate the attack using malicious firewall bytecode, and ability of **Yaksha-Prashna** in detecting and dedending against malicious bytecode .

---

# Prerequisites

Ensure that the following dependencies are installed in the host:

- Linux system
- bpfman
- tcpdump
- Docker

---

#### Install bpfman

**bpfman** is used for managing and loading eBPF programs.

Install it using the following commands:

```bash
git clone https://github.com/bpfman/bpfman.git
cd bpfman
cargo build --release
sudo cp target/release/bpfman /usr/local/bin/
```

Verify the installation:
```bash
bpfman version
```
---

#### Install tcpdump

**tcpdump** is needed to capture and inspect network packets.

Install it using the following commands:

```bash
sudo apt install -y tcpdump
```

Verify the installation:
```bash
tcpdump --version
```

---

#### Build the Docker Image
This repository provides a `Dockerfile` to build the required environment.

Run the following command from the root directory of this repository:
```bash
 docker build -t network_tools_image .
```
This command builds an image from your Dockerfile in the current directory (`.`) and tags it as `network_tools_image`.

**Run a container from the image:**
   ```bash
   docker run -it --name network_tools network_tools_image
   ```
   This creates and starts an interactive container named "network_tools".

---

#### Demo and Verification Directories

This repository provides two directories for demonstrating and validating malicious network function behavior:

- **`attack_demonstration/`** – Contains all scripts and code to execute the attack using malicious firewall bytecode. Follow the instructions in this directory to observe unauthorized traffic bypassing the firewall.

- **`verifying_NF/`** – Contains scripts and instructions to validate network functions (NFs) against security properties using **Yaksha-Prashna**. This directory demonstrates how Yaksha-Prashna detects malicious modifications in firewall bytecode.