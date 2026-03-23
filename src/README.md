# Overview

This repository contains the code and components required to for running **Yaksha-Prashna** for detecting and defending against malicious bytecode .

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
