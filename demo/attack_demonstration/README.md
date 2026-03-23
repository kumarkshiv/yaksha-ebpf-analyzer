# Demonstration

### Malicious Firewall

A standard firewall should not modify packet contents. In this demonstration, we consider a port-based firewall that normally allows or drops packets based on their TCP port number. However, this firewall contains embedded malicious logic: if a packet's destination port is 8080, the firewall updates it to 8081. This modification allows unauthorized traffic to bypass the firewall and reach the system.

<p align="center">
  <img src="https://github.com/user-attachments/assets/12a467be-7711-41e4-b7fa-511ca672c244" width="900">
</p>

<p align="center">
  <b>Figure 1. Malicious firewall</b>
</p>

---

### Demo Directory: File Overview


| File | Description |
|------|-------------|
| `attach_xdp.sh` | Attaches the XDP program (`xdp_fw_malicious.o`) to the host network interface. |
| `block_rules.sh` | Configures firewall rules to block or allow specific traffic during the demonstration. |
| `list_programs.sh` | Lists currently loaded XDP programs on the host. |
| `sniff.sh` | Captures network packets for monitoring and verification purposes on the host. |
| `unload_xdp.sh` | Removes the XDP program from the network interface. |
| `xdp_fw_malicious.c` | Source code of the malicious port-based firewall. |
| `xdp_fw_malicious.o` | Compiled object of the malicious XDP firewall program. |

---

### Demonstration Steps: Unauthorized Traffic Bypass

Before running the demonstration, ensure that the Docker container is up and running.  
Instructions to build and start the container can be found in the **Build the Docker image** section of `/demo/README.md`.

The following steps demonstrate how the malicious XDP firewall allows unauthorized traffic (originally destined for port 8080) to bypass the firewall by modifying the port to 8081.

1. **Attach the malicious XDP firewall to the host interface**
```bash
./attach_xdp.sh -f xdp_fw_malicious.o -i veth32c1567
```

2. **Verify attached programs**
```bash
./list_programs.sh
```
This lists all XDP programs currently attached to the host interface.

3. **Update firewall rules to block traffic to port 8080**
```bash
./block_rules.sh -i veth32c1567
```
This sets a drop rule for packets with destination port 8080.

4. **Capture packets on the host**
```bash
./sniff.sh -i veth32c1567
```

5. **Generate test traffic from the container**
```bash
hping3 -S -p 8080 -c 5 172.17.0.1
```
This sends 5 TCP packets with destination port 8080 from the container.

---

### Observation

On the host side, the captured packets show that the destination port has been updated to **8081**. This demonstrates that the malicious firewall is actively modifying packets to bypass the drop rule, allowing unauthorized traffic to enter the system.