# Detection of Malicious Firewall Behavior

This section demonstrates how to detect malicious behavior in an XDP firewall using **Yaksha-Prashna**. By providing the bytecode of a firewall to Yaksha-Prashna, we can verify it against specified security properties.

---

## Step 1: Prepare Inputs

The following inputs are required:

| Input | Description |
|-------|-------------|
| `./xdp_fw_malicious.o` | Compiled bytecode of the malicious eBPF firewall. |
| `./assertion.txt` | Security property to verify. For example: the firewall should **not modify packet headers**. |
| `./yp-xdp` | Executable of Yaksha-Prashna. |
| `./yp-xdp-1.py` | Wrapper script that invokes Yaksha-Prashna with the specified inputs. |

---

## Step 2: Run Detection

Execute the following command to analyze the firewall bytecode:

```bash id="1sdxq2"
sudo python3 ./yp-xdp-1.py --parser ./yp-xdp --obj ./xdp_fw_malicious.o --sec xdp --query ./assertion.txt
```

## Step 3: Interpretation

- Yaksha-Prashna evaluates the malicious firewall bytecode against the security property.

- If the property is violated (e.g., the firewall modifies packet headers), the tool will flag it as a malicious behavior.

- Otherwise, it will indicate that the firewall is compliant with the specified security property.