# CIC-IDS2017 Curated Test Vector Subset

This directory contains trimmed, high-density network captures curated from the **CIC-IDS2017 benchmark dataset** for the Threat Detection Lane (Lane 2) of the **PQC-NIDS FPGA** engine.

## 1. Summary of Traces

| Trace File | Threat Class | Packets | Wire Size | Target Hardware Module | Triggered Reason Code |
|---|---|---:|---:|---|:---:|
| `benign.pcap` | Clean Traffic | 150 | 14,024 B | Baseline Noise Floor / All Lanes | `RC_NONE` (`4'h0`) |
| `synflood.pcap` | Volumetric Flood | 600 | 42,024 B | `count_min_sketch.v` ($C_{\text{flow}} \ge 512$) | `RC_FLOOD` (`4'h5`) |
| `portscan.pcap` | Horizontal Scan | 450 | 31,524 B | `count_min_sketch.v` ($C_{\text{host}} \ge 384$) | `RC_SCAN` (`4'h6`) |
| `signature.pcap` | Known Exploits | 20 | 2,292 B | `cam_matcher.v` (String Match) | `RC_SIGNATURE` (`4'h4`) |
| **Total** | | **1,220** | | | |

## 2. Integrity & Cryptographic Checksums (SHA-256)

```text
e0c1553d84c110f160ff9b65d9e42faf8fe2b817373d37a9ea577ad0b4e54f45  benign.pcap
6884de7ecce12dff007f51bfd8882584850d355f7427a3b49154e9032efb796b  synflood.pcap
8f957703730ee66d517916f72a33f426a553aa82abef20cbf62ed9be7d78a502  portscan.pcap
60176ae1f801c6b131043508ecd1acefbe8f49c41ef37a357bed2f82e16ca8cf  signature.pcap
```

## 3. Ground Truth Labels (`labels.json`)

The file `labels.json` maps every packet across all 4 traces to its expected hardware verdict (`expected_fail` and `expected_reason`). Testbenches in `sim/cocotb/` and live replay scripts in `test-network/attacker.py` consume this file as the ground truth oracle.
