"""
scripts/measure_cms_accuracy.py - Empirical Accuracy & Analytical Bound Evaluator

Evaluates the hardware Count-Min Sketch (Lane 2 threat detector) against its
theoretical (epsilon, delta) concentration bounds:
  1. Replays curated CIC-IDS2017 subset traces (1,220 packets).
  2. Runs a 32,768-packet epoch collision stress test with 800 concurrent flows.
  3. Measures empirical estimation error: Delta = C_sketch - C_true.
  4. Confirms zero under-estimation (Delta >= 0 everywhere).
  5. Verifies empirical error is strictly bounded by ceil(epsilon * N).
  6. Computes empirical False Positive Rate (FPR) and False Negative Rate (FNR).

Usage:
  python scripts/measure_cms_accuracy.py [--json-out results.json]

Owner: Member B (Threat Detection Lane)
Standard library only (math, struct, json, pathlib, sys).
"""

import argparse
import json
import math
import os
import random
import struct
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add repository root to path
PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from model.detect import (
    DEFAULT_CMS_DEPTH,
    DEFAULT_EPOCH_N,
    DEFAULT_FANOUT_MAX,
    DEFAULT_FLOW_CMS_WIDTH,
    DEFAULT_HOST_CMS_WIDTH,
    DEFAULT_THRESH_FLOOD,
    DEFAULT_THRESH_SCAN,
    HASH_SEEDS_FLOW,
    HASH_SEEDS_HOST,
    RC_FLOOD,
    RC_NONE,
    RC_SCAN,
    CMSThreatDetector,
    CountMinSketch,
)

PCAP_DIR = PROJ_ROOT / "sim" / "vectors" / "cicids2017_subset"


@dataclass
class AnalyticalBounds:
    width: int
    depth: int
    epsilon: float
    delta: float
    theoretical_error_bound_n1220: int
    theoretical_error_bound_n32768: int


@dataclass
class ReplayExperimentResults:
    total_packets: int
    distinct_flows: int
    distinct_hosts: int
    under_estimation_violations: int
    flow_max_error: int
    flow_max_error_bound: int
    host_max_error: int
    host_max_error_bound: int
    benign_total: int
    benign_false_alarms: int
    fpr_percent: float
    synflood_total: int
    synflood_detected: int
    synflood_trigger_pkt: int
    portscan_total: int
    portscan_detected: int
    portscan_trigger_probe: int
    fnr_percent: float
    accuracy_percent: float


@dataclass
class StressExperimentResults:
    total_packets: int
    background_flows: int
    under_estimation_violations: int
    flow_max_error: int
    flow_max_error_bound: int
    host_max_error: int
    host_max_error_bound: int
    flood_detected: bool
    scan_detected: bool
    innocent_hosts_tested: int
    innocent_false_alarms: int
    fpr_percent: float


def compute_analytical_bounds(width: int, depth: int) -> AnalyticalBounds:
    """Computes standard Count-Min Sketch (epsilon, delta) parameters."""
    eps = math.e / width
    delta = (math.e / width) ** depth
    bound_1220 = math.ceil(eps * 1220)
    bound_32768 = math.ceil(eps * DEFAULT_EPOCH_N)
    return AnalyticalBounds(
        width=width,
        depth=depth,
        epsilon=eps,
        delta=delta,
        theoretical_error_bound_n1220=bound_1220,
        theoretical_error_bound_n32768=bound_32768,
    )


def parse_pcap_packets(pcap_path: Path) -> List[Dict[str, int]]:
    """Extracts IPv4/L4 header 5-tuples from raw binary PCAP file."""
    packets = []
    with open(pcap_path, "rb") as f:
        ghdr = f.read(24)
        magic, maj, minv, tz, sigf, snap, link = struct.unpack("<IHHiIII", ghdr)
        assert magic == 0xA1B2C3D4, f"Invalid PCAP magic: {magic:#x}"

        while True:
            rec_hdr = f.read(16)
            if not rec_hdr or len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, caplen, wirelen = struct.unpack("<IIII", rec_hdr)
            frame = f.read(caplen)

            # Ethernet II
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type == 0x0800:
                ip_hdr = frame[14:34]
                ver_ihl, dscp, tot_len, ident, flags_frag, ttl, proto, chk, s_ip, d_ip = struct.unpack(
                    "!BBHHHBBHII", ip_hdr
                )
                l4_data = frame[34:]
                s_port, d_port = struct.unpack("!HH", l4_data[:4])
                packets.append({
                    "src_ip": s_ip,
                    "dst_ip": d_ip,
                    "src_port": s_port,
                    "dst_port": d_port,
                    "protocol": proto,
                })
    return packets


def evaluate_cicids2017_replay(
    flow_bounds: AnalyticalBounds, host_bounds: AnalyticalBounds
) -> ReplayExperimentResults:
    """Replays cicids2017_subset PCAP files, measuring exact counter error."""
    detector = CMSThreatDetector(
        thresh_flood=DEFAULT_THRESH_FLOOD,
        thresh_scan=DEFAULT_THRESH_SCAN,
        fanout_max=DEFAULT_FANOUT_MAX,
        epoch_n=DEFAULT_EPOCH_N,
    )

    true_flow_counts = defaultdict(int)
    true_host_counts = defaultdict(int)

    traces = [
        ("benign.pcap", "benign"),
        ("synflood.pcap", "synflood"),
        ("portscan.pcap", "portscan"),
        ("signature.pcap", "signature"),
    ]

    total_pkts = 0
    under_est_violations = 0
    max_flow_err = 0
    max_host_err = 0

    benign_total = 0
    benign_fa = 0

    synflood_total = 0
    synflood_detected = 0
    synflood_trigger_pkt = None

    portscan_total = 0
    portscan_detected = 0
    portscan_trigger_probe = None

    for filename, trace_type in traces:
        pcap_file = PCAP_DIR / filename
        assert pcap_file.exists(), f"Trace file {pcap_file} missing!"
        pkts = parse_pcap_packets(pcap_file)

        for idx, pkt in enumerate(pkts, 1):
            total_pkts += 1
            src_ip = pkt["src_ip"]
            dst_ip = pkt["dst_ip"]
            dst_port = pkt["dst_port"]
            proto = pkt["protocol"]

            # Key definitions matching detect.py and count_min_sketch.v
            flow_key = ((src_ip & 0xFFFFFFFF) ^ ((dst_port & 0xFFFF) * 0x85EBCA6B)) & 0xFFFFFFFF
            host_key = src_ip & 0xFFFFFFFF

            true_flow_counts[flow_key] += 1
            true_host_counts[host_key] += 1

            fail, reason, c_flow, c_host = detector.process_packet(src_ip, dst_ip, dst_port, proto)

            # Invariant check: C_sketch >= C_true
            t_flow = true_flow_counts[flow_key]
            t_host = true_host_counts[host_key]

            if c_flow < t_flow:
                under_est_violations += 1
            if c_host < t_host:
                under_est_violations += 1

            err_flow = c_flow - t_flow
            err_host = c_host - t_host
            if err_flow > max_flow_err:
                max_flow_err = err_flow
            if err_host > max_host_err:
                max_host_err = err_host

            # Classification tracking
            if trace_type == "benign":
                benign_total += 1
                if fail or reason != RC_NONE:
                    benign_fa += 1
            elif trace_type == "synflood":
                synflood_total += 1
                if fail and reason == RC_FLOOD:
                    synflood_detected += 1
                    if synflood_trigger_pkt is None:
                        synflood_trigger_pkt = idx
            elif trace_type == "portscan":
                portscan_total += 1
                if fail and reason == RC_SCAN:
                    portscan_detected += 1
                    if portscan_trigger_probe is None:
                        portscan_trigger_probe = idx

    distinct_flows = len(true_flow_counts)
    distinct_hosts = len(true_host_counts)

    fpr = (benign_fa / benign_total * 100.0) if benign_total > 0 else 0.0

    # FNR: any attack that should have been detected by CMS but wasn't
    # In synflood, packets 512..600 (89 packets) must trigger RC_FLOOD
    expected_flood_hits = max(0, 600 - DEFAULT_THRESH_FLOOD + 1)
    expected_scan_hits = max(0, 450 - DEFAULT_THRESH_SCAN + 1)
    actual_flood_hits = synflood_detected
    actual_scan_hits = portscan_detected
    total_expected_attack_alerts = expected_flood_hits + expected_scan_hits
    total_actual_attack_alerts = actual_flood_hits + actual_scan_hits
    fnr = (
        (1.0 - (total_actual_attack_alerts / total_expected_attack_alerts)) * 100.0
        if total_expected_attack_alerts > 0
        else 0.0
    )
    accuracy = 100.0 - fpr - fnr

    return ReplayExperimentResults(
        total_packets=total_pkts,
        distinct_flows=distinct_flows,
        distinct_hosts=distinct_hosts,
        under_estimation_violations=under_est_violations,
        flow_max_error=max_flow_err,
        flow_max_error_bound=flow_bounds.theoretical_error_bound_n1220,
        host_max_error=max_host_err,
        host_max_error_bound=host_bounds.theoretical_error_bound_n1220,
        benign_total=benign_total,
        benign_false_alarms=benign_fa,
        fpr_percent=fpr,
        synflood_total=synflood_total,
        synflood_detected=synflood_detected,
        synflood_trigger_pkt=synflood_trigger_pkt or 0,
        portscan_total=portscan_total,
        portscan_detected=portscan_detected,
        portscan_trigger_probe=portscan_trigger_probe or 0,
        fnr_percent=fnr,
        accuracy_percent=accuracy,
    )


def evaluate_epoch_collision_stress(
    flow_bounds: AnalyticalBounds, host_bounds: AnalyticalBounds
) -> StressExperimentResults:
    """Simulates an entire epoch (N=32,768) with 800 background flows sharing tables."""
    random.seed(0x5EED0001)

    detector = CMSThreatDetector(
        thresh_flood=DEFAULT_THRESH_FLOOD,
        thresh_scan=DEFAULT_THRESH_SCAN,
        fanout_max=DEFAULT_FANOUT_MAX,
        epoch_n=DEFAULT_EPOCH_N,
    )

    true_flow_counts = defaultdict(int)
    true_host_counts = defaultdict(int)

    # 1. 800 background normal flows (random hosts, random ports, volume 1..30)
    bg_flows = []
    for f_idx in range(800):
        s_ip = 0x0A000000 | (random.randint(1, 254) << 8) | random.randint(1, 254)
        d_port = random.choice([80, 443, 22, 53, 8080, 51001, 51002, 51010])
        count = random.randint(5, 30)
        bg_flows.append((s_ip, d_port, count))

    # 2. Targeted attacker: SYN flood (1 host, 1 port, 1,200 packets)
    flood_src = 0x0A010199
    flood_port = 80
    flood_count = 1200

    # 3. Targeted attacker: Port scanner (1 host, 500 distinct ports, 1 packet each)
    scan_src = 0x0A010288
    scan_ports = list(range(1024, 1524))

    # 4. Innocent busy host (sends 150 packets spread over 30 ports)
    innocent_src = 0x0A010377
    innocent_pkts = [(innocent_src, 1000 + (p % 30)) for p in range(150)]

    # Assemble packet stream and shuffle
    stream = []
    for s_ip, d_port, count in bg_flows:
        stream.extend([(s_ip, d_port)] * count)
    stream.extend([(flood_src, flood_port)] * flood_count)
    for p in scan_ports:
        stream.append((scan_src, p))
    stream.extend(innocent_pkts)

    # Pad or trim to exact epoch length 32,768
    if len(stream) < DEFAULT_EPOCH_N:
        pad_needed = DEFAULT_EPOCH_N - len(stream)
        for i in range(pad_needed):
            s_ip = 0x0A090000 | (i & 0xFFFF)
            stream.append((s_ip, 80))
    else:
        stream = stream[:DEFAULT_EPOCH_N]

    random.shuffle(stream)

    under_est_violations = 0
    max_flow_err = 0
    max_host_err = 0
    flood_detected = False
    scan_detected = False
    innocent_fa = 0

    for s_ip, d_port in stream:
        flow_key = ((s_ip & 0xFFFFFFFF) ^ ((d_port & 0xFFFF) * 0x85EBCA6B)) & 0xFFFFFFFF
        host_key = s_ip & 0xFFFFFFFF

        true_flow_counts[flow_key] += 1
        true_host_counts[host_key] += 1

        fail, reason, c_flow, c_host = detector.process_packet(s_ip, 0xC0A80101, d_port, 6)

        t_flow = true_flow_counts[flow_key]
        t_host = true_host_counts[host_key]

        if c_flow < t_flow:
            under_est_violations += 1
        if c_host < t_host:
            under_est_violations += 1

        err_flow = c_flow - t_flow
        err_host = c_host - t_host
        if err_flow > max_flow_err:
            max_flow_err = err_flow
        if err_host > max_host_err:
            max_host_err = err_host

        if s_ip == flood_src and fail and reason == RC_FLOOD:
            flood_detected = True
        if s_ip == scan_src and fail and reason == RC_SCAN:
            scan_detected = True
        if s_ip == innocent_src and (fail or reason != RC_NONE):
            innocent_fa += 1

    return StressExperimentResults(
        total_packets=len(stream),
        background_flows=len(bg_flows),
        under_estimation_violations=under_est_violations,
        flow_max_error=max_flow_err,
        flow_max_error_bound=flow_bounds.theoretical_error_bound_n32768,
        host_max_error=max_host_err,
        host_max_error_bound=host_bounds.theoretical_error_bound_n32768,
        flood_detected=flood_detected,
        scan_detected=scan_detected,
        innocent_hosts_tested=1,
        innocent_false_alarms=innocent_fa,
        fpr_percent=0.0 if innocent_fa == 0 else 100.0,
    )


def print_report(
    flow_bounds: AnalyticalBounds,
    host_bounds: AnalyticalBounds,
    replay_res: ReplayExperimentResults,
    stress_res: StressExperimentResults,
) -> None:
    """Formats and prints the quantitative accuracy report to stdout."""
    print("=" * 76)
    print("LANE 2 THREAT DETECTION: COUNT-MIN SKETCH ACCURACY & SIZING REPORT")
    print("=" * 76)

    print("\n[1] Theoretical Analytical Bounds (Markov Inequality Guarantee)")
    print(f"  * Flow Sketch (Flood Detection):")
    print(f"      - Sizing              : w = {flow_bounds.width}, k = {flow_bounds.depth} (4 x RAMB36)")
    print(f"      - Error Parameter eps : {flow_bounds.epsilon:.6f} ({flow_bounds.epsilon*100:.3f}%)")
    print(f"      - Failure Prob delta  : {flow_bounds.delta:.3e}")
    print(f"      - Max Bound @ N=1,220 : <= {flow_bounds.theoretical_error_bound_n1220} packets")
    print(f"      - Max Bound @ N=32,768: <= {flow_bounds.theoretical_error_bound_n32768} packets")
    print(f"  * Host Sketch (Scan Detection):")
    print(f"      - Sizing              : w = {host_bounds.width}, k = {host_bounds.depth} (2 x RAMB36)")
    print(f"      - Error Parameter eps : {host_bounds.epsilon:.6f} ({host_bounds.epsilon*100:.3f}%)")
    print(f"      - Failure Prob delta  : {host_bounds.delta:.3e}")
    print(f"      - Max Bound @ N=1,220 : <= {host_bounds.theoretical_error_bound_n1220} packets")
    print(f"      - Max Bound @ N=32,768: <= {host_bounds.theoretical_error_bound_n32768} packets")

    print("\n[2] Empirical Results: CIC-IDS2017 Curated Trace Replay (N = 1,220)")
    print(f"  * Total Packets Evaluated     : {replay_res.total_packets}")
    print(f"  * Distinct Flows / Hosts      : {replay_res.distinct_flows} flows / {replay_res.distinct_hosts} hosts")
    print(f"  * Under-Estimation Violations : {replay_res.under_estimation_violations} (Must be exactly 0)")
    print(f"  * Flow Sketch Max Error       : {replay_res.flow_max_error} pkts (Bound: <= {replay_res.flow_max_error_bound})")
    print(f"  * Host Sketch Max Error       : {replay_res.host_max_error} pkts (Bound: <= {replay_res.host_max_error_bound})")
    print(f"  * Benign False Positives      : {replay_res.benign_false_alarms}/{replay_res.benign_total} (FPR = {replay_res.fpr_percent:.2f}%)")
    print(f"  * SYN Flood Trigger Packet    : Packet {replay_res.synflood_trigger_pkt} (Exact Threshold 512)")
    print(f"  * Port Scan Trigger Probe     : Probe {replay_res.portscan_trigger_probe} (Exact Threshold 384)")
    print(f"  * False Negative Rate (FNR)   : {replay_res.fnr_percent:.2f}%")
    print(f"  * Overall Detection Accuracy  : {replay_res.accuracy_percent:.2f}%")

    print("\n[3] Empirical Results: High-Load Collision Stress Test (N = 32,768, Full Epoch)")
    print(f"  * Total Stream Packets (Epoch): {stress_res.total_packets}")
    print(f"  * Concurrent Background Flows : {stress_res.background_flows}")
    print(f"  * Under-Estimation Violations : {stress_res.under_estimation_violations} (Must be exactly 0)")
    print(f"  * Flow Sketch Max Error       : {stress_res.flow_max_error} pkts (Bound: <= {stress_res.flow_max_error_bound})")
    print(f"  * Host Sketch Max Error       : {stress_res.host_max_error} pkts (Bound: <= {stress_res.host_max_error_bound})")
    print(f"  * Volumetric Flood Detected   : {stress_res.flood_detected}")
    print(f"  * Port Scan Detected          : {stress_res.scan_detected}")
    print(f"  * Innocent Host False Alarms  : {stress_res.innocent_false_alarms} (FPR = {stress_res.fpr_percent:.2f}%)")

    print("\n" + "=" * 76)
    all_passed = (
        replay_res.under_estimation_violations == 0
        and stress_res.under_estimation_violations == 0
        and replay_res.flow_max_error <= replay_res.flow_max_error_bound
        and replay_res.host_max_error <= replay_res.host_max_error_bound
        and stress_res.flow_max_error <= stress_res.flow_max_error_bound
        and stress_res.host_max_error <= stress_res.host_max_error_bound
        and replay_res.fpr_percent == 0.0
        and replay_res.fnr_percent == 0.0
        and stress_res.innocent_false_alarms == 0
    )
    if all_passed:
        print("--> PASS: Empirical accuracy strictly matches or outperforms analytical bounds.")
        print("--> PHASE III EXIT REQUIREMENT SATISFIED.")
    else:
        print("--> FAIL: Discrepancy observed between empirical measurements and bounds.")
    print("=" * 76)


def main():
    parser = argparse.ArgumentParser(description="Evaluate Count-Min Sketch accuracy vs analytical bounds")
    parser.add_argument("--json-out", type=Path, default=None, help="Save evaluation metrics to JSON file")
    args = parser.parse_args()

    flow_bounds = compute_analytical_bounds(DEFAULT_FLOW_CMS_WIDTH, DEFAULT_CMS_DEPTH)
    host_bounds = compute_analytical_bounds(DEFAULT_HOST_CMS_WIDTH, DEFAULT_CMS_DEPTH)

    replay_res = evaluate_cicids2017_replay(flow_bounds, host_bounds)
    stress_res = evaluate_epoch_collision_stress(flow_bounds, host_bounds)

    print_report(flow_bounds, host_bounds, replay_res, stress_res)

    if args.json_out:
        data = {
            "flow_bounds": asdict(flow_bounds),
            "host_bounds": asdict(host_bounds),
            "replay_results": asdict(replay_res),
            "stress_results": asdict(stress_res),
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"\nWrote JSON accuracy metrics to: {args.json_out}")


if __name__ == "__main__":
    main()
