"""
model/detect.py - Threat Detection Lane (Lane 2) Reference & Sizing Model

Bit-exact Python specification twin for:
  - rtl/detect/count_min_sketch.v
  - rtl/detect/hash_functions.v
  - rtl/detect/protocol_validator.v
  - rtl/detect/cam_matcher.v

Owner: Member B
Reference Documents:
  - docs/Member B/Member-B-Threat-Detection-Lane.md
  - docs/Member B/Member-B-Theory-Guide.md
  - docs/PROJECT-TASK-BOARD.md (Tasks B2, B3, B5, B6)
  - rtl/control/reason_codes.vh

How the CMS Distinguishes RC_FLOOD (4'h5) vs RC_SCAN (4'h6):
------------------------------------------------------------
A single counter on source IP cannot tell a flood from a scan because both
generate a high aggregate packet count. However, their spatial distribution
across destination ports is opposite:
  1. RC_FLOOD (Concentration Anomaly):
     - An attacker floods a specific victim service (e.g. HTTP port 80, or
       the PQC handshake port 51001).
     - Flow sketch C_flow(src_ip, dst_port) is HIGH (>= THRESH_FLOOD).
     - Reason: RC_FLOOD (4'h5).
  2. RC_SCAN (Spread / Dispersion Anomaly):
     - An attacker probes many distinct ports (ports 1, 2, 3...) looking for
       vulnerabilities.
     - For any single port, C_flow(src_ip, dst_port) is LOW (<= THRESH_FANOUT_MAX,
       e.g. 1 to 4 packets).
     - But aggregate host sketch C_host(src_ip) is HIGH (>= THRESH_SCAN).
     - High host volume + low per-port concentration = Port Scan!
     - Reason: RC_SCAN (4'h6).

Hardware Architecture & BRAM Sizing (ZedBoard XC7Z020 @ 100 MHz):
-----------------------------------------------------------------
  - Target BRAM Budget: ~11.5 of 140 36Kb Block RAMs (414 Kb total)
  - Dual-Sketch Parallel Architecture:
      * Flow Sketch (Flood): w = 2048, k = 4, 16-bit saturating counters
        Key: (src_ip, dst_port) -> 4 x RAMB36E1 (34.8% budget)
        epsilon = e / 2048 = 0.001327 (0.133%), delta = e^(-4) = 0.0183 (1.83%)
      * Host Sketch (Scan):  w = 1024, k = 4, 16-bit saturating counters
        Key: (src_ip)           -> 2 x RAMB36E1 (17.4% budget)
        epsilon = e / 1024 = 0.002654 (0.265%), delta = e^(-4) = 0.0183 (1.83%)
      * Total BRAM: 6.0 of 11.5 RAMB36 tiles (52.2% of Detect Lane budget).
  - Epoch Window: N = 32,768 packets (2^15)
  - Max Collision Over-estimate:
      * Flow Sketch: ceil(epsilon * N) = 44 packets (98.17% confidence)
      * Host Sketch: ceil(epsilon * N) = 87 packets (98.17% confidence)
  - Saturating Counters: Counters saturate and hold at 16'hFFFF (65,535); NEVER wrap.
  - Verdict Latency: Fixed 2 clock cycles after eof for drop_engine synchronization.
"""

import math
import random
import sys
from typing import Dict, List, Optional, Tuple


# =====================================================================
# Reason Codes (from rtl/control/reason_codes.vh)
# =====================================================================

RC_NONE                 = 0x0  # No failure; packet passes
RC_CRC_FAIL             = 0x1  # Member A: link corruption
RC_FRAME_TIMEOUT        = 0x2  # Member A: truncated frame
RC_MALFORMED            = 0x3  # Member B: protocol_validator invalid header
RC_SIGNATURE            = 0x4  # Member B: cam_matcher known signature
RC_FLOOD                = 0x5  # Member B: count_min_sketch rate anomaly
RC_SCAN                 = 0x6  # Member B: count_min_sketch spread anomaly
RC_BAD_TAG              = 0x7  # Member D: poly1305 auth failure
RC_HANDSHAKE_KEY_INVALID= 0x8  # Member C: mlkem_top key structural failure


# =====================================================================
# Sizing & Sizing Parameters
# =====================================================================

DEFAULT_FLOW_CMS_WIDTH = 2048     # w = 2^11 entries for flow/port sketch
DEFAULT_HOST_CMS_WIDTH = 1024     # w = 2^10 entries for host aggregate sketch
DEFAULT_CMS_DEPTH      = 4        # k = 4 hash rows
DEFAULT_COUNTER_BITS   = 16       # 16-bit counters (0..65535)
MAX_COUNTER_VAL        = (1 << DEFAULT_COUNTER_BITS) - 1  # 65535 (0xFFFF)

DEFAULT_EPOCH_N        = 32768    # N = 2^15 packets per epoch
XC7Z020_BRAM36_BUDGET  = 11.5     # Allocated 36Kb BRAMs for Lane 2 memory

# Detection thresholds (calibrated against N = 32,768 packets & theoretical noise floors):
#   - Flow Sketch error bound: ceil(e/2048 * 32768) = 44 packets
#   - Host Sketch error bound: ceil(e/1024 * 32768) = 87 packets
#
# Calibration principles:
#   1. THRESH_FLOOD (512): 11.6x above the 44-packet flow noise ceiling.
#   2. THRESH_SCAN (384): 4.41x above the 87-packet host noise ceiling (>= 4x 87).
#      Guarantees unrelated background collisions cannot inflate an innocent host past threshold.
#   3. FANOUT_MAX (96): Well above the 44-packet flow noise ceiling (> 2x 44).
#      Prevents hash collisions from inflating true 1-2 probe counts above the fanout gate,
#      which would otherwise blind the scanner detector during a busy epoch.
DEFAULT_THRESH_FLOOD   = 512      # >= 512 pkts on (src_ip, dst_port)
DEFAULT_THRESH_SCAN    = 384      # >= 384 pkts from host in epoch
DEFAULT_FANOUT_MAX     = 96       # <= 96 pkts on current port indicates spread scan


# 2-Universal 32-bit multiply-shift hash constants: (a_j, b_j)
HASH_SEEDS_FLOW: List[Tuple[int, int]] = [
    (0x5BD1E995, 0x1B873593),
    (0x85EBCA6B, 0x48BB74C5),
    (0xC2B2AE35, 0x9E3779B9),
    (0x7FEB352D, 0x27D4EB2F),
]

HASH_SEEDS_HOST: List[Tuple[int, int]] = [
    (0x21F0AAAD, 0x7322F225),
    (0x3B643793, 0x1A23D457),
    (0x992B5F1B, 0x5678ABCD),
    (0x4C871A31, 0x9ABCDEF1),
]


# =====================================================================
# Sizing & Analytical Bound Computations
# =====================================================================

def calc_cms_sizing(w: int, k: int, n_epoch: int) -> Dict[str, float]:
    """Computes theoretical error parameters and BRAM resources for a sketch."""
    epsilon = math.e / w
    delta = math.exp(-k)
    max_error_pkts = math.ceil(epsilon * n_epoch)
    confidence_pct = (1.0 - delta) * 100.0

    # In Xilinx 7-Series, 1 BRAM tile = 1 RAMB36E1 or 2 x RAMB18E1 (18,432 bits each).
    row_bits = w * DEFAULT_COUNTER_BITS
    if row_bits <= 18432:
        ramb36_per_row = 0.5  # Fits in 1 x RAMB18E1
    else:
        ramb36_per_row = math.ceil(row_bits / 36864)
    total_ramb36 = k * ramb36_per_row
    bram_budget_pct = (total_ramb36 / XC7Z020_BRAM36_BUDGET) * 100.0

    return {
        "width": w,
        "depth": k,
        "epoch_n": n_epoch,
        "epsilon": epsilon,
        "epsilon_pct": epsilon * 100.0,
        "delta": delta,
        "delta_pct": delta * 100.0,
        "confidence_pct": confidence_pct,
        "max_error_packets": max_error_pkts,
        "total_ramb36": total_ramb36,
        "bram_budget_pct": bram_budget_pct,
    }


# =====================================================================
# Hardware-Exact 2-Universal Hash Function
# =====================================================================

def hash_k(
    key: int,
    row_idx: int,
    width: int,
    seeds: Optional[List[Tuple[int, int]]] = None,
) -> int:
    """
    Hardware-exact 2-universal hash function:
      h_j(x) = ((a_j * (x mod 2^32) + b_j) mod 2^32) >> (32 - m)

    Where m = log2(width). Single-cycle multiply-add in RTL.
    """
    if seeds is None:
        seeds = HASH_SEEDS_FLOW
    if row_idx >= len(seeds):
        raise ValueError(f"Row index {row_idx} exceeds available seeds ({len(seeds)})")

    a, b = seeds[row_idx]
    m = int(math.log2(width))

    val = ((a * (key & 0xFFFFFFFF)) + b) & 0xFFFFFFFF
    idx = (val >> (32 - m)) & (width - 1)
    return idx


# =====================================================================
# Bit-Exact Count-Min Sketch Table Primitive
# =====================================================================

class CountMinSketch:
    """
    Hardware-accurate Count-Min Sketch table primitive with:
      - k rows x w columns of 16-bit saturating counters.
      - Saturate-and-hold at 16'hFFFF (65,535); zero counter wrap-around.
      - Automatic synchronous reset at epoch boundary (N packets).
    """

    def __init__(
        self,
        width: int = DEFAULT_FLOW_CMS_WIDTH,
        depth: int = DEFAULT_CMS_DEPTH,
        epoch_n: int = DEFAULT_EPOCH_N,
        seeds: Optional[List[Tuple[int, int]]] = None,
    ):
        assert (width & (width - 1)) == 0, "Width must be a power of 2 for bitmask indexing"
        self.width = width
        self.depth = depth
        self.epoch_n = epoch_n
        self.seeds = seeds if seeds is not None else HASH_SEEDS_FLOW

        self.table: List[List[int]] = [[0] * self.width for _ in range(self.depth)]
        self.epoch_pkt_count: int = 0
        self.total_epochs_completed: int = 0

    def reset_epoch(self) -> None:
        """Flushes sketch counters at epoch boundary."""
        for j in range(self.depth):
            for i in range(self.width):
                self.table[j][i] = 0
        self.epoch_pkt_count = 0
        self.total_epochs_completed += 1

    def update(self, key: int) -> Tuple[int, bool]:
        """
        Updates counters for key across all k rows.

        Returns:
            Tuple of (min_count_after_update, epoch_reset_occurred)
        """
        min_val = MAX_COUNTER_VAL
        for j in range(self.depth):
            idx = hash_k(key, j, self.width, self.seeds)
            curr = self.table[j][idx]

            # Saturate-and-hold: never wrap past 16'hFFFF
            if curr < MAX_COUNTER_VAL:
                curr += 1
                self.table[j][idx] = curr

            if curr < min_val:
                min_val = curr

        self.epoch_pkt_count += 1
        epoch_reset = False
        if self.epoch_pkt_count >= self.epoch_n:
            self.reset_epoch()
            epoch_reset = True

        return min_val, epoch_reset

    def query(self, key: int) -> int:
        """Point estimate query without incrementing."""
        min_val = MAX_COUNTER_VAL
        for j in range(self.depth):
            idx = hash_k(key, j, self.width, self.seeds)
            val = self.table[j][idx]
            if val < min_val:
                min_val = val
        return min_val


# =====================================================================
# Dual-Sketch Threat Detection Engine (Distinguishes Flood vs Scan)
# =====================================================================

class CMSThreatDetector:
    """
    Dual-Sketch Threat Detection Engine for Lane 2.

    Distinguishes RC_FLOOD from RC_SCAN using two parallel sketches:
      1. Flow Sketch (w=2048, k=4): Key = (src_ip, dst_port).
         Measures traffic volume concentrated on a specific target port/service.
      2. Host Sketch (w=1024, k=4): Key = src_ip.
         Measures aggregate volume from a single source across all ports.

    Verdict Decision Matrix:
      - c_flow >= THRESH_FLOOD                               -> RC_FLOOD (4'h5)
      - c_host >= THRESH_SCAN and c_flow <= THRESH_FANOUT_MAX -> RC_SCAN  (4'h6)
      - otherwise                                             -> RC_NONE  (4'h0)

    Hardware Cost:
      - Flow Sketch: 4 x RAMB36E1
      - Host Sketch: 2 x RAMB36E1
      - Total: 6.0 RAMB36 out of 11.5 budget (52.2%)
      - Latency: 2 clock cycles after eof.
    """

    def __init__(
        self,
        thresh_flood: int = DEFAULT_THRESH_FLOOD,
        thresh_scan: int = DEFAULT_THRESH_SCAN,
        fanout_max: int = DEFAULT_FANOUT_MAX,
        epoch_n: int = DEFAULT_EPOCH_N,
    ):
        self.thresh_flood = thresh_flood
        self.thresh_scan = thresh_scan
        self.fanout_max = fanout_max
        self.epoch_n = epoch_n

        # Two sketches in parallel
        self.flow_sketch = CountMinSketch(
            width=DEFAULT_FLOW_CMS_WIDTH,
            depth=DEFAULT_CMS_DEPTH,
            epoch_n=epoch_n,
            seeds=HASH_SEEDS_FLOW,
        )
        self.host_sketch = CountMinSketch(
            width=DEFAULT_HOST_CMS_WIDTH,
            depth=DEFAULT_CMS_DEPTH,
            epoch_n=epoch_n,
            seeds=HASH_SEEDS_HOST,
        )

    def process_packet(
        self, src_ip: int, dst_ip: int, dst_port: int, protocol: int = 6
    ) -> Tuple[bool, int, int, int]:
        """
        Evaluates one parsed packet arriving from the packet bus.

        Args:
            src_ip: 32-bit IPv4 source address
            dst_ip: 32-bit IPv4 destination address
            dst_port: 16-bit L4 destination port
            protocol: IP protocol (6 = TCP, 17 = UDP)

        Returns:
            Tuple of:
              (fail: bool, reason_code: int, c_flow: int, c_host: int)
        """
        # Form composite flow key: (src_ip, dst_port)
        flow_key = ((src_ip & 0xFFFFFFFF) ^ ((dst_port & 0xFFFF) * 0x85EBCA6B)) & 0xFFFFFFFF
        host_key = src_ip & 0xFFFFFFFF

        # Update both sketches (both execute in parallel in RTL)
        c_flow, _ = self.flow_sketch.update(flow_key)
        c_host, _ = self.host_sketch.update(host_key)

        # Classification decision
        if c_flow >= self.thresh_flood:
            # Concentrated high-rate flood on single target/port
            return True, RC_FLOOD, c_flow, c_host
        elif c_host >= self.thresh_scan and c_flow <= self.fanout_max:
            # High aggregate traffic from host, but low per-port concentration (port scan)
            return True, RC_SCAN, c_flow, c_host
        else:
            return False, RC_NONE, c_flow, c_host


# =====================================================================
# Self-Test and Validation Suite
# =====================================================================

def run_self_test() -> bool:
    """Rigorous self-test verifying sizing, invariants, saturation, and classification."""
    print("====================================================================")
    print("Threat Detection Lane (Lane 2) -- CMS Dual-Sketch Sizing & Model")
    print("====================================================================")

    # -----------------------------------------------------------------
    # Test 1: Sizing Math & BRAM Budget
    # -----------------------------------------------------------------
    flow_sz = calc_cms_sizing(DEFAULT_FLOW_CMS_WIDTH, DEFAULT_CMS_DEPTH, DEFAULT_EPOCH_N)
    host_sz = calc_cms_sizing(DEFAULT_HOST_CMS_WIDTH, DEFAULT_CMS_DEPTH, DEFAULT_EPOCH_N)
    total_bram = flow_sz["total_ramb36"] + host_sz["total_ramb36"]

    print("\n[1] Dual-Sketch Sizing & Memory Footprint:")
    print(f"    Flow Sketch (Flood): w={flow_sz['width']}, k={flow_sz['depth']} -> {flow_sz['total_ramb36']} RAMB36, max error {flow_sz['max_error_packets']} pkts (ε={flow_sz['epsilon_pct']:.3f}%)")
    print(f"    Host Sketch (Scan) : w={host_sz['width']}, k={host_sz['depth']} -> {host_sz['total_ramb36']} RAMB36, max error {host_sz['max_error_packets']} pkts (ε={host_sz['epsilon_pct']:.3f}%)")
    print(f"    Total BRAM Usage   : {total_bram:.1f} of {XC7Z020_BRAM36_BUDGET} tiles ({total_bram / XC7Z020_BRAM36_BUDGET * 100:.1f}%)")
    assert total_bram <= XC7Z020_BRAM36_BUDGET, "Exceeded Lane 2 BRAM budget!"
    print("  --> PASS: Dual-sketch fits comfortably inside BRAM budget (52.2%).")

    # -----------------------------------------------------------------
    # Test 2: Saturating Counter Behavior (70,000 increments)
    # -----------------------------------------------------------------
    print("\n[2] Saturating Counter Hold Test (70,000 updates on single flow):")
    cms_sat = CountMinSketch(width=128, depth=4, epoch_n=100000)
    test_key = 0x0A000001
    for _ in range(70000):
        cms_sat.update(test_key)

    val = cms_sat.query(test_key)
    print(f"    Counter value: {val} (hex: 0x{val:04X})")
    assert val == MAX_COUNTER_VAL, f"Counter wrapped! Expected {MAX_COUNTER_VAL}, got {val}"
    print("  --> PASS: Counter saturates-and-holds at 65535; zero wrap-around.")

    # -----------------------------------------------------------------
    # Test 3: Zero Under-Estimation Invariant & Error Bound on Epoch
    # -----------------------------------------------------------------
    print(f"\n[3] Invariant Test over Epoch (N = {DEFAULT_EPOCH_N}):")
    cms = CountMinSketch(width=DEFAULT_FLOW_CMS_WIDTH, depth=DEFAULT_CMS_DEPTH, epoch_n=DEFAULT_EPOCH_N + 1000)

    ground_truth: Dict[int, int] = {}
    stream: List[int] = []

    flood_ip = 0xC0A80164
    ground_truth[flood_ip] = 1500
    stream.extend([flood_ip] * 1500)

    for i in range(10):
        med_ip = 0x0A010000 | i
        ground_truth[med_ip] = 200
        stream.extend([med_ip] * 200)

    for i in range(DEFAULT_EPOCH_N - len(stream)):
        bg_ip = 0xAC100000 | i
        ground_truth[bg_ip] = 1
        stream.append(bg_ip)

    for pkt_key in stream:
        cms.update(pkt_key)

    under_est_count = 0
    max_observed_error = 0
    for key, actual in ground_truth.items():
        est = cms.query(key)
        err = est - actual
        if est < actual:
            under_est_count += 1
        if err > max_observed_error:
            max_observed_error = err

    print(f"    Under-estimation Violations : {under_est_count} (must be 0)")
    print(f"    Max Observed Error          : {max_observed_error} pkts (Bound: {flow_sz['max_error_packets']})")
    assert under_est_count == 0, "CRITICAL: CMS under-estimated!"
    assert max_observed_error <= flow_sz["max_error_packets"], "Observed error exceeded analytical bound!"
    print("  --> PASS: Zero under-estimation, maximum error strictly bounded.")

    # -----------------------------------------------------------------
    # Test 4: Heavy Concurrent Background Stress Test (800 flows, N=32,768)
    # -----------------------------------------------------------------
    print("\n[4] Heavy Background Collision Stress Test (N = 32,768 packets):")
    print("    Simulating 800 concurrent background flows sharing the exact same tables...")
    detector = CMSThreatDetector(
        thresh_flood=DEFAULT_THRESH_FLOOD,
        thresh_scan=DEFAULT_THRESH_SCAN,
        fanout_max=DEFAULT_FANOUT_MAX,
        epoch_n=DEFAULT_EPOCH_N,
    )

    rng = random.Random(1234)
    packets = []

    # 1. 800 background benign flows with varying packet volumes (20 to 45 pkts each)
    for i in range(800):
        src = 0x0A000000 | (i + 1)
        port = rng.choice([80, 443, 22, 53, 8080, 8443, 3306, 5432, 25, 110])
        count = rng.randint(20, 45)
        packets.extend([(src, 0xC0A80101, port, "bg")] * count)

    # 2. Port Scanner: probes 450 distinct destination ports with 1 packet each
    scan_src = 0x0B000001
    for p in range(1, 451):
        packets.append((scan_src, 0xC0A80101, p, "scan"))

    # 3. Volumetric Flooder: sends 700 packets to port 51001 (handshake port)
    flood_src = 0x0C000001
    for _ in range(700):
        packets.append((flood_src, 0xC0A80101, 51001, "flood"))

    # 4. 20 Innocent test hosts: 25 packets each on port 443
    innocent_srcs = [0x0D000000 | i for i in range(1, 21)]
    for isrc in innocent_srcs:
        for _ in range(25):
            packets.append((isrc, 0xC0A80101, 443, "innocent"))

    # 5. Filler packets to reach exactly N = 32,768 (100% capacity)
    rem = DEFAULT_EPOCH_N - len(packets)
    if rem > 0:
        for i in range(rem):
            packets.append((0x0E000000 | (i % 256), 0xC0A80101, 80, "filler"))

    assert len(packets) == DEFAULT_EPOCH_N, f"Epoch size mismatch: {len(packets)}"
    rng.shuffle(packets)

    scan_detected = False
    flood_detected = False
    innocent_false_alarms = 0
    bg_false_alarms = 0
    scanner_c_flow_observed = []
    innocent_c_host_observed = []

    for src, dst, port, label in packets:
        fail, reason, c_f, c_h = detector.process_packet(src, dst, port)
        if label == "scan":
            scanner_c_flow_observed.append(c_f)
            if fail and reason == RC_SCAN:
                scan_detected = True
        elif label == "flood":
            if fail and reason == RC_FLOOD:
                flood_detected = True
        elif label == "innocent":
            innocent_c_host_observed.append(c_h)
            if fail:
                innocent_false_alarms += 1
        elif label in ("bg", "filler"):
            if fail:
                bg_false_alarms += 1

    max_scanner_c_flow = max(scanner_c_flow_observed)
    max_innocent_c_host = max(innocent_c_host_observed)

    print(f"    Total Stream Packets in Epoch   : {len(packets)}")
    print(f"    Scanner C_flow Max Observed     : {max_scanner_c_flow} (True count: 1, Bound: {flow_sz['max_error_packets']}, Fanout_Max: {DEFAULT_FANOUT_MAX})")
    print(f"    Innocent C_host Max Observed    : {max_innocent_c_host} (True count: 25, Bound: {host_sz['max_error_packets']}, Thresh_Scan: {DEFAULT_THRESH_SCAN})")
    print(f"    Port Scanner Detected (RC_SCAN) : {scan_detected}")
    print(f"    Volumetric Flood Detected       : {flood_detected}")
    print(f"    Innocent Host False Alarms      : {innocent_false_alarms} (must be 0)")
    print(f"    Background Traffic False Alarms : {bg_false_alarms} (must be 0)")

    # Assertions for robust detection under collision noise
    assert max_scanner_c_flow > 8, f"Stress test failed to produce collision noise (got {max_scanner_c_flow})"
    assert max_scanner_c_flow <= DEFAULT_FANOUT_MAX, f"Scanner C_flow {max_scanner_c_flow} exceeded fanout_max {DEFAULT_FANOUT_MAX}"
    assert scan_detected, "Port scan missed due to collision noise!"
    assert flood_detected, "Volumetric flood missed!"
    assert innocent_false_alarms == 0, f"False alarm on innocent host! ({innocent_false_alarms})"
    assert bg_false_alarms == 0, f"False alarm on background traffic! ({bg_false_alarms})"

    print("  --> PASS: Under heavy collision noise, zero false alarms and zero evasions.")

    print("\n====================================================================")
    print("ALL Lane 2 Dual-Sketch checks PASSED.")
    print("====================================================================")
    return True


if __name__ == "__main__":
    success = run_self_test()
    sys.exit(0 if success else 1)
