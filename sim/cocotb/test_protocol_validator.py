"""
sim/cocotb/test_protocol_validator.py - Cocotb Testbench for Protocol Validator

Lane 2 (Threat Detection): rtl/detect/protocol_validator.v
Bit-exact verification against Python twin: model/detect.py (validate_protocol)

Three test layers (per .agents/skills/cocotb_bench.md):
  1. Hand-crafted vectors: all 17 cases from PROTOCOL_VALIDATOR_TEST_VECTORS.
  2. Randomised fuzzing: 250 randomized packet headers compared live to oracle.
  3. Edge cases & throughput: back-to-back streaming and reset verification.

Target: ZedBoard XC7Z020 @ 100 MHz (10 ns clock period)
Owner: Member B
"""

import os
import random
import sys

# Import the Python twin oracle live from repository root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

from model.detect import (
    PROTOCOL_VALIDATOR_TEST_VECTORS,
    RC_MALFORMED,
    RC_NONE,
    validate_protocol,
)


async def reset_dut(dut):
    """Applies synchronous active-high reset for 2 clock cycles."""
    dut.rst.value = 1
    dut.header_valid.value = 0
    dut.eth_type.value = 0
    dut.ip_version_ihl.value = 0
    dut.ip_protocol.value = 0
    dut.ip_total_length.value = 0
    dut.l4_src_port.value = 0
    dut.l4_dst_port.value = 0
    dut.l4_length.value = 0
    dut.tcp_flags.value = 0
    dut.payload_len.value = 0

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)


# =====================================================================
# Layer 1: Hand-Crafted Test Vectors (17 distinct hardware cases)
# =====================================================================

@cocotb.test()
async def test_protocol_validator_vectors(dut):
    """Verifies all 17 published test vectors against model/detect.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    for idx, vec in enumerate(PROTOCOL_VALIDATOR_TEST_VECTORS, 1):
        # 1. Query the live Python oracle
        oracle_fail, oracle_reason = validate_protocol(
            eth_type=vec["eth_type"],
            ip_version_ihl=vec["ip_version_ihl"],
            ip_protocol=vec["ip_protocol"],
            ip_total_length=vec["ip_total_length"],
            l4_src_port=vec["l4_src_port"],
            l4_dst_port=vec["l4_dst_port"],
            l4_length=vec["l4_length"],
            tcp_flags=vec["tcp_flags"],
            payload_len=vec["payload_len"],
        )

        assert oracle_fail == vec["exp_fail"], (
            f"Vector {idx} ({vec['name']}) oracle mismatch: expected {vec['exp_fail']}, got {oracle_fail}"
        )
        assert oracle_reason == vec["exp_reason"], (
            f"Vector {idx} ({vec['name']}) oracle reason mismatch: expected {vec['exp_reason']:#x}, got {oracle_reason:#x}"
        )

        # 2. Drive the RTL DUT at FallingEdge (setup time before RisingEdge)
        dut.eth_type.value = vec["eth_type"] & 0xFFFF
        dut.ip_version_ihl.value = vec["ip_version_ihl"] & 0xFF
        dut.ip_protocol.value = vec["ip_protocol"] & 0xFF
        dut.ip_total_length.value = vec["ip_total_length"] & 0xFFFF
        dut.l4_src_port.value = vec["l4_src_port"] & 0xFFFF
        dut.l4_dst_port.value = vec["l4_dst_port"] & 0xFFFF
        dut.l4_length.value = vec["l4_length"] & 0xFFFF
        dut.tcp_flags.value = vec["tcp_flags"] & 0xFF
        dut.payload_len.value = vec["payload_len"] & 0xFFFF
        dut.header_valid.value = 1

        # Clock edge: RTL registers inputs
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        dut.header_valid.value = 0

        # 3. Read outputs (verdict is valid on this cycle)
        got_valid = int(dut.verdict_valid.value)
        got_fail = int(dut.verdict_fail.value)
        got_reason = int(dut.verdict_reason.value)

        assert got_valid == 1, (
            f"Vector {idx} ({vec['name']}): verdict_valid was not asserted (got {got_valid})"
        )
        assert got_fail == (1 if vec["exp_fail"] else 0), (
            f"Vector {idx} ({vec['name']}): RTL fail {got_fail} != model {vec['exp_fail']}\n"
            f"  inputs: eth={vec['eth_type']:#06x}, ver_ihl={vec['ip_version_ihl']:#04x}, "
            f"proto={vec['ip_protocol']}, total_len={vec['ip_total_length']}"
        )
        assert got_reason == vec["exp_reason"], (
            f"Vector {idx} ({vec['name']}): RTL reason {got_reason:#x} != model {vec['exp_reason']:#x}"
        )

        # 4. Verify strobe clears on idle cycle
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        assert int(dut.verdict_valid.value) == 0, (
            f"Vector {idx}: verdict_valid did not auto-clear after 1-cycle strobe"
        )


# =====================================================================
# Layer 2: Randomised Fuzzing Agreement (250 trials vs Python oracle)
# =====================================================================

@cocotb.test()
async def test_protocol_validator_random_fuzz(dut):
    """Drives 250 randomized packets and checks bit-exact agreement with model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0xDEADBEEF)

    for trial in range(250):
        # 50% chance of building a nominally valid packet, 50% purely random
        if rng.random() < 0.5:
            eth_type = 0x0800
            ip_version_ihl = 0x45
            is_tcp = rng.choice([True, False])
            ip_proto = 6 if is_tcp else 17
            l4_src = rng.randint(1, 65535)
            l4_dst = rng.randint(1, 65535)
            l4_len = rng.choice([20, 24, 32]) if is_tcp else 8
            payload_l = rng.randint(0, 1400)
            ip_tot = 20 + l4_len + payload_l
            flags = rng.choice([0x02, 0x10, 0x12, 0x18, 0x11]) if is_tcp else 0

            # Inject random mutations
            mutation = rng.randint(0, 7)
            if mutation == 1:
                eth_type = rng.choice([0x0806, 0x86DD, 0x8100])
            elif mutation == 2:
                ip_version_ihl = rng.choice([0x65, 0x46, 0x44, 0x00])
            elif mutation == 3:
                ip_proto = rng.choice([1, 2, 47, 50])
            elif mutation == 4:
                if rng.choice([True, False]):
                    l4_src = 0
                else:
                    l4_dst = 0
            elif mutation == 5 and is_tcp:
                flags = rng.choice([0x03, 0x06, 0x00, 0x01])
            elif mutation == 6:
                ip_tot = max(0, ip_tot + rng.choice([-5, -1, 1, 10]))
        else:
            eth_type = rng.randint(0, 0xFFFF)
            ip_version_ihl = rng.randint(0, 0xFF)
            ip_proto = rng.randint(0, 0xFF)
            l4_src = rng.randint(0, 0xFFFF)
            l4_dst = rng.randint(0, 0xFFFF)
            l4_len = rng.randint(0, 0xFFFF)
            payload_l = rng.randint(0, 1500)
            ip_tot = rng.randint(0, 0xFFFF)
            flags = rng.randint(0, 0xFF)

        # Oracle evaluation
        exp_fail, exp_reason = validate_protocol(
            eth_type=eth_type,
            ip_version_ihl=ip_version_ihl,
            ip_protocol=ip_proto,
            ip_total_length=ip_tot,
            l4_src_port=l4_src,
            l4_dst_port=l4_dst,
            l4_length=l4_len,
            tcp_flags=flags,
            payload_len=payload_l,
        )

        # Drive RTL on FallingEdge
        dut.eth_type.value = eth_type
        dut.ip_version_ihl.value = ip_version_ihl
        dut.ip_protocol.value = ip_proto
        dut.ip_total_length.value = ip_tot
        dut.l4_src_port.value = l4_src
        dut.l4_dst_port.value = l4_dst
        dut.l4_length.value = l4_len
        dut.tcp_flags.value = flags
        dut.payload_len.value = payload_l
        dut.header_valid.value = 1

        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        dut.header_valid.value = 0

        # Sample registered outputs
        got_valid = int(dut.verdict_valid.value)
        got_fail = int(dut.verdict_fail.value)
        got_reason = int(dut.verdict_reason.value)

        assert got_valid == 1, f"Fuzz trial {trial}: verdict_valid was 0"
        assert got_fail == (1 if exp_fail else 0), (
            f"Fuzz trial {trial} mismatch: RTL fail={got_fail} != model fail={exp_fail}\n"
            f"  eth={eth_type:#06x}, ver_ihl={ip_version_ihl:#04x}, proto={ip_proto}, "
            f"src={l4_src}, dst={l4_dst}, l4_len={l4_len}, flags={flags:#04x}, "
            f"total_len={ip_tot}, payload_len={payload_l}"
        )
        assert got_reason == exp_reason, (
            f"Fuzz trial {trial} mismatch: RTL reason={got_reason:#x} != model reason={exp_reason:#x}"
        )


# =====================================================================
# Layer 3: Edge Cases & Throughput (Continuous Back-to-Back Streaming)
# =====================================================================

@cocotb.test()
async def test_protocol_validator_back_to_back(dut):
    """Pipes consecutive packets on every clock cycle with zero bubbles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets = [
        # Packet A: Valid TCP SYN
        {
            "eth_type": 0x0800, "ip_version_ihl": 0x45, "ip_protocol": 6,
            "ip_total_length": 40, "l4_src_port": 12345, "l4_dst_port": 80,
            "l4_length": 20, "tcp_flags": 0x02, "payload_len": 0,
        },
        # Packet B: Malformed Port 0
        {
            "eth_type": 0x0800, "ip_version_ihl": 0x45, "ip_protocol": 6,
            "ip_total_length": 40, "l4_src_port": 0, "l4_dst_port": 80,
            "l4_length": 20, "tcp_flags": 0x02, "payload_len": 0,
        },
        # Packet C: Valid UDP packet
        {
            "eth_type": 0x0800, "ip_version_ihl": 0x45, "ip_protocol": 17,
            "ip_total_length": 48, "l4_src_port": 5353, "l4_dst_port": 53,
            "l4_length": 8, "tcp_flags": 0x00, "payload_len": 20,
        },
        # Packet D: Malformed SYN+FIN
        {
            "eth_type": 0x0800, "ip_version_ihl": 0x45, "ip_protocol": 6,
            "ip_total_length": 40, "l4_src_port": 12345, "l4_dst_port": 80,
            "l4_length": 20, "tcp_flags": 0x03, "payload_len": 0,
        },
    ]

    expected = []
    for p in packets:
        f, r = validate_protocol(**p)
        expected.append((1 if f else 0, r))

    # Drive Packet 0 at FallingEdge
    p = packets[0]
    dut.eth_type.value = p["eth_type"]
    dut.ip_version_ihl.value = p["ip_version_ihl"]
    dut.ip_protocol.value = p["ip_protocol"]
    dut.ip_total_length.value = p["ip_total_length"]
    dut.l4_src_port.value = p["l4_src_port"]
    dut.l4_dst_port.value = p["l4_dst_port"]
    dut.l4_length.value = p["l4_length"]
    dut.tcp_flags.value = p["tcp_flags"]
    dut.payload_len.value = p["payload_len"]
    dut.header_valid.value = 1

    for i in range(1, len(packets)):
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        # In this cycle, verdict for packet (i-1) is ready, and packet i is presented
        exp_f, exp_r = expected[i - 1]
        assert int(dut.verdict_valid.value) == 1, f"Back-to-back stream failed at packet {i-1}: valid != 1"
        assert int(dut.verdict_fail.value) == exp_f, f"Back-to-back stream failed at packet {i-1}: fail mismatch"
        assert int(dut.verdict_reason.value) == exp_r, f"Back-to-back stream failed at packet {i-1}: reason mismatch"

        p = packets[i]
        dut.eth_type.value = p["eth_type"]
        dut.ip_version_ihl.value = p["ip_version_ihl"]
        dut.ip_protocol.value = p["ip_protocol"]
        dut.ip_total_length.value = p["ip_total_length"]
        dut.l4_src_port.value = p["l4_src_port"]
        dut.l4_dst_port.value = p["l4_dst_port"]
        dut.l4_length.value = p["l4_length"]
        dut.tcp_flags.value = p["tcp_flags"]
        dut.payload_len.value = p["payload_len"]
        dut.header_valid.value = 1

    # Final packet presentation concludes
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.header_valid.value = 0
    exp_f, exp_r = expected[-1]
    assert int(dut.verdict_valid.value) == 1, "Final back-to-back packet valid != 1"
    assert int(dut.verdict_fail.value) == exp_f, "Final back-to-back packet fail mismatch"
    assert int(dut.verdict_reason.value) == exp_r, "Final back-to-back packet reason mismatch"

    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert int(dut.verdict_valid.value) == 0, "verdict_valid did not clear after back-to-back stream"


@cocotb.test()
async def test_protocol_validator_reset_clears(dut):
    """Verifies that synchronous reset immediately clears all verdict registers."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Present an invalid packet on FallingEdge
    dut.eth_type.value = 0x0800
    dut.ip_version_ihl.value = 0x45
    dut.ip_protocol.value = 6
    dut.ip_total_length.value = 40
    dut.l4_src_port.value = 0  # illegal port 0
    dut.l4_dst_port.value = 80
    dut.l4_length.value = 20
    dut.tcp_flags.value = 0x02
    dut.payload_len.value = 0
    dut.header_valid.value = 1

    # Assert reset before or during the rising edge
    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)

    assert int(dut.verdict_valid.value) == 0, "verdict_valid was not cleared by reset"
    assert int(dut.verdict_fail.value) == 0, "verdict_fail was not cleared by reset"
    assert int(dut.verdict_reason.value) == RC_NONE, "verdict_reason was not cleared by reset"


if __name__ == "__main__":
    from pathlib import Path
    from cocotb.runner import get_runner

    proj = Path(__file__).resolve().parent.parent.parent
    runner = get_runner("icarus")
    runner.build(
        sources=[proj / "rtl" / "detect" / "protocol_validator.v"],
        hdl_toplevel="protocol_validator",
        includes=[proj / "rtl" / "control"],
        build_dir=proj / "sim" / "build",
        always=True,
    )
    runner.test(
        hdl_toplevel="protocol_validator",
        test_module="test_protocol_validator",
        test_dir=proj / "sim" / "cocotb",
    )

