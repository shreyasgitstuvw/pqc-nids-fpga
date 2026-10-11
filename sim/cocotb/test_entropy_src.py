#==========================================================================
# sim/cocotb/test_entropy_src.py
#
# Tests rtl/control/entropy_src.v, the seed source for mlkem_top's
# rng_valid / rng_data / rng_take handshake.
#
# This module is a DRBG, not a TRNG (its header says so plainly), so these
# tests check the properties the design actually relies on:
#   * a seed is always available, so the KEM never stalls waiting for one;
#   * every rng_take yields a different word, so no two encapsulations reuse m;
#   * the LFSR never reaches the all-zero fixed point;
#   * jitter from byte arrivals changes the sequence;
#   * seed_load replaces the state, which is the hook for the Zynq PS's
#     hardware RNG.
#==========================================================================

import os

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

LFSR_TAPS = 0xA4200000 << 224
MASK256 = (1 << 256) - 1


def lfsr_next(state):
    """Must match the Galois LFSR in entropy_src.v."""
    fb = state & 1
    nxt = state >> 1
    if fb:
        nxt ^= LFSR_TAPS
    return nxt & MASK256


async def reset_dut(dut):
    dut.rst.value = 1
    dut.jitter_strobe.value = 0
    dut.seed_load.value = 0
    dut.seed_in.value = 0
    dut.rng_take.value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def take(dut):
    """Consume one seed the way mlkem_top does, and return it."""
    val = int(dut.rng_data.value)
    assert int(dut.rng_valid.value) == 1, "rng_valid must be high whenever a seed is ready"
    dut.rng_take.value = 1
    await FallingEdge(dut.clk)
    dut.rng_take.value = 0
    await FallingEdge(dut.clk)
    return val


@cocotb.test()
async def entropy_always_available(dut):
    """rng_valid is held high, so the KEM never waits for entropy. A stall here
    would show up as a handshake that silently never starts."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    for _ in range(50):
        assert int(dut.rng_valid.value) == 1
        await FallingEdge(dut.clk)


@cocotb.test()
async def entropy_every_take_is_different(dut):
    """200 consecutive takes must all differ. Two encapsulations sharing m would
    reuse the same ML-KEM message, which is the failure this guards."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    seen = []
    for _ in range(200):
        seen.append(await take(dut))
    assert len(set(seen)) == len(seen), (
        f"{len(seen) - len(set(seen))} of {len(seen)} seeds repeated")
    assert 0 not in seen, "the all-zero state is an LFSR fixed point and must never occur"


@cocotb.test()
async def entropy_matches_the_lfsr_model(dut):
    """Without jitter the sequence is the documented Galois LFSR exactly. This
    is what makes the generator's behaviour reviewable rather than mysterious."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    state = int(dut.rng_data.value)
    for n in range(40):
        got = await take(dut)
        assert got == state, f"take {n}: RTL {got:#x} != model {state:#x}"
        state = lfsr_next(state)


@cocotb.test()
async def entropy_jitter_changes_the_sequence(dut):
    """A byte arrival stirs in the free-running counter. That arrival phase is
    the only input an attacker does not control from reset alone, so it must
    actually reach the state."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    async def run(with_jitter):
        await reset_dut(dut)
        for _ in range(7):
            await FallingEdge(dut.clk)
        if with_jitter:
            dut.jitter_strobe.value = 1
            await FallingEdge(dut.clk)
            dut.jitter_strobe.value = 0
            await FallingEdge(dut.clk)
        return [await take(dut) for _ in range(5)]

    plain = await run(False)
    stirred = await run(True)
    assert plain != stirred, "jitter_strobe did not change the sequence"


@cocotb.test()
async def entropy_seed_load_replaces_the_state(dut):
    """seed_load is the hook for a real RNG behind the Zynq PS. An all-zero word
    must be refused, because zero is the LFSR's fixed point."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    wanted = 0xDEADBEEF << 192 | 0x12345678
    dut.seed_in.value = wanted
    dut.seed_load.value = 1
    await FallingEdge(dut.clk)
    dut.seed_load.value = 0
    await FallingEdge(dut.clk)
    assert int(dut.rng_data.value) == wanted, "seed_load did not take effect"

    dut.seed_in.value = 0
    dut.seed_load.value = 1
    await FallingEdge(dut.clk)
    dut.seed_load.value = 0
    await FallingEdge(dut.clk)
    assert int(dut.rng_data.value) != 0, "an all-zero seed must be refused"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_entropy_src"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    runner = get_runner("icarus")
    runner.build(verilog_sources=[os.path.join(proj, "rtl", "control", "entropy_src.v")],
                 includes=[os.path.join(proj, "rtl", "control")],
                 hdl_toplevel="entropy_src",
                 build_dir=os.path.join(proj, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="entropy_src", test_module="test_entropy_src",
                test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_entropy_src")
