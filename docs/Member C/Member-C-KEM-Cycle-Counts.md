# Member C — Measured ML-KEM-512 cycle counts (task C18)

**Status:** measured in RTL simulation on the real `mlkem_top.v`. **Pre-synthesis.**
No Vivado run has happened, so these are cycle counts, not proven wall-clock latencies
(see "What this does and does not say").

**Reproduce:** `KEM_CYCLES_OUT=kem_cycles.json python sim/cocotb/test_kem_cycles.py`
(about 3 minutes with Icarus). Every sample is also checked bit-exact against
`model/mlkem/` before it is counted, so a number is only logged for a correct result.

## Table for synopsis §6.3

Cycles are counted from the `cmd_start` edge to the `kem_done` strobe.
Time is cycles × 10 ns, i.e. at the 100 MHz target clock.

| Operation | Samples | Cycles (min – max) | Mean | Time @ 100 MHz | Board lower bound (`opcount.py`) |
|---|---:|---:|---:|---:|---:|
| KeyGen | 7 (2 NIST KAT + 5 random) | 17,640 – 17,669 | 17,660 | ≈ 177 µs | 4,800 |
| Encaps | 6 (1 NIST KAT + 5 random) | 24,022 – 24,049 | 24,033 | ≈ 240 µs | 6,000 |
| Decaps, authentic ciphertext | 9 (4 NIST VAL + 5 random) | 33,786 – 33,814 | 33,800 | ≈ 338 µs | 8,900 |
| Decaps, rejected (corrupted) ciphertext | 5 (random) | 33,790 – 33,814 | 33,797 | ≈ 338 µs | 8,900 |

Earlier, larger sweeps during development stayed inside the same window
(KeyGen 17,638 – 17,679; Encaps 24,018 – 24,062; Decaps 33,786 – 33,841). The test asserts
a window around the measured range (KeyGen 17,600 – 17,720; Encaps 23,950 – 24,120;
Decaps 33,700 – 33,900), so a regression that moves a count out of it fails the suite.

## Why the numbers vary

Counts are not constant across inputs because `SampleNTT` is rejection sampling: the number
of SHAKE128 blocks needed to fill a polynomial depends on ρ. KeyGen and Encaps vary with their
seed or public key; Decaps varies only with the ρ stored in `dk`.

**Decaps is constant-time with respect to the ciphertext.** For the same `dk`, an authentic and
a corrupted ciphertext take exactly the same number of cycles (asserted pair by pair in
`test_kem_cycles.py`, and checked as a full cycle-by-cycle waveform at the `session_mgr.v`
boundary in `test_seam2_kem_session.py`). Observed variation in the table above comes only from
different `dk`/ρ values.

## What this does and does not say

- The board's old figures (4,800 / 6,000 / 8,900) were algorithmic lower bounds with zero control
  or memory overhead. The real design is about 3.7× (KeyGen), 4.0× (Encaps) and 3.8× (Decaps)
  above them. That is expected for a single-butterfly, one-DSP48E1 iterative datapath, and it
  stays well inside the project's time budget: receiving the 768-byte ciphertext at 3 Mbaud takes
  ≈ 2.56 ms, so the handshake is still UART-bound, now by roughly 7.5× rather than 30×.
- Wall-clock figures assume timing closes at 100 MHz. That has not been checked (no synthesis or
  implementation run yet), so the microsecond column is an estimate until the Vivado timing report
  exists. The cycle counts themselves are measured.
- Packet-bus ingest adds the time to receive the packet; measured from the packet's last byte,
  Decaps finishes ≈ 33.8 k cycles later (33,788 – 33,815 across the NIST VAL vectors in
  `test_seam2_kem_session.py`).
- Resource figures (LUT/FF/BRAM/DSP) in the RTL headers remain pre-synthesis estimates.
