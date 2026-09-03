# Member C — Master Guide
## Track: Lane 1 Security — Keccak, NTT, ML-KEM-512 Engine (Highest-Risk Track)

You own the module the whole project's schedule risk is concentrated in. The synopsis says this explicitly (§6.6): the lattice core is deliberately built bottom-up, and if it doesn't close in time, the project falls back to a software KEM on the host with the hardware interface unchanged. That fallback exists so you should build methodically rather than rushing — a late-but-correct KEM beats an on-time-but-wrong one, since "wrong" here fails the FIPS 203 KAT gate and blocks Phase VII for everyone.

---

## 1. Your scope, in one sentence

Build a standards-conformant ML-KEM-512 engine (FIPS 203) in synthesizable Verilog — key generation, encapsulation, decapsulation with correct implicit rejection — bottom-up from the arithmetic primitives, verified against the official KAT vectors before anyone relies on it.

## 2. Files you own

```
rtl/crypto/sha3/
├── keccak_f1600.v       the 1600-bit permutation — shared by SHA3 and SHAKE
└── shake_wrapper.v

rtl/crypto/ntt/
├── ntt_core.v            forward/inverse NTT, Cooley-Tukey butterfly network
├── butterfly.v
└── modmul.v              mod-q (q=3329) multiplier, uses DSP slices

rtl/crypto/kem/
├── mlkem_top.v            keygen / encaps / decaps state machine
├── cbd_sampler.v          centered binomial distribution noise sampler
├── compress.v / decompress.v
└── fo_transform.v         Fujisaki-Okamoto re-encrypt-and-compare, implicit rejection

model/mlkem/
├── ntt.py
├── cbd.py
├── pke.py                 K-PKE (the encryption scheme under the KEM)
└── kem.py                 keygen/encaps/decaps incl. FO transform + implicit rejection

sim/vectors/fips203_kat/    official known-answer test vectors — your final gate

sim/cocotb/
├── test_ntt.py
└── test_mlkem_top.py
```

## 3. Why the build order below is not optional

Do not attempt `mlkem_top.v` before the sub-blocks are individually proven. This isn't caution for its own sake — a bug in NTT or Keccak, if you build top-down, surfaces as "the KEM produces the wrong key" with no way to localize it to one of a dozen possible causes. Built bottom-up, each stage has its own oracle and its own pass/fail gate.

## 4. Build order

### Step 1 — `model/mlkem/` in Python, entirely, before any RTL
Write the full Python reference — NTT, CBD sampler, K-PKE, and the KEM wrapper with FO transform — first. Run it against the official FIPS 203 KAT vectors and confirm it passes bit-exact. This is your ground truth for every RTL stage that follows, and writing it in Python first is far cheaper than debugging the same logic in Verilog from scratch.

You do not need to write this from mathematical first principles alone — cross-check intermediate values (e.g., the reference CRYSTALS-Kyber implementation, since ML-KEM is its standardized descendant) is reasonable, but the vectors your RTL is ultimately graded against are the official FIPS 203 ones, not a third-party implementation's internal state.

### Step 2 — `keccak_f1600.v`
The 1600-bit Keccak permutation. Get this right and SHA3-256/512 and SHAKE128/256 fall out as different padding/rate parameterizations of the same core — you do not need four separate hash engines.

**Verify:** against NIST's SHA-3 KAT vectors (FIPS 202) directly — these are well-published and give you an early, independent correctness gate before you're relying on Keccak inside anything KEM-specific.

### Step 3 — `ntt_core.v`, `butterfly.v`, `modmul.v`
The polynomial arithmetic engine — this is the part of the design an FPGA is architecturally suited for (regular, parallel, FFT-like structure), and it's also where DSP slices get used (synopsis budgets ≈8 DSP slices for the whole design, small since this is a lattice, not a filter — check your multiplier reuse strategy against that budget as you go).

**Verify:** against `model/mlkem/ntt.py` on randomized polynomial inputs (hundreds of random test cases, not just a handful) before touching CBD or the top-level KEM. Forward-then-inverse NTT should be the identity on any input — a cheap, powerful self-check to run continuously in simulation.

### Step 4 — `cbd_sampler.v`
Centered binomial distribution noise sampling, consuming Keccak/SHAKE output as its entropy source. Small module, but it's a place where an off-by-one in bit extraction silently produces a *plausible-looking but wrong* distribution — verify against `model/mlkem/cbd.py` on many samples, checking not just bit-exactness on a fixed seed but that your RTL's random-seed handling actually matches the reference's.

### Step 5 — `mlkem_top.v` + `compress.v`/`decompress.v` + `fo_transform.v`
Only now do you assemble keygen, encapsulation, and decapsulation state machines from the proven sub-blocks. Two details from the synopsis worth re-reading carefully before you implement this stage, because they're easy to get subtly wrong:

- **The FO transform protects the handshake, not per-packet data.** During decapsulation, re-encrypt the recovered value and compare against the received ciphertext; a mismatch means dishonestly-generated ciphertext. This is a *different* mechanism from Poly1305 (someone else's module, checks per-packet integrity) — don't conflate the two failure modes or their reason codes.
- **Implicit rejection is a compliance requirement, not a nice-to-have.** On decapsulation failure, FIPS 203 requires returning a deterministic pseudo-random key derived from a stored secret — never an explicit error — so a passive observer can't distinguish rejection from acceptance by timing or output shape. If your `fo_transform.v` branches visibly (different latency, different output pattern) on success vs. failure, that's a spec violation even if the *key value* it returns is otherwise correct. Test this explicitly: confirm the timing/side-channel shape of a rejected decapsulation is indistinguishable from an accepted one in your testbench, not just that the wrong output is "some other value."

### Step 6 — Full FIPS 203 KAT gate
Run the complete `mlkem_top.v` (keygen + encaps + decaps) against the official KAT vector set. This is a **hard gate**: zero unexplained mismatches, per Objective 6 of the synopsis. Do not let Phase VII (timing closure) start on an unverified core — a bug found after synthesis is dramatically more expensive to trace than one found here.

## 5. What "done" looks like for Phases IV–V

- [ ] `model/mlkem/` Python reference passes official FIPS 203 KAT vectors bit-exact
- [ ] `keccak_f1600.v` passes FIPS 202 SHA-3 KAT vectors
- [ ] `ntt_core.v` verified against Python on hundreds of random polynomials; forward∘inverse = identity holds
- [ ] `cbd_sampler.v` verified against Python reference, including seed-handling agreement
- [ ] `mlkem_top.v` passes full FIPS 203 KAT vectors, zero unexplained mismatches
- [ ] Implicit rejection verified as *indistinguishable* from acceptance (timing/output-shape check), not just "returns something different"
- [ ] Cycle counts logged for keygen/encaps/decaps — these feed directly into the §6.3 timing table in the synopsis

## 6. Dependencies and handoffs

- You depend on Member A's session-register-file section of the interface contract (where the shared secret and session state get written once your KEM completes a handshake) — confirm this section early even though you won't touch it until Phase V–VI.
- Member D (ChaCha/control) consumes your session key output — coordinate the exact handoff format (32-byte secret, which register, what "session established" signal looks like) well before Phase VI integration.
- You are the critical path. Communicate slippage early — the fallback plan (software KEM on host) is legitimate and pre-approved by the synopsis, but it needs to be invoked with enough runway left for Phases VII–VIII, not discovered in November.

## 7. Common failure modes to watch for

- Building `mlkem_top.v` before NTT/Keccak are independently proven — resist this even under time pressure, it costs more time than it saves.
- Treating implicit rejection as "just return a different value" rather than a side-channel-shape requirement — re-read synopsis §6.1 before implementing this.
- Losing track of which KAT vector set is authoritative — always the official FIPS 203 vectors, not a third-party implementation's self-consistency, even if you used the latter for early sanity-checking.
- DSP slice budget creep in `modmul.v` — check usage against the ≈8 DSP-slice budget periodically, not just at the end, since surprises here late in Phase VII cost timing-closure time.
