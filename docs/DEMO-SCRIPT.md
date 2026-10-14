# PQC-NIDS - Demo Screenplay

Assumed running time **8 minutes plus Q&A** (change the dwell times in Act III if the slot differs).
Every beat has four parts: **ON SCREEN**, **SAY**, **DO** (operator), **PROOF IT IS LIVE**. Nothing on
screen is scripted output: every number comes from the board's own telemetry frame or the host's
own packets. If a beat cannot be shown live it is shown as a clearly labelled recording, never faked.

## The one idea the audience leaves with

> **Encryption blinds the firewall. Quantum computers will break today's key exchange. This board fixes
> both with one design: the device that holds the quantum-safe key is the same device that inspects the
> traffic.**

Everything in the demo exists to make one of three sentences land, in this order:

1. **The problem is a trap.** To inspect traffic you must read it; to protect it you must encrypt it.
   Normal networks pick one. And what is encrypted today can be recorded now and decrypted later by a
   quantum computer (Shor's algorithm breaks RSA and elliptic-curve key exchange).
2. **The answer is placement.** Put a post-quantum key exchange (ML-KEM-512, the NIST FIPS 203 standard)
   and the cipher *inside* the inspection engine, in hardware, so plaintext exists only inside the
   device and only for the clock cycles it is being checked.
3. **The proof is that it fails closed and says nothing it should not.** Every attack is dropped for a
   named reason, and the one attack that must produce *no* signal produces none.

## Staging (what the room sees)

| Position | Device | Role |
|---|---|---|
| Centre, big screen | **Telemetry dashboard** (laptop C, link C) | The only thing the audience reads. Renders the same four lines as the OLED, much larger, plus the eight reason counters and a packet ticker |
| Left | **Sender** (laptop A, link A) | Handshake and clean traffic; console visible but small |
| Right | **Attacker** (laptop B, link B) | Dark terminal, started by hand mid-demo for a clean before/after |
| Table, camera on it | **ZedBoard** | LEDs LD0-LD7 and the OLED, filmed and projected as a corner inset |

The OLED is 128x32 pixels and unreadable beyond a metre; the dashboard is the readable copy and uses the
same `oled_layout.render()` so the two cannot disagree.

Roles: **Narrator** (speaks, never touches a keyboard), **Operator** (keys only, speaks only to say
"ready"), **Spotter** (watches the board and the clock, owns the reset). One person alone is a single
point of failure.

## Act 0 - The trap (0:00-1:00), one slide, no hardware

**ON SCREEN** two boxes: *"Inspect it" needs plaintext* / *"Protect it" needs ciphertext*, then a
timeline: *recorded today -> quantum computer -> decrypted later*.
**SAY** "Every security tool you own has the same weakness: it can only stop what it can read, and the
thing that protects your data is exactly what stops it reading. Worse, an adversary does not need to
break your encryption today. They record it, and wait. What we built is one board that refuses to make
that trade."
**DO** advance to the board.

## Act I - A quantum-safe handshake, live (1:00-2:30)

**ON SCREEN** dashboard: `SESSION: IDLE`, counters 0, all LEDs dark.
**SAY** "Nothing is connected yet. The board generated its own ML-KEM key pair when it powered up."
**DO** run `send.py` on laptop A.
**ON SCREEN** `SESSION: HANDSHAKING` -> the 800-byte public key goes in, the 768-byte ciphertext comes
back -> `SESSION: ESTABLISHED`, LD0 goes solid.
**SAY** "The laptop sent a public key. The board answered with a sealed ciphertext only the laptop can
open. Both sides now hold the same 256-bit secret, and that secret never crossed the wire. A quantum
computer watching this learns nothing it can use."
**PROOF IT IS LIVE** the first encrypted packet is accepted. A wrong key could not produce a valid
authentication tag, so acceptance *is* the proof that both ends derived the same key. Say that sentence
aloud; it is the claim an expert will test.
**Number to show** (labelled): "Decapsulation takes 33,786-33,814 cycles. At 100 MHz that is about
338 microseconds *if timing closes at 100 MHz*." Use the synthesised figure once Vivado reports it.

## Act II - Business as usual (2:30-3:15)

**ON SCREEN** `RX` climbing, `DROP 0`, ticker of `[RX] seq=N ok`.
**SAY** "This is the boring part, and it is the point. Legitimate traffic passes and nothing is
logged as suspicious. Hold on to that line: the counters we are about to watch move are the only ones
that should."
**DO** let it run ten seconds. Do not narrate over it.

## Act III - Attacks (3:15-6:45)

Order is chosen as an argument, not a list: *simplest thing a firewall can see*, then *the thing that
proves the thesis*, then *stress*, then *integrity*, then *the finale*. The attacker laptop is started
here, mid-demo.

**Beat 1 - Port scan (3:15)** · expect `SCAN` · LD6
**SAY** "An attacker probing for open doors. No payload to read, just behaviour: one source touching
many ports. A Count-Min Sketch, a few kilobytes of counters, notices the spread."
**PROOF** counter moves, LD6 pulses, `SRC` row on the OLED changes to the attacker's address (the
attacker uses a different source IP from the sender, deliberately).

**Beat 2 - Known attack signature inside an encrypted session (4:00)** · expect `SIGNATURE` · LD4
*This is the beat the whole project exists for. Slow down.*
**SAY** "Now the interesting one. This attack is inside the encrypted stream. A normal tap sees random
bytes. This board is the endpoint of the session, so for a few clock cycles it holds the plaintext, and
a content-addressable memory compares it against known signatures in a single cycle. The packet is
dropped before it ever leaves the device."
**PROOF** show the same packet's bytes on the wire (random-looking) next to the verdict.

**Beat 3 - Flood while legitimate traffic continues (4:45)** · expect `FLOOD` · LD5
**SAY** "Volume instead of content. Watch the sender, not the attacker: the legitimate session does not
stutter, because the two paths into the board are buffered separately."
**PROOF** sender ticker keeps `[RX] ok` through the flood, `FLOOD` counter climbs.

**Beat 4 - One flipped byte (5:30)** · expect `BAD_TAG` · LD7
**SAY** "A single bit changed in an established session. Poly1305 is a keyed fingerprint of the packet;
change one bit and the fingerprint is wrong. Dropped, counted, named."

**Beat 5 - A malformed key (6:00)** · expect `HANDSHAKE_KEY_INVALID` · LD0 fast blink
**SAY** "A public key with a number out of range. Rejected before any cryptography runs, because a
well-formed key is a precondition, not something to be discovered half-way through the maths."

## Act IV - The finale: the attack that makes no noise (6:45-7:45)

**ON SCREEN** a tampered handshake ciphertext is sent. **Nothing lights up. No counter moves.**
**SAY (after 3 seconds of silence)** "Nothing happened. That is the correct result. Our standard says
that when a handshake is tampered with, the board must not raise an error. It quietly derives a
different, useless key, so an attacker probing it learns nothing about whether they were close. Raise
an alarm and you have handed them exactly the signal the standard was designed to deny."
**DO** send one normal packet. **ON SCREEN** it is dropped as `BAD_TAG`.
**SAY** "And here is the failure, one packet later, from the layer below. The silence was not a gap. It
was the design."
**PROOF** the session shows `ESTABLISHED` throughout the silent step (no state change is observable).

## Act V - Close (7:45-8:30), one slide

**ON SCREEN** three lines only: the two measured cycle counts, `0 unexplained mismatches against the
reference model (70 official test vectors)`, and the synthesised resource/timing figures once they exist.
**SAY** "A quantum-safe handshake in hundreds of microseconds. Eight named reasons a packet can die.
One board, one clock, and nothing is decrypted anywhere it can be seen."

## If something breaks (rehearse until boring)

1. **Spotter** says "reset" -> `./demo/run/demo_reset.sh` (one command; practise it once).
2. A dropped step is repeated, never explained away. The narrator says "that is why we rehearse the
   reset" and moves on.
3. If hardware is dead: show the real session log captured at the last rehearsal
   (`demo/logs/`), introduced as "a recording of this exact run". Never present a recording as live.

## Questions to expect, and the true answers

| Question | Answer |
|---|---|
| Is the random number generator a real TRNG? | No. `entropy_src.v` is a DRBG stirred with UART arrival jitter, with a seed port for the Zynq's hardware RNG. It is documented as such. |
| How do you know ML-KEM is correct? | 70 official FIPS 203 known-answer vectors pass through the real `mlkem_top`, and the board and the Python host derive the same secret. |
| Why a UART instead of Ethernet? | It models the wire at 3 Mbaud so the full framing/CRC/parse path is real and testable on one board. The parsing layer is the same one an Ethernet MAC would feed. |
| False positive rate? | The Count-Min Sketch rate is reported in `docs/Member B/cms_accuracy_report.md`. |
| Known limits? | A horizontal IP sweep is classified as a port-scan variant, not separately; the sketch does not count packets during its 2048-clock epoch sweep. State these before being asked. |

## Code the script requires (add to the build list before synthesis)

- `demo/dashboard.py`: reads telemetry on link C, renders the OLED lines large plus eight counters and
  the packet ticker. Same `oled_layout.render()` as the RTL checks.
- `attacker.py` must use a source IP different from the sender's, and send beat 3 concurrently with
  the sender's traffic.
- `attack_sequence.json`: reorder to scan, signature, flood, tampered payload, malformed key, tampered
  ciphertext, and update the `gap_s` and `say` fields from this script.
- A `--rehearse` flag that runs the full sequence unattended and prints expected vs observed reason per
  beat (this becomes the rehearsal gate).
