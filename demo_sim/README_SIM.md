# Rehearsal simulator (no hardware)

A Python process plays the board so you can feel the demo before the real RTL exists.
Real crypto (ML-KEM-512, ChaCha20-Poly1305) and the real attack-signature list are used.
Thresholds are scaled down and timings are NOT hardware timings. Every screen says [SIMULATION].

One command opens all four windows (from the repo root):

    powershell -ExecutionPolicy Bypass -File demo_sim\run_demo.ps1

Or open four PowerShell windows yourself, in this order:

    1  python demo_sim/board_sim.py          # the board: LED panel + event log
    2  python demo_sim/chat_sim.py --me B    # Device B (a full peer: it can talk back)
    3  python demo_sim/chat_sim.py --me A    # Device A (handshake takes a few seconds: software ML-KEM)
    4  python demo_sim/attacker_sim.py       # Device C

Only three windows? Run `python demo_sim/board_sim.py --inbox` and skip the board-only window: the panel then
also shows what each side receives. Every received message is shown twice: the ciphertext that arrived, and the plaintext the receiver decrypted
locally. The board re-encrypts for each destination, so no plaintext ever crosses a wire.

Suggested run, about six minutes:
 A:  (banner shows the secure line)   /ping   hello bob   hi alice
 C:  join-bad            LD0 blinks, no session
 C:  nosession hello     LD7, no session
 C:  join   say hi, checking in      B receives it (C is a legitimate peer)
 C:  tamper x  |  wrongkey y  |  inject 1  |  inject 3     LD7 / LD7 / LD4 / LD4, B sees nothing
 A:  /tamper  then  send report      LD7, then a normal message still arrives
 C:  flood 400           LD5 after the first ~150 packets
 C:  crc  truncated  scan            LD1 / LD2 / LD3 (scan shows as MALFORMED today)
 C:  replay              LD7, then `join` to recover (a replay desyncs C's own session)
 C:  auto                the same story as one paced, narrated run
