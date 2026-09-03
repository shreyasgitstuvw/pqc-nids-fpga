# Member B — Theoretical Understanding Guide (Beginner Level)
## Track: Lane 2 — Threat Detection

This assumes no background in network security, hashing, or probabilistic data structures. Read this before your build order.

---

## 1. Two philosophies of intrusion detection

There are fundamentally two ways to decide "is this traffic an attack?", and your lane implements both because they catch different things:

**Signature-based detection** asks "does this look like a *known* attack I've seen before?" You keep a database of patterns (byte sequences, header combinations) associated with known attacks, and check every packet against that database. Strength: very low false-positive rate for known attacks — if it matches, it almost certainly is one. Weakness: completely blind to anything novel. This is the model pioneered by tools like Snort and Suricata, which your synopsis's literature review cites directly.

**Anomaly/volume-based detection** asks "does the *pattern of traffic*, regardless of content, look statistically unusual?" A flood of a million requests from one source, or a slow methodical scan across thousands of ports, doesn't require matching any specific byte pattern — it's the *volume and shape* of the traffic that's suspicious. This is what your Count-Min Sketch does. Strength: catches novel attacks that don't match any known signature. Weakness: needs careful tuning to avoid flagging legitimate bursty traffic (a popular website suddenly getting real traffic looks similar to a flood, from pure volume alone).

Your lane runs both simultaneously because they cover each other's blind spots.

## 2. Content-Addressable Memory (CAM) — how signature matching works in one clock cycle

A normal memory (RAM) works by address: you give it an address, it gives you back the data stored there. A **content-addressable memory** works backwards: you give it a piece of *data*, and it tells you whether that data exists anywhere in its stored table — and does so in a single clock cycle, regardless of how many entries are stored, because every stored entry is compared *in parallel*, all at once, by dedicated comparison hardware at each memory cell.

The analogy: a normal address-book lookup ("what's the phone number at entry #47?") versus asking a room full of a hundred people simultaneously "does anyone here have this exact phone number?" and getting an instant answer, because everyone checked their own slip of paper at the same time rather than one at a time.

This is exactly why CAM latency doesn't grow with signature-table size — you're trading hardware area (every entry needs its own comparator) for constant-time lookup, which is the right trade when you need wire-speed matching.

## 3. Why a hash table alone isn't enough for tracking millions of sources

A natural first idea for "track how much traffic each source IP has sent" is: keep a counter per source IP in a hash table. The problem is the address space — there are 4 billion possible IPv4 addresses, and even a small fraction of them appearing in an attack could require unbounded memory to track individually. Fixed hardware needs fixed, bounded memory, decided at design time — you can't allocate more BRAM mid-attack.

## 4. The Count-Min Sketch — bounded memory, one-directional error

This is the clever trick that solves the problem above. Instead of one counter per source (unbounded), you keep a small fixed 2D array of counters (say, k rows × w columns) and **k independent hash functions**, one per row.

To increment a source's count: for each of the k rows, hash the source's identifier (e.g., IP address) to pick one column in that row, and increment the counter there. Many different sources will collide into the same cell — that's expected and unavoidable with fixed memory.

To *read* a source's estimated count: hash it the same k ways, look up the k corresponding cells, and take the **minimum** of those k values.

Why the minimum, and why this works: any single cell's count might be inflated by collisions with *other* sources hashing to the same slot — but it can never be lower than the true count, since every real increment for that source did land there. Because you have k independent rows, the chance that *all k* of a source's cells are heavily polluted by unlucky collisions, simultaneously, is small and shrinks as k grows. So the minimum across rows is your best (still slightly over-, never under-, estimated) guess at the true count.

This is precisely why the synopsis states CMS "over-estimates but never under-estimates" — it's a direct mathematical consequence of taking the minimum of quantities that can only be inflated by collision, never deflated. **An attack can never be missed for lack of table space; the cost is a bounded, quantifiable rate of seeing a "phantom" high count on some innocent source.**

### The math behind sizing it (you'll need this before writing RTL)
You choose two parameters up front: `epsilon` (how much over-estimation error you'll tolerate, as a fraction of total traffic volume) and `delta` (the probability your estimate exceeds that error bound). Standard sizing:
- width `w = ceil(e / epsilon)` (e ≈ 2.718, Euler's number)
- depth `k = ceil(ln(1/delta))`

Concretely: smaller epsilon (tighter accuracy) costs more width (more memory per row); smaller delta (higher confidence) costs more depth (more hash rows, more parallel comparisons). This is a genuine engineering trade against your BRAM budget, not a knob to guess at — compute it before implementation, exactly as your build order specifies.

## 5. What a "flood" and a "scan" actually look like in header data

- **SYN flood**: a Denial-of-Service technique. TCP connections begin with a SYN packet (a request to open a connection). An attacker sends a huge volume of SYN packets, often with spoofed source addresses, and never completes the handshake — this can exhaust a server's resources reserving space for connections that never finish. Your CMS tracking incoming SYN-flag packets per source (or per destination, depending on what you're defending) is exactly the mechanism that catches this by volume, without needing to inspect payload content at all.
- **Port scan**: an attacker probes many different destination ports on a target, usually in sequence, looking for open services to exploit. This shows up as one source touching an unusually large number of distinct destination ports in a short time — a slightly different statistical signature than a flood (many distinct targets rather than many repeated hits on one).
- **Slow-rate exploits**: deliberately low-volume, spread over time, specifically to evade naive threshold-based detection ("more than N packets/second = alert"). This is part of why the CIC-IDS2017 dataset your synopsis cites includes such attacks — a good detection system needs to catch these too, not just high-volume floods.

## 6. Protocol validation — the simplest but still important check

Some attacks (or just malformed/buggy traffic) don't need volume or a known signature to be recognizable as wrong — they violate the protocol spec itself. Examples: a TCP packet with both SYN and FIN flags set simultaneously (nonsensical — one opens a connection, the other closes it), a header claiming a length that doesn't match the actual bytes present, or a reserved protocol number that shouldn't appear in legitimate traffic. This check is pure combinational logic against already-parsed header fields — no state, no memory — which is why it's the easiest of your three modules and a good first build.

## 7. Why false-positive rate is a number you report, not a vibe

Every detection mechanism trades sensitivity against false alarms. Your synopsis's Objective 7 explicitly wants "detection accuracy" reported as a measured number. For the CAM, this is close to zero false positives by construction (you're checking exact matches). For the CMS, it's the (epsilon, delta) bound you calculated analytically, **checked empirically** by replaying labeled attack traffic and counting how often your sketch over-estimates beyond that bound. This empirical-vs-analytical comparison is exactly what makes your section of the final report defensible rather than a hand-wave.
