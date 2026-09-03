# Member C — Theoretical Understanding Guide (Beginner Level)
## Track: Lane 1 Security — Keccak, NTT, ML-KEM-512

This is the heaviest theory load in the project — you're implementing genuinely novel cryptography (standardized in 2024), not a decades-old, well-worn algorithm. Take this section seriously; the build order in your master guide will make much more sense once these ideas are in place. No prior cryptography or abstract algebra background is assumed.

---

## 1. Why does encryption need to change at all?

Almost every secure connection you've ever used (HTTPS, Wi-Fi, banking apps) relies on one of two hard math problems: factoring a large number into its prime factors (RSA), or the discrete logarithm problem on elliptic curves (ECC/ECDH). Both are believed to be hard for *classical* computers — hard enough that breaking a well-chosen key would take longer than the age of the universe with all the computing power on Earth today.

**Shor's algorithm** (1994) is a quantum algorithm that solves both of these problems *efficiently* — not "somewhat faster," but fundamentally, exponentially faster, turning a computation that's intractable for millennia into one that's tractable in hours or days, *if* a sufficiently large, stable quantum computer exists. Such a machine doesn't exist yet at the scale needed to break real-world keys. But that's exactly the danger your synopsis names: **"harvest now, decrypt later."** An adversary can record your encrypted traffic *today*, store it, and decrypt it retroactively the moment a large enough quantum computer becomes available — years from now. For anything that needs to stay secret for a long time (medical records, government communications, long-lived infrastructure), that future decryption is a present-day risk, not a hypothetical one.

This is why NIST ran a multi-year public competition to standardize replacement algorithms believed to resist quantum attack, culminating in FIPS 203 (ML-KEM) in August 2024 — the standard you're implementing.

## 2. Why lattices? What even is a lattice?

Picture an infinite, evenly-spaced grid of points in space — like the intersections of graph paper, but in many dimensions instead of two. That's a **lattice**: the set of all points you can reach by taking integer combinations of some fixed set of "basis vectors."

The hard problem lattice cryptography relies on is roughly: *given a "bad" (skewed, hard-to-use) description of a lattice's basis vectors, find the shortest non-zero vector in that lattice, or find the lattice point closest to some given target point.* In low dimensions (2D, 3D) this is easy — you could practically eyeball it. But in hundreds of dimensions, with a deliberately awkward basis, it becomes computationally intractable — and critically, **no quantum algorithm is currently known that solves this efficiently**, unlike factoring and discrete log. That's the whole reason lattice-based schemes were the strongest, most-studied candidates in NIST's competition.

ML-KEM specifically is built on a structured variant called **Module-LWE** (Module Learning With Errors) — "structured" meaning the lattice has extra algebraic regularity (built from polynomial rings) that makes it much faster to compute with than a generic lattice, while (as far as current cryptanalysis shows) not making it meaningfully easier to break. This structure is precisely what makes the NTT-based fast arithmetic in Step 2 below possible at all.

## 3. The intuition behind "Learning With Errors"

You don't need the full formal definition to build this, but the shape of the idea will make the noise-sampling step make sense. Roughly: you take a system of linear equations (which would be trivially solvable with ordinary algebra) and deliberately add small random "noise" to each equation before publishing it. Recovering the original secret from the *noisy* equations turns out to be extremely hard — but if you *know* the secret, verifying or using it (checking that a candidate answer roughly satisfies the noisy equations) is easy. This asymmetry — hard to solve, easy to verify with the secret — is the basic shape every public-key cryptosystem needs, and LWE is where ML-KEM gets it. The "noise" is exactly what `cbd_sampler.v` generates.

## 4. Modular arithmetic and rings — the arithmetic ML-KEM actually runs on

All the arithmetic in ML-KEM happens modulo a small prime, `q = 3329`, and over polynomials, not just plain integers. If you haven't worked with modular arithmetic before: it's arithmetic on a clock face — numbers wrap around after reaching `q`, so `q - 1 + 2 = 1` (mod q), the same way `11 o'clock + 2 hours = 1 o'clock`.

ML-KEM works with **polynomials** whose coefficients are numbers mod `q`, and where the polynomials themselves are also reduced modulo a fixed polynomial (making the whole structure a finite "ring," in the abstract-algebra sense — you don't need to formalize this, just know that "multiply two polynomials" always produces another polynomial in the same bounded space, never growing without bound). The core expensive operation in the whole scheme is **multiplying two such polynomials together**, many times, and doing it fast is exactly the NTT's job.

## 5. The Number Theoretic Transform (NTT) — why it exists

Multiplying two polynomials the naive way (each term of one times each term of the other) costs work proportional to *n²*, where *n* is the polynomial's degree (256 here). For n=256 that's tens of thousands of multiplications — done millions of times, this is far too slow.

The NTT is the finite-field cousin of the Fast Fourier Transform (FFT) — the same trick used to make digital signal processing and audio compression fast. The core insight, without the full derivation: instead of multiplying polynomials in their normal ("coefficient") representation, you transform both into a different representation (the "evaluation" representation, evaluating the polynomial at a specific set of special points related to roots of unity mod q) where multiplication becomes pointwise — just multiply corresponding entries together, one at a time, no cross-terms. Then you transform the result back. The transform itself costs *n log n* work using a butterfly network structure (the same Cooley-Tukey structure used in FFT hardware), which is dramatically cheaper than *n²* for meaningful n.

This is exactly the "regular, parallel structure" your synopsis says an FPGA is well-suited for — a butterfly network is inherently parallelizable, unlike a general-purpose multiplication algorithm, which is why lattice cryptography (unlike RSA, which needs huge general-purpose modular exponentiation) maps so naturally onto FPGA fabric.

**Sanity check property to remember for testing:** applying the forward NTT and then the inverse NTT to any polynomial should return you to exactly where you started — this "forward then inverse is the identity" property is a free, powerful self-test you should run constantly during development, not just a one-off check at the end.

## 6. Keccak / SHA-3 / SHAKE — the hashing engine underneath everything

A cryptographic hash function takes an input of any size and produces a fixed-size output that looks statistically random, is infeasible to reverse (find an input from the output), and changes completely if even one bit of input changes. **Keccak** is the specific construction standardized as SHA-3 (FIPS 202); it works via a "sponge" model — data is "absorbed" into a large internal state through repeated permutation rounds, then "squeezed" back out.

The reason this matters to you: Keccak's core permutation (`keccak_f1600.v`, operating on a 1600-bit internal state) is reusable machinery. SHA3-256, SHA3-512, SHAKE128, and SHAKE256 are all *the same underlying permutation*, just with different padding rules and different amounts of output squeezed out (SHAKE is an "extendable output function" — you can ask for as many output bits as you need, unlike fixed-length SHA3). Inside ML-KEM, this hashing engine is used to expand seeds into larger structured data (like the public matrix in the underlying scheme) and to generate the pseudorandomness the noise sampler consumes — it's the entropy backbone of the whole KEM, even though it's not "the lattice math" itself.

## 7. What a KEM actually is, and why it's not the same as "encryption"

A **Key Encapsulation Mechanism (KEM)** solves a specific, narrower problem than general public-key encryption: two parties who've never met need to agree on a shared secret key, over a channel an eavesdropper can read, such that the eavesdropper learns nothing about the resulting secret even having seen everything transmitted.

The mechanics: one side generates a keypair and publishes the public ("encapsulation") key. The other side uses that public key to generate a fresh random secret and "wraps" it, producing a ciphertext that only the corresponding private key can unwrap ("decapsulate") back into the same secret. Critically — **the secret itself never crosses the wire**, only the wrapped form does. This shared secret then becomes the symmetric key that ChaCha20-Poly1305 uses for actual bulk data encryption. This division of labor (expensive asymmetric crypto once, per session, to establish a key; cheap symmetric crypto per packet, using that key) is universal in real-world protocols, not unique to this project — it's why your synopsis splits the KEM engine and the ChaCha/Poly engine into two separate teams with very different performance profiles.

## 8. Chosen-ciphertext attacks and why the FO transform exists

A subtler class of attack: rather than trying to break the math directly, an attacker sends the decapsulating side *deliberately malformed* ciphertexts and observes how it responds (does it error differently? take different time? reveal partial information through its behavior?). Over many such attempts, these tiny leaks can be pieced together to recover the secret key — even though the underlying lattice problem itself was never "solved."

The **Fujisaki-Okamoto (FO) transform** is a generic technique (not specific to lattices — it's a well-studied 1999 construction, cited in your references) that hardens an encryption scheme against exactly this. The mechanism: on decapsulation, before trusting the result, the hardware *re-encrypts* the value it just recovered using the same randomness it derived, and checks whether that re-encryption matches the ciphertext it was actually given. If it doesn't match, the ciphertext wasn't honestly generated by someone who knew the correct public key process — it was tampered with or invented — and the decapsulation must be treated as failed.

This upgrades a scheme that's only secure against a *passive* eavesdropper into one secure against an *active* attacker who gets to submit chosen ciphertexts and observe responses — the difference between "IND-CPA" and "IND-CCA2" security, in the field's terminology, though you don't need the formal definitions to implement it correctly.

## 9. Implicit rejection — the part that's easy to get subtly wrong

Naively, you might think a failed FO check should just return an error. FIPS 203 specifically forbids this. Instead, on failure, the scheme returns a **deterministic pseudo-random value derived from a stored secret** — a "decoy" key that looks exactly like a real one from the outside, with no visible error signal, no different timing, no different output shape.

Why: if failure produced any observable difference at all — an error flag, a shorter response time, a different-looking output — an attacker could exploit that difference as an "oracle," repeatedly submitting slightly different malformed ciphertexts and using the yes/no leak from your error signal to slowly reconstruct the secret key, one bit of information at a time. Implicit rejection closes this off completely: from the outside, "you gave me garbage" and "you gave me a valid ciphertext" look identical in every observable way. This is why your build order calls this a compliance requirement to test explicitly (timing/output-shape indistinguishability), not just "does the function return the mathematically expected decoy value."

## 10. How this all fits together, in the order you'll build it

1. **Keccak** gives you a hashing/entropy engine — needed by nearly everything else.
2. **NTT** gives you fast polynomial multiplication — the arithmetic backbone.
3. **CBD sampler** uses Keccak's output to generate the "noise" that makes the LWE problem hard.
4. **The full KEM** (keygen/encaps/decaps) assembles 1–3 into the actual protocol, with the **FO transform** hardening decapsulation against active attacks, and **implicit rejection** ensuring failures leak nothing.
5. The output of a successful decapsulation — a 32-byte shared secret — is handed off to the ChaCha20-Poly1305 lane (a different team member) as the session key for actual data encryption.

Every one of these five layers has a known-answer test you can check yourself against before moving to the next — that's not incidental, it's the entire strategy for building something this mathematically dense without getting lost in an undebuggable integrated system.
