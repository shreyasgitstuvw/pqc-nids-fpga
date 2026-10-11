# NIST CAVP FIPS 202 Test Vectors: Provenance & Checksums

## 1. Upstream Source
These test vectors are official cryptographic ground truth published by the **National Institute of Standards and Technology (NIST)** under the Cryptographic Algorithm Validation Program (CAVP).

- **SHA-3 Byte Test Vectors:**  
  URL: `https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip`
- **SHAKE Byte Test Vectors:**  
  URL: `https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip`

Downloaded and staged on: `2026-10-09`  
Owner: External Ground Truth (read-only per `AGENTS.md` §3). Never edit these files.

---

## 2. Archive Checksums
- `sha-3bytetestvectors.zip`:
  `e9ef2433eb139fec071df986eaebdfa441dfdf5bc0f98be1288b85775c9779df`
- `shakebytetestvectors.zip`:
  `b3c9bf81b16ee867c4cfa6c77d5ecbe5d448408a2dfcaebc42144866b8fb739a`

---

## 3. Extracted Response Files (`.rsp`) SHA-256 Checksums

| File | SHA-256 Checksum |
|---|---|
| `SHA3_224LongMsg.rsp` | `8b70888c4b0936ec4232e14b448a06b3b5d2461c25de3da84e9e270d957efc0f` |
| `SHA3_224Monte.rsp` | `d6b61e4fabc9b5f12770b2a6060915086b4f8814ef0ba594bbc1ef56f7a993c3` |
| `SHA3_224ShortMsg.rsp` | `c2c57e8090b270a7ca154602803c8a30859e737ca65729701df02080dd6c75fd` |
| `SHA3_256LongMsg.rsp` | `741b75d093aeb1de3536681b5e7e65090a5eca8015eb75c5f9be0feda47660d5` |
| `SHA3_256Monte.rsp` | `0b387d75eb7bb96070007ae570601675d4527f50295f41c9d0fbc6c03ec48ca4` |
| `SHA3_256ShortMsg.rsp` | `e75b1ded16e9862eaaef9ad9b89402b9832f86fe818292634b2e54dc6b3540ff` |
| `SHA3_384LongMsg.rsp` | `d7e1e35d90c46617869b7819a8c1ebc113f583dd4de63f6ee2f97f0d98f80531` |
| `SHA3_384Monte.rsp` | `1de2e1a352d4f53412bd2236c39125da802ec3f4f89f65cef1837e7e3ff6a5c9` |
| `SHA3_384ShortMsg.rsp` | `0e15aa35474c85084a0a1682c28ae9d4ebde61daa130ea0b408f51a1e9ec3150` |
| `SHA3_512LongMsg.rsp` | `142aab2fc0fd41809b1efdf48819e4f863985fb8d5cb30694acf7c8e7080d20e` |
| `SHA3_512Monte.rsp` | `2e07ae80620d566a77f4c3cb2d5b465454100b3984e7e661030c942db9804c89` |
| `SHA3_512ShortMsg.rsp` | `f73a39d8091d58c9225cfad8e6d8cfa3e8d67532c7029bf376baef0d0d86d5b6` |
| `SHAKE128LongMsg.rsp` | `826b319c265448f5268c7e36f432de31315dd8155eaa038ba76d1acd0d03736f` |
| `SHAKE128Monte.rsp` | `78b0e751fd8c8eb455ec8f98debb2f2c2e39f04f5241850e190326238baf83dc` |
| `SHAKE128ShortMsg.rsp` | `c7384e3f84247d90e6b0af9ac618a968bb65f5dcbe9c2ee7e8a66475c551764b` |
| `SHAKE128VariableOut.rsp` | `56ac04dd47c8063bdd08fd7744aef55c22c22946d722012460703bcae0b2583f` |
| `SHAKE256LongMsg.rsp` | `f7881838fa013853993bf7e0814de0ab53ee93a4dbc2b7bce5bed7cc81e6985f` |
| `SHAKE256Monte.rsp` | `95e5929344f4309e70f16e42620bd393d7a69b3f2577231ff5adcda1b395c6c8` |
| `SHAKE256ShortMsg.rsp` | `a21dd9180a0f0139fa8d4056919f8194ddaca2f36dc5aafa70723682099d64f5` |
| `SHAKE256VariableOut.rsp` | `90fb72336900b22284477b76d0868fc2822ae42a114079c6c8a7fbda12eb52ca` |

---

## 4. Verification in Testbench
Test vectors are parsed directly by [`sim/cocotb/test_fips202_kat.py`](file:///c:/Users/chand/PycharmProjects/pqc-nids-fpga/sim/cocotb/test_fips202_kat.py) and verified against both [`rtl/crypto/sha3/shake_wrapper.v`](file:///c:/Users/chand/PycharmProjects/pqc-nids-fpga/rtl/crypto/sha3/shake_wrapper.v) and [`model/sha3.py`](file:///c:/Users/chand/PycharmProjects/pqc-nids-fpga/model/sha3.py).
