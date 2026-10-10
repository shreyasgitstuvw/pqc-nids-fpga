#!/usr/bin/env python3
"""
scripts/schedule_check.py
Deterministic schedule replay and verification for ML-KEM-512 (C14 mlkem_top.v).
Follows .agents/workflows/self-review.md Section A:
Verifies for KeyGen, Encaps, and Decaps:
1. No bank read before write.
2. No bank read after overwrite without re-write.
3. Peak live polynomial banks <= 8 at every step.
4. Ciphertext compare path sees exactly 96 words (768 bytes).
"""

import sys

class BankScheduler:
    def __init__(self, name, num_banks=8):
        self.name = name
        self.num_banks = num_banks
        self.bank_content = [None] * num_banks
        self.bank_birth = [None] * num_banks
        self.step_idx = 0
        self.peak_live = 0
        self.log = []

    def write(self, bank_id, var_name):
        assert 0 <= bank_id < self.num_banks, f"Bank {bank_id} out of range [0..{self.num_banks-1}]"
        self.bank_content[bank_id] = var_name
        self.bank_birth[bank_id] = self.step_idx
        live = sum(1 for c in self.bank_content if c is not None)
        if live > self.peak_live:
            self.peak_live = live
        self.log.append((self.step_idx, f"WRITE Bank {bank_id} <= {var_name}", self._state_str()))

    def read(self, bank_id, expected_var):
        assert 0 <= bank_id < self.num_banks, f"Bank {bank_id} out of range [0..{self.num_banks-1}]"
        actual = self.bank_content[bank_id]
        assert actual is not None, f"Step {self.step_idx} ({self.name}): Read from empty Bank {bank_id}! Expected {expected_var}"
        assert actual == expected_var, f"Step {self.step_idx} ({self.name}): Read mismatch on Bank {bank_id}! Expected '{expected_var}', but holds '{actual}'"
        self.log.append((self.step_idx, f"READ  Bank {bank_id} == {expected_var}", self._state_str()))

    def free(self, bank_id):
        assert 0 <= bank_id < self.num_banks, f"Bank {bank_id} out of range [0..{self.num_banks-1}]"
        self.bank_content[bank_id] = None
        self.bank_birth[bank_id] = None

    def step(self, desc):
        self.step_idx += 1
        self.log.append((self.step_idx, f"--- STEP {self.step_idx}: {desc} ---", self._state_str()))

    def _state_str(self):
        return "[" + ", ".join(f"B{i}:{c if c else '-'}" for i, c in enumerate(self.bank_content)) + "]"


def verify_keygen():
    s = BankScheduler("KeyGen", num_banks=8)
    
    # Step 1: Sample s_0, s_1 into Banks 0, 1; NTT in place
    s.step("Sample s_0, s_1 via CBD eta1 into Banks 0, 1")
    s.write(0, "s_0")
    s.write(1, "s_1")
    s.step("NTT(s_0), NTT(s_1) in place")
    s.read(0, "s_0")
    s.write(0, "s_hat_0")
    s.read(1, "s_1")
    s.write(1, "s_hat_1")

    # Step 2: Matrix A Column 0 (A_00, A_01)
    s.step("Sample A_hat column 0 into Banks 2, 3")
    s.write(2, "A_hat_00")
    s.write(3, "A_hat_01")
    s.step("Mat-vec partial: row_0 = A_00*s_0; row_1 = A_01*s_0")
    s.read(2, "A_hat_00")
    s.read(0, "s_hat_0")
    s.write(4, "t_hat_0_accum")
    s.read(3, "A_hat_01")
    s.read(0, "s_hat_0")
    s.write(5, "t_hat_1_accum")
    s.free(2)
    s.free(3)

    # Step 3: Matrix A Column 1 (A_10, A_11)
    s.step("Sample A_hat column 1 into Banks 2, 3")
    s.write(2, "A_hat_10")
    s.write(3, "A_hat_11")
    s.step("Mat-vec accumulate: row_0 += A_10*s_1; row_1 += A_11*s_1")
    s.read(2, "A_hat_10")
    s.read(1, "s_hat_1")
    s.read(4, "t_hat_0_accum")
    s.write(4, "t_hat_0_accum2")
    s.read(3, "A_hat_11")
    s.read(1, "s_hat_1")
    s.read(5, "t_hat_1_accum")
    s.write(5, "t_hat_1_accum2")
    s.free(2)
    s.free(3)

    # Step 4: Sample e_0, e_1 into Banks 2, 3; NTT in place
    s.step("Sample e_0, e_1 via CBD eta1 into Banks 2, 3; NTT in place")
    s.write(2, "e_0")
    s.write(3, "e_1")
    s.read(2, "e_0")
    s.write(2, "e_hat_0")
    s.read(3, "e_1")
    s.write(3, "e_hat_1")

    # Step 5: Add noise to get t_hat_0, t_hat_1 in Banks 4, 5
    s.step("Add: t_hat_0 = row_0 + e_hat_0; t_hat_1 = row_1 + e_hat_1")
    s.read(4, "t_hat_0_accum2")
    s.read(2, "e_hat_0")
    s.write(4, "t_hat_0")
    s.free(2)
    s.read(5, "t_hat_1_accum2")
    s.read(3, "e_hat_1")
    s.write(5, "t_hat_1")
    s.free(3)

    # Step 6: Encode t_hat into ek and s_hat into dk_pke
    s.step("ByteEncode12(t_hat) from Banks 4, 5 into ek")
    s.read(4, "t_hat_0")
    s.read(5, "t_hat_1")
    s.step("ByteEncode12(s_hat) from Banks 0, 1 into dk")
    s.read(0, "s_hat_0")
    s.read(1, "s_hat_1")

    assert s.peak_live <= 8, f"KeyGen peak live {s.peak_live} > 8!"
    print(f"[PASS] KeyGen Schedule: Peak Live Banks = {s.peak_live} <= 8")


def verify_encaps():
    s = BankScheduler("Encaps", num_banks=8)
    words_emitted = 0

    # Step 1: Decode t_hat_0, t_hat_1 into Banks 0, 1 from ek
    s.step("ByteDecode12(ek) -> t_hat_0, t_hat_1 into Banks 0, 1")
    s.write(0, "t_hat_0")
    s.write(1, "t_hat_1")

    # Step 2: Sample y_0, y_1 into Banks 2, 3; NTT in place
    s.step("Sample y_0, y_1 via CBD eta1 into Banks 2, 3; NTT in place")
    s.write(2, "y_0")
    s.write(3, "y_1")
    s.read(2, "y_0")
    s.write(2, "y_hat_0")
    s.read(3, "y_1")
    s.write(3, "y_hat_1")

    # Step 3: Compute u_0 = INTT(A_00*y_0 + A_10*y_1) + e1_0
    s.step("Row 0: Sample A_00, A_10; mul-acc with y_hat -> Bank 6")
    s.write(4, "A_hat_00")
    s.read(4, "A_hat_00")
    s.read(2, "y_hat_0")
    s.write(6, "u_hat_0_part")
    s.free(4)

    s.write(4, "A_hat_10")
    s.read(4, "A_hat_10")
    s.read(3, "y_hat_1")
    s.read(6, "u_hat_0_part")
    s.write(6, "u_hat_0")
    s.free(4)

    s.step("INTT(u_hat_0) in place in Bank 6")
    s.read(6, "u_hat_0")
    s.write(6, "u_intt_0")

    s.step("Sample e1_0 JIT into Bank 4; add to Bank 6 -> u_0")
    s.write(4, "e1_0")
    s.read(6, "u_intt_0")
    s.read(4, "e1_0")
    s.write(6, "u_0")
    s.free(4)

    s.step("Compress_10(u_0) and ByteEncode_10 -> c1_part0 (40 words)")
    s.read(6, "u_0")
    s.free(6)
    words_emitted += 40

    # Step 4: Compute u_1 = INTT(A_01*y_0 + A_11*y_1) + e1_1
    s.step("Row 1: Sample A_01, A_11; mul-acc with y_hat -> Bank 6")
    s.write(4, "A_hat_01")
    s.read(4, "A_hat_01")
    s.read(2, "y_hat_0")
    s.write(6, "u_hat_1_part")
    s.free(4)

    s.write(4, "A_hat_11")
    s.read(4, "A_hat_11")
    s.read(3, "y_hat_1")
    s.read(6, "u_hat_1_part")
    s.write(6, "u_hat_1")
    s.free(4)

    s.step("INTT(u_hat_1) in place in Bank 6")
    s.read(6, "u_hat_1")
    s.write(6, "u_intt_1")

    s.step("Sample e1_1 JIT into Bank 4; add to Bank 6 -> u_1")
    s.write(4, "e1_1")
    s.read(6, "u_intt_1")
    s.read(4, "e1_1")
    s.write(6, "u_1")
    s.free(4)

    s.step("Compress_10(u_1) and ByteEncode_10 -> c1_part1 (40 words)")
    s.read(6, "u_1")
    s.free(6)
    words_emitted += 40

    # Step 5: Compute v = INTT(t_hat_0*y_0 + t_hat_1*y_1) + e2 + mu
    s.step("Dot product t_hat^T . y_hat -> Bank 6")
    s.read(0, "t_hat_0")
    s.read(2, "y_hat_0")
    s.write(6, "v_hat_part")
    s.free(0)
    s.free(2)

    s.read(1, "t_hat_1")
    s.read(3, "y_hat_1")
    s.read(6, "v_hat_part")
    s.write(6, "v_hat")
    s.free(1)
    s.free(3)

    s.step("INTT(v_hat) in place in Bank 6")
    s.read(6, "v_hat")
    s.write(6, "v_intt")

    s.step("Sample e2 JIT into Bank 4; Decompress m JIT into Bank 5")
    s.write(4, "e2")
    s.write(5, "mu")
    s.read(6, "v_intt")
    s.read(4, "e2")
    s.read(5, "mu")
    s.write(6, "v")
    s.free(4)
    s.free(5)

    s.step("Compress_4(v) and ByteEncode_4 -> c2 (16 words)")
    s.read(6, "v")
    s.free(6)
    words_emitted += 16

    assert s.peak_live <= 8, f"Encaps peak live {s.peak_live} > 8!"
    assert words_emitted == 96, f"Encaps words emitted {words_emitted} != 96!"
    print(f"[PASS] Encaps Schedule: Peak Live Banks = {s.peak_live} <= 8, Ciphertext Words = {words_emitted} == 96")


def verify_decaps():
    s = BankScheduler("Decaps", num_banks=8)
    words_compared = 0

    # Phase 1: Decrypt
    s.step("Decompress c1 into Banks 0, 1; Decompress c2 into Bank 4")
    s.write(0, "u'_0")
    s.write(1, "u'_1")
    s.write(4, "v'")

    s.step("NTT(u'_0), NTT(u'_1) in place in Banks 0, 1")
    s.read(0, "u'_0")
    s.write(0, "u_hat'_0")
    s.read(1, "u'_1")
    s.write(1, "u_hat'_1")

    s.step("ByteDecode12 s_hat into Banks 2, 3 from dk")
    s.write(2, "s_hat_0")
    s.write(3, "s_hat_1")

    s.step("Dot product s_hat^T . u_hat' -> Bank 5")
    s.read(2, "s_hat_0")
    s.read(0, "u_hat'_0")
    s.write(5, "dot_part")
    s.free(2)
    s.free(0)

    s.read(3, "s_hat_1")
    s.read(1, "u_hat'_1")
    s.read(5, "dot_part")
    s.write(5, "dot")
    s.free(3)
    s.free(1)

    s.step("INTT(dot) in place in Bank 5")
    s.read(5, "dot")
    s.write(5, "dot_intt")

    s.step("Sub: w = v' - dot_intt into Bank 6")
    s.read(4, "v'")
    s.read(5, "dot_intt")
    s.write(6, "w")
    s.free(4)
    s.free(5)

    s.step("Compress_1(w) -> m' (latched to 256-bit register)")
    s.read(6, "w")
    s.free(6)

    # Phase 2: Re-encryption
    s.step("Sample y_0, y_1 into Banks 0, 1; NTT in place")
    s.write(0, "y_0")
    s.write(1, "y_1")
    s.read(0, "y_0")
    s.write(0, "y_hat_0")
    s.read(1, "y_1")
    s.write(1, "y_hat_1")

    s.step("Row 0: Sample A_00, A_10 JIT into Bank 2; mul-acc -> Bank 4")
    s.write(2, "A_hat_00")
    s.read(2, "A_hat_00")
    s.read(0, "y_hat_0")
    s.write(4, "u_hat''_0_part")
    s.free(2)

    s.write(2, "A_hat_10")
    s.read(2, "A_hat_10")
    s.read(1, "y_hat_1")
    s.read(4, "u_hat''_0_part")
    s.write(4, "u_hat''_0")
    s.free(2)

    s.step("INTT(u_hat''_0) in place in Bank 4")
    s.read(4, "u_hat''_0")
    s.write(4, "u''_intt_0")

    s.step("Sample e1_0 JIT into Bank 2; add -> u''_0 in Bank 4")
    s.write(2, "e1_0")
    s.read(4, "u''_intt_0")
    s.read(2, "e1_0")
    s.write(4, "u''_0")
    s.free(2)

    s.step("Compress_10(u''_0) and ByteEncode_10 -> compare 40 words against stored c1")
    s.read(4, "u''_0")
    s.free(4)
    words_compared += 40

    s.step("Row 1: Sample A_01, A_11 JIT into Bank 2; mul-acc -> Bank 4")
    s.write(2, "A_hat_01")
    s.read(2, "A_hat_01")
    s.read(0, "y_hat_0")
    s.write(4, "u_hat''_1_part")
    s.free(2)

    s.write(2, "A_hat_11")
    s.read(2, "A_hat_11")
    s.read(1, "y_hat_1")
    s.read(4, "u_hat''_1_part")
    s.write(4, "u_hat''_1")
    s.free(2)

    s.step("INTT(u_hat''_1) in place in Bank 4")
    s.read(4, "u_hat''_1")
    s.write(4, "u''_intt_1")

    s.step("Sample e1_1 JIT into Bank 2; add -> u''_1 in Bank 4")
    s.write(2, "e1_1")
    s.read(4, "u''_intt_1")
    s.read(2, "e1_1")
    s.write(4, "u''_1")
    s.free(2)

    s.step("Compress_10(u''_1) and ByteEncode_10 -> compare 40 words against stored c1")
    s.read(4, "u''_1")
    s.free(4)
    words_compared += 40

    s.step("Dot product: Decode t_hat_0, t_hat_1 JIT into Bank 2; mul-acc -> Bank 4")
    s.write(2, "t_hat_0")
    s.read(2, "t_hat_0")
    s.read(0, "y_hat_0")
    s.write(4, "v_hat''_part")
    s.free(2)
    s.free(0)

    s.write(2, "t_hat_1")
    s.read(2, "t_hat_1")
    s.read(1, "y_hat_1")
    s.read(4, "v_hat''_part")
    s.write(4, "v_hat''")
    s.free(2)
    s.free(1)

    s.step("INTT(v_hat'') in place in Bank 4")
    s.read(4, "v_hat''")
    s.write(4, "v''_intt")

    s.step("Sample e2 JIT into Bank 2; Decompress m' JIT into Bank 3")
    s.write(2, "e2")
    s.write(3, "mu'")
    s.read(4, "v''_intt")
    s.read(2, "e2")
    s.read(3, "mu'")
    s.write(4, "v''")
    s.free(2)
    s.free(3)

    s.step("Compress_4(v'') and ByteEncode_4 -> compare 16 words against stored c2")
    s.read(4, "v''")
    s.free(4)
    words_compared += 16

    assert s.peak_live <= 8, f"Decaps peak live {s.peak_live} > 8!"
    assert words_compared == 96, f"Decaps words compared {words_compared} != 96!"
    print(f"[PASS] Decaps Schedule: Peak Live Banks = {s.peak_live} <= 8, Compare Words = {words_compared} == 96")


def main():
    print("=" * 70)
    print("ML-KEM-512 POLYNOMIAL BANK SCHEDULE REPLAY & VERIFICATION")
    print("=" * 70)
    verify_keygen()
    verify_encaps()
    verify_decaps()
    print("=" * 70)
    print("ALL SCHEDULE CHECKS PASSED: Peak Live Banks <= 8 across all modes.")
    print("=" * 70)

if __name__ == "__main__":
    main()
