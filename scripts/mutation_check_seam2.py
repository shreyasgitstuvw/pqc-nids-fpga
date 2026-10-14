#!/usr/bin/env python3
"""Mutation check for the C17 Seam-2 joint test (not part of CI; ~5 min).

C17 (sim/cocotb/test_seam2_kem_session.py) claims it would catch an
implicit-rejection leak. A test that never fails proves nothing, so this script
plants two classic leaks into a TEMP COPY of mlkem_top.v and requires the test to
FAIL on each, while passing on the unmodified copy:

  delay-on-reject   rejected Decaps asserts kem_done one cycle late (timing leak)
  verdict-on-reject rejected Decaps also strobes kem_key_invalid (verdict leak)

Your working tree is never modified. Run:  python scripts/mutation_check_seam2.py
Exit 0 = baseline passes and both mutants are caught; 1 otherwise.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOP = Path("rtl/crypto/kem/mlkem_top.v")
TEST = "seam2_authentic_vs_rejected_waveform_identical"

# Decaps tail: kem_done is raised here for both outcomes (see mlkem_top.v).
ANCHOR = ("                                kem_done          <= 1'b1;\n"
          "                                state_r           <= S_IDLE;\n")
REJECT = "is_decaps && !(c_match & (c_ram[c_ram_wr_addr] == enc_c_word_data) & (c_cmp_cnt == 8'd95))"
CLEAR = "            kem_done        <= 1'b0;\n            kem_key_invalid <= 1'b0;\n"


def once(text, needle, what):
    if text.count(needle) != 1:
        sys.exit(f"mutation anchor for {what} matched {text.count(needle)} times; "
                 f"mlkem_top.v changed, update this script")
    return text


def delay_on_reject(src):
    once(src, ANCHOR, "kem_done tail")
    once(src, CLEAR, "default clear")
    once(src, "    reg         c_match;\n", "c_match decl")
    s = src.replace(ANCHOR,
        f"                                if ({REJECT}) mut_dly <= 1'b1;\n"
        f"                                else kem_done <= 1'b1;\n"
        "                                state_r           <= S_IDLE;\n")
    s = s.replace("    reg         c_match;\n", "    reg         c_match;\n    reg         mut_dly;\n")
    return s.replace(CLEAR, CLEAR + "            mut_dly <= 1'b0;\n            if (mut_dly) kem_done <= 1'b1;\n")


def verdict_on_reject(src):
    once(src, ANCHOR, "kem_done tail")
    return src.replace(ANCHOR,
        "                                kem_done          <= 1'b1;\n"
        f"                                if ({REJECT}) kem_key_invalid <= 1'b1;\n"
        "                                state_r           <= S_IDLE;\n")


def run(tree):
    env = dict(os.environ, TESTCASE=TEST)
    cocotb_dir = tree / "sim" / "cocotb"
    res = cocotb_dir / "results.xml"
    if res.exists():
        res.unlink()
    subprocess.run([sys.executable, "test_seam2_kem_session.py"], cwd=cocotb_dir, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not res.exists():
        return None  # build/sim error: neither pass nor fail
    root = ET.parse(res).getroot()
    cases = root.iter("testcase")
    ran = [c for c in cases if c.get("name") == TEST]
    if not ran:
        return None
    return not any(c.find("failure") is not None for c in ran)  # True = test passed


def make_tree(tmp, name, mutate=None):
    tree = Path(tmp) / name
    ignore = shutil.ignore_patterns("sim_build*", "__pycache__", "results.xml", ".git")
    for d in ("rtl", "sim", "model"):
        shutil.copytree(REPO / d, tree / d, ignore=ignore)
    if mutate:
        p = tree / TOP
        p.write_text(mutate(p.read_text(encoding="utf-8")), encoding="utf-8")
    return tree


def main():
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        for name, mut, want_pass in (("baseline", None, True),
                                     ("delay-on-reject", delay_on_reject, False),
                                     ("verdict-on-reject", verdict_on_reject, False)):
            passed = run(make_tree(tmp, name.replace("-", "_"), mut))
            good = passed is want_pass
            state = {True: "test passed", False: "test FAILED", None: "sim error"}[passed]
            print(f"{name:18s} {state:12s} -> {'OK' if good else 'UNEXPECTED'}", flush=True)
            ok &= good
    print("MUTATION CHECK", "PASSED: C17 catches both leaks" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
