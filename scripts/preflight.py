#!/usr/bin/env python3
"""Deterministic pre-PR gate. Run: python scripts/preflight.py [--base origin/main] [--skip-sim]
Exit 0 only if every check passes. Antigravity must paste the full output into the PR body."""
import argparse, glob, os, re, subprocess, sys

# Windows scoop environment support
oss_bin = os.path.normpath(os.path.expanduser("~/scoop/apps/oss-cad-suite-nightly/current/bin"))
oss_lib = os.path.normpath(os.path.expanduser("~/scoop/apps/oss-cad-suite-nightly/current/lib"))
for p in (oss_bin, oss_lib):
    if os.path.exists(p) and p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
oss_share = os.path.normpath(os.path.expanduser("~/scoop/apps/oss-cad-suite-nightly/current/share/verilator"))
if os.path.exists(oss_share) and "VERILATOR_ROOT" not in os.environ:
    os.environ["VERILATOR_ROOT"] = oss_share

FROZEN = ["model/mlkem/", "model/sha3.py", "sim/vectors/"]
fails = []

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n    {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)

def changed_files(base):
    r = run(f"git diff --name-only {base}...HEAD")
    return [l for l in r.stdout.splitlines() if l]

def comment_lines(path):
    """Return (lineno, text) for // comments and python docstring/# lines."""
    out, in_doc = [], False
    for i, l in enumerate(open(path, encoding="utf-8", errors="ignore"), 1):
        s = l.strip()
        if path.endswith(".v") and s.startswith("//"):
            out.append((i, s))
        elif path.endswith(".py"):
            if s.startswith("#"):
                out.append((i, s))
            if s.count('"""') == 1:
                in_doc = not in_doc
                out.append((i, s))
            elif in_doc or s.count('"""') >= 2:
                out.append((i, s))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--skip-sim", action="store_true")
    a = ap.parse_args()
    files = changed_files(a.base)

    # 1. Frozen paths untouched
    bad = [f for f in files if any(f.startswith(p) for p in FROZEN)]
    check("no frozen paths modified", not bad, f"modified: {bad}")

    # 2. Never on main, never merged here
    br = run("git rev-parse --abbrev-ref HEAD").stdout.strip()
    check("working on a feature branch (not main)", br not in ("main", "master"), f"branch={br}")

    # 3. Verilator lint, warnings are errors, every changed .v
    for f in [f for f in files if f.endswith(".v") and f.startswith("rtl/")]:
        inc = " ".join(f"-I{d}" for d in glob.glob("rtl/**/", recursive=True))
        r = run(f"verilator --lint-only -Wall {inc} {f}")
        check(f"verilator -Wall clean: {f}", r.returncode == 0, r.stderr[-600:])
        txt = open(f, encoding="utf-8").read()
        check(f"`timescale present: {f}", "`timescale" in txt)

    # 4. Stale-number check: every "N cycles" in comments/docstrings must also
    #    appear in an assert/== line of the matching test file.
    for f in [f for f in files if f.endswith((".v", ".py")) and (f.startswith("rtl/") or f.startswith("sim/cocotb/"))]:
        stem = re.sub(r"^test_", "", os.path.splitext(os.path.basename(f))[0])
        tests = glob.glob(f"sim/cocotb/test_{stem}.py")
        if not tests:
            continue
        asserted = set()
        for l in open(tests[0], encoding="utf-8"):
            if "assert" in l or "==" in l or "EXPECT" in l.upper():
                asserted |= set(re.findall(r"\b\d{2,5}\b", l))
        for ln, c in comment_lines(f):
            for n in re.findall(r"\b(\d{2,5})\s*(?:clock\s+)?cycles?\b", c):
                check(f"{f}:{ln} comment says {n} cycles -> backed by an assert", n in asserted,
                      f"'{n}' is not in any assert in {tests[0]} (stale or unmeasured number)")

    # 5. Resource / timing figures must be labelled as estimates
    for f in [f for f in files if f.endswith(".v") and f.startswith("rtl/")]:
        for ln, c in comment_lines(f):
            if re.search(r"\b\d+\s*(LUTs?|FFs?|DSP48E1|BRAM)\b|~\s*\d+\s*(LUT|FF)", c, re.I) \
               and not re.search(r"estimat|measured|synth report", c, re.I) \
               and not re.search(r"estimat", "".join(l for _, l in comment_lines(f)[:40]), re.I):
                check(f"{f}:{ln} resource figure labelled", False, c)

    # 6. Every new RTL module has a cocotb test file
    for f in [f for f in files if f.endswith(".v") and f.startswith("rtl/")]:
        mod = os.path.splitext(os.path.basename(f))[0]
        check(f"test file exists for {mod}", os.path.exists(f"sim/cocotb/test_{mod}.py") or
              any(mod in open(t, encoding='utf-8').read() for t in glob.glob("sim/cocotb/test_*.py")))

    # 7. cocotb tests no test_ coroutines (pytest-collision pitfall)
    for t in glob.glob("sim/cocotb/test_*.py"):
        src = open(t, encoding="utf-8").read()
        for m in re.finditer(r"@cocotb\.test\(\)\s*\nasync def (test_\w+)", src):
            check(f"{t}: coroutine '{m.group(1)}' must not start with test_", False)

    # 8. Simulation suite
    if not a.skip_sim:
        py_cmd = sys.executable
        try:
            import cocotb  # noqa: F401
        except ImportError:
            scoop_py = os.path.normpath(os.path.expanduser("~/scoop/apps/python311/current/python.exe"))
            if os.path.exists(scoop_py):
                py_cmd = scoop_py

        r = run(f'"{py_cmd}" -m pytest sim/cocotb -q --noconftest')
        check("pytest sim/cocotb passes", r.returncode == 0, r.stdout[-800:])
        for s in sorted(set(glob.glob("model/*_hw.py"))):
            r = run(f'"{py_cmd}" {s}')
            check(f"model self-test: {s}", r.returncode == 0, r.stdout[-400:])

    print("\nPREFLIGHT", "PASSED" if not fails else f"FAILED ({len(fails)} checks)")
    sys.exit(1 if fails else 0)

main()
