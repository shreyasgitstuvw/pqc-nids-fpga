# Environment Setup Guide (Windows)
## Getting Your System Ready — Before You Touch the Repo

Every team member is on Windows, so this guide is written specifically for that — no cross-platform hedging. Read it top to bottom once, in order; it's structured as: install Vivado → if you don't have space/hardware for that, here's your fallback → the tools everyone needs regardless → VS Code setup → a table of README commands that need adjusting on Windows → a final checklist.

---

## 1. Installing Vivado on Windows

### 1.1 Check your system first
Vivado is a large install (30–90 GB depending on which device families you include) and genuinely resource-hungry. Before downloading anything, confirm:
- **Disk space:** at least 100 GB free, ideally on an SSD. The installer itself needs staging space on top of the final install size.
- **RAM:** 16 GB minimum; 8 GB will technically run it but synthesis/implementation on even a small device like the XC7Z020 will be slow and occasionally unstable.
- **OS:** Windows 10 or 11, 64-bit. Confirm with `winver` (Win+R → type `winver`).

If you don't clear the disk-space bar comfortably, skip to §2 now rather than fighting through a half-finished install — it's a very common failure mode and not worth the time lost.

### 1.2 Which edition to install
Your synopsis specifies the XC7Z020 (ZedBoard), and explicitly notes the **free Vivado Design Suite Standard edition covers this device** — you do not need a paid license or Vivado ML Enterprise. Get **Vivado ML Standard** (formerly "WebPACK") from AMD/Xilinx's downloads page.

### 1.3 Download and install
1. Go to the official AMD/Xilinx downloads page (search "Xilinx Vivado downloads" — always get it from `xilinx.com`/`amd.com` directly, never a mirror).
2. Create a free Xilinx/AMD account if you don't have one — required to download, no cost.
3. Download the **Vivado ML Standard Edition** Windows installer (a small bootstrap `.exe` that then downloads the rest).
4. Run the installer as Administrator. When prompted for device families to install, you only strictly need **Zynq-7000** support — deselecting unrelated families (Versal, UltraScale+, etc.) saves a large amount of disk space and install time. If unsure, this is the single most effective way to cut a 90 GB install down to something much more manageable.
5. Accept the default install path unless you have a specific reason not to (avoid spaces in the path — e.g. avoid installing under `C:\Program Files\` if you can choose `C:\Xilinx\` instead; Vivado and Tcl scripts have a long, well-known history of choking on spaces in paths).
6. Let it finish — this genuinely takes hours on a normal connection. Start it before you go to sleep or during a class you don't need your laptop for.

### 1.4 Licensing
The Standard/WebPACK edition is free and doesn't require a separate license file for the device families you need here — it self-licenses on first launch. If you're prompted for a license and you selected only WebPACK-covered device families (Zynq-7000 included), choose the "Get Free ISE WebPACK License" or equivalent option in the license manager rather than pursuing a paid license.

### 1.5 Verify it works
Open **Vivado** from the Start Menu, then in the Tcl Console at the bottom (or via `Tools → Run Tcl Script`), run:
```tcl
puts "vivado ok"
```
If that prints, your install is functional. Next, confirm command-line batch mode works too — this is what `scripts/build_bitstream.tcl` from the main README actually uses:
```powershell
# In PowerShell, from Vivado's install directory or with Vivado added to PATH:
vivado -mode batch -source nul
```
(This just launches batch mode against an empty script — if it doesn't immediately error about the executable itself being missing, your PATH is set up correctly. Full functional testing happens once you actually run `build_bitstream.tcl` against the real repo.)

If `vivado` isn't recognized as a command, add its `bin` directory to your PATH (Settings → search "environment variables" → Edit the `Path` variable under your user account → add something like `C:\Xilinx\Vivado\2024.x\bin`).

---

## 2. No space or hardware for Vivado? Here's your fallback

This is a completely normal situation on a shared family laptop or a smaller SSD, and it does **not** block you from doing the large majority of the project's work. Here's the key fact: **Vivado is only needed for Phase VII (timing closure) and building the final bitstream** (§6 of the main README). Every RTL module, every cocotb testbench, every Python reference model, and all of Phases I–VI run on tools that are a fraction of the size and work on almost any machine.

### Your plan if you can't install Vivado locally:
1. **Do all RTL development, simulation, and verification on your own machine** using the lightweight toolchain in §3 below (Icarus Verilog + cocotb) — this is genuinely everyone's day-to-day workflow regardless of whether they have Vivado installed, since Vivado isn't used for iteration-speed testing anyway.
2. **Designate one shared machine (or the department lab) for Vivado-specific steps.** Whoever on the team does have the disk space, or a lab machine, runs `scripts/build_bitstream.tcl` against the same repo (pulled fresh via `git clone`/`git pull`) once RTL is verified and ready for synthesis. You don't need to be present for this — push your verified branch, have that person pull and build.
3. **If literally nobody on the team has local Vivado space**, check with your project supervisor/coordinator about department lab access — most EE departments running Zynq/Vivado coursework have lab machines with it pre-installed specifically for this reason. This is a completely standard ask, not a workaround to be embarrassed about.
4. **A free, lighter-weight alternative for early sanity-checking (not a Vivado replacement):** some open-source toolchains (e.g. F4PGA/SymbiFlow-adjacent projects) exist for other Xilinx families, but **Zynq-7000 is not well supported by open-source synthesis toolchains** — don't spend time chasing this route for the real bitstream build. Use it only if you specifically want extra lint/synthesis-sanity feedback beyond simulation, and treat Vivado as the only trustworthy path to a real, working bitstream on this hardware.

The practical upshot: not having Vivado installed should never be the reason you're blocked before Phase VII. If you find yourself stuck because of it earlier than that, something's being asked of you that shouldn't need Vivado — flag it.

---

## 3. The toolchain everyone needs, regardless of Vivado status

Install these on every team member's machine — this is what you actually use day to day.

### 3.1 Git
Download **Git for Windows** from `git-scm.com`. During install, accept defaults, but on the "Adjusting your PATH environment" step, choose **"Git from the command line and also from 3rd-party software"** — this also gives you **Git Bash**, a Unix-like shell that will save you real pain later (see §6).

```powershell
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
git config --global core.autocrlf true
```
The `autocrlf true` setting matters specifically on Windows — without it, Git silently converts line endings on every file you touch, which creates noisy diffs and can occasionally trip up tools that care about exact line endings (some Verilog testbench comparisons among them).

Clone the repo:
```powershell
git clone <repo-url>
cd pqc-nids-fpga
```

### 3.2 Python 3.11+
Download from `python.org` — **not** the Microsoft Store version, which has historically had PATH and permissions quirks that cause exactly the kind of "works for me, not for you" friction this whole doc is trying to prevent. During install, **check "Add python.exe to PATH"** on the first installer screen — this is the single most commonly missed step and the source of most "python isn't recognized" problems afterward.

Verify:
```powershell
python --version
```
Should show 3.11 or newer. If it shows something else or errors, close and reopen your terminal first (PATH changes need a fresh shell), and if that doesn't fix it, reinstall with the PATH checkbox this time.

Set up your project virtual environment:
```powershell
cd pqc-nids-fpga
python -m venv .venv
.venv\Scripts\Activate.ps1
```
If PowerShell blocks that last command with a script-execution policy error, run this once (as your normal user, not Administrator):
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
Then retry activation. Once activated, your prompt should show `(.venv)` at the start.

```powershell
pip install --upgrade pip
pip install cocotb pytest ruff black
```

### 3.3 Icarus Verilog + GTKWave
Get the Windows installer from the [Icarus Verilog releases page](https://github.com/steveicarus/iverilog) (via `bleyer.org/icarus` mirror or GitHub releases — search "Icarus Verilog Windows installer"). This installer bundles GTKWave as well, so one install covers both. Accept defaults; it adds `iverilog`, `vvp`, and `gtkwave` to your PATH automatically.

Verify:
```powershell
iverilog -V
gtkwave --version
```
Both should print version info without error.

### 3.4 Verilator (only if your track needs it — see §3.5)
Verilator's native Windows support is genuinely weak — the practically reliable way to run it on Windows is through **Git Bash + a prebuilt MSYS2 package**, or simplest of all, inside **WSL2** (Windows Subsystem for Linux) if you're comfortable setting that up:
```powershell
wsl --install -d Ubuntu-22.04
```
then, inside the Ubuntu shell that opens:
```bash
sudo apt update && sudo apt install -y verilator
```
If your track doesn't specifically need Verilator's speed advantage (mainly relevant for large random-vector test runs on the crypto lane's NTT/Keccak testbenches), skip this section entirely — Icarus Verilog alone covers everything else.

### 3.5 Who actually needs what
| Track | Icarus Verilog | GTKWave | Verilator | Vivado |
|---|---|---|---|---|
| Ingress / parser | Required | Recommended (UART timing debug) | Not needed | Only for Phase VII |
| Detection lane | Required | Recommended | Not needed | Only for Phase VII |
| ML-KEM crypto core | Required | Recommended | Recommended (large random-vector NTT tests run faster) | Only for Phase VII |
| ChaCha/Poly/control | Required | Recommended | Not needed | Only for Phase VII |

---

## 4. VS Code setup

Download VS Code from `code.visualstudio.com`, then install these extensions (open VS Code → Extensions sidebar → search each by name):

- **Verilog-HDL/SystemVerilog** (publisher: mshr-h) — syntax highlighting and basic linting for your `.v` files
- **Python** (publisher: Microsoft) — for everything in `model/` and `sim/cocotb/`
- **GitLens** (optional but useful) — makes it easier to see who last touched a shared file, relevant to the multi-owner coordination rules in the main README §8
- **WSL** (publisher: Microsoft) — install this even if you're not using WSL2 daily; it's what lets VS Code cleanly open a project living inside WSL2's filesystem if you end up there for Verilator (§3.4)

Open the repo in VS Code from a terminal already inside the project folder with the venv active:
```powershell
cd pqc-nids-fpga
code .
```
This ensures VS Code inherits the right working directory. Once open, set VS Code's default terminal to PowerShell (usually the default already) or Git Bash if you prefer Unix-style commands — set this via the dropdown next to the `+` in VS Code's integrated terminal panel.

---

## 5. Verify your whole simulation toolchain in one shot

Before touching real project files, confirm everything is wired together correctly:
```powershell
mkdir sim-check
cd sim-check
echo 'module foo; initial begin $display("toolchain ok"); $finish; end endmodule' > foo.v
iverilog -o foo.vvp foo.v
vvp foo.vvp
cd ..
rmdir /s /q sim-check
```
If you see `toolchain ok` printed, Icarus Verilog is correctly installed and callable from your shell. If this fails, fix it here before opening the real repo — debugging a toolchain problem is much easier on a two-line throwaway file than inside the actual project.

---

## 6. README commands that need adjusting on Windows

The main `README.md`'s examples were written with a generic Unix-style shell in mind. Here's exactly what to change when running them from native Windows (PowerShell or cmd):

| README command | Problem on native Windows | Fix |
|---|---|---|
| `source .venv/bin/activate` | This is a Bash syntax; PowerShell has no `source` and the path structure differs | Use `.venv\Scripts\Activate.ps1` instead (see §3.2) |
| `cd sim && make test_ntt` | `make` isn't installed on Windows by default | Either install it via [Chocolatey](https://chocolatey.org) (`choco install make`), or open the `sim/Makefile`, find the underlying `iverilog`/cocotb command the target runs, and call that directly in PowerShell |
| `./scripts/run_all_sim.sh` | `.sh` scripts don't execute natively in PowerShell/cmd | Run it from **Git Bash** instead (installed alongside Git for Windows, §3.1) — right-click the repo folder → "Git Bash Here" → run the script there |
| `python scripts/measure_timing.py` | Usually fine once PATH is set correctly (§3.2), but occasionally `python` resolves to a Microsoft Store stub that does nothing | If `python --version` doesn't show a real version number, reinstall Python from python.org with "Add to PATH" checked, and remove/disable the Store alias under Settings → Apps → Advanced app settings → App execution aliases |
| `vivado -mode batch -source build_bitstream.tcl` | Works fine natively on Windows once Vivado's `bin` directory is on PATH — the one real gotcha is spaces in file paths | If you installed Vivado or cloned the repo under a path containing spaces (e.g. inside `OneDrive` folders, which often have none, but some usernames do, like `C:\Users\John Smith\...`), you may hit Tcl parsing errors; safest fix is cloning the repo into a short, space-free path like `C:\dev\pqc-nids-fpga` |
| Any command using `~` for your home directory | Inconsistent behavior between PowerShell 5.1 and 7+, and meaningless in cmd | Use `$env:USERPROFILE` in PowerShell, or just use full paths |

**General rule of thumb:** if a README command is a shell script (`.sh`) or uses Bash-specific syntax, run it from **Git Bash**, not PowerShell or cmd — it's already installed from §3.1 and saves you from re-deriving a PowerShell equivalent for every script in the repo.

---

## 7. Sanity checklist — confirm before you touch the real repo

- [ ] `git --version` runs
- [ ] `python --version` shows 3.11+
- [ ] `.venv\Scripts\Activate.ps1` activates cleanly and `pip list` shows `cocotb`
- [ ] `iverilog -V` and `gtkwave --version` both run
- [ ] The §5 toolchain check prints `toolchain ok`
- [ ] `git clone` of the real repo succeeds, `git status` shows a clean tree
- [ ] VS Code opens the repo with Verilog and Python extensions showing as **enabled** (not just installed) in the Extensions sidebar
- [ ] You know your Vivado situation concretely: installed locally (§1) or using the shared-machine fallback (§2) — and if it's the fallback, you know who on the team has it
- [ ] The repo is cloned into a short, space-free path (e.g. `C:\dev\pqc-nids-fpga`), to avoid the Vivado/Tcl path issue in §6

Once every box is checked, go to your individual member guide and start on Phase I/II of the build order.