# Opens the four rehearsal windows (board, B, A, attacker C). Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File demo_sim\run_demo.ps1
$root = (Get-Location).Path
function Open-Win($title, $cmd) {
    Start-Process powershell -ArgumentList "-NoExit","-Command",
        "`$Host.UI.RawUI.WindowTitle='$title'; Set-Location '$root'; $cmd"
}
Open-Win "BOARD (simulated)" "python demo_sim\board_sim.py"
Start-Sleep -Seconds 2
Open-Win "Device B" "python demo_sim\chat_sim.py --me B"
Start-Sleep -Seconds 2
Open-Win "Device A" "python demo_sim\chat_sim.py --me A"
Start-Sleep -Seconds 2
Open-Win "Device C (attacker)" "python demo_sim\attacker_sim.py"
