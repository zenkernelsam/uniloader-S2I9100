#!/usr/bin/env python3
"""Morning one-shot: phone in download mode -> flash control kernel -> boot ->
persistent-session capture of threads/ports for backboardd/SpringBoard/launchd.

odin-loop.py's Host.inventory() requires Windows (powershell.exe), so all
plan/execute calls go through Windows python.exe with D:\\ paths.
Run in WSL:  python3 /root/i9100d/tools/dbg/morning.py
Requires: phone already in DOWNLOAD mode (VID_04E8 visible)."""
import json, subprocess, sys, time, os, glob, hashlib, re

WROOT = "/root/i9100d"                                   # WSL view
DROOT = "D:\\Desktop\\Git\\ios-samsung-i9100"            # Windows view
UNI   = WROOT + "/neighbor/uniloader"
DUNI  = DROOT + "\\neighbor\\uniloader"
PKG   = UNI + "/out/control-20261108-124500"
DPKG  = DUNI + "\\out\\control-20261108-124500"
STAMP = time.strftime("%H%M%S")
OUT   = WROOT + "/tools/dbg/morning-" + STAMP
OUTW  = DROOT + "\\tools\\dbg\\morning-" + STAMP
PYEXE = "/mnt/c/Users/Cisco He/AppData/Local/Programs/Python/Python312/python.exe"
ODIN  = DUNI + "\\scripts\\i9100\\odin-loop.py"
PROFW = DUNI + "\\out\\automation\\morning-profile-%s.json" % STAMP
PROF  = UNI + "/out/automation/morning-profile-%s.json" % STAMP
os.makedirs(OUT, exist_ok=True)

def wrun(*a, t=300):
    """Windows python via WSL interop."""
    print("+ py.exe", " ".join(str(x) for x in a), flush=True)
    return subprocess.run([PYEXE] + list(a), capture_output=True, timeout=t)

def ps(cmd):
    r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", cmd],
                       capture_output=True, timeout=60)
    # PowerShell may emit GBK/legacy bytes; decode tolerantly.
    return r.stdout.decode('utf-8', errors='replace') + \
        r.stderr.decode('utf-8', errors='replace')

def show(r, n=400):
    out = (r.stdout or b'').decode('utf-8', errors='replace')
    err = (r.stderr or b'').decode('utf-8', errors='replace')
    print(out[-n:], err[-200:], flush=True)

# 0) verify download mode present (Samsung VID_04E8 download device)
inv = ps("Get-PnpDevice -PresentOnly | Select-Object -ExpandProperty InstanceId")
if "VID_04E8" not in inv:
    sys.exit("phone not in download mode (no VID_04E8). Aborting before any USB touch.")
print("download-mode device present", flush=True)

# 1) observe-download -> unique profile path (exclusive create)
r = wrun(ODIN, "observe-download", "--output", PROFW)
show(r)
if not os.path.exists(PROF):
    sys.exit("observe-download produced no profile")

# 2) plan (offline snapshot; Windows paths stored in plan.json)
r = wrun(ODIN, "plan", "--image", DPKG + "\\zImage", "--profile", PROFW)
show(r)
plan = None
i = (r.stdout or b'').decode('utf-8', errors='replace').find("{")
if i >= 0:
    plan = json.loads((r.stdout or b'').decode('utf-8', errors='replace')[i:])
if not plan:
    sys.exit("no plan json")
print("plan:", plan["plan"])

# 3) execute --mode bootstrap: phone is ALREADY in download mode; skips the
#    CDC reboot-download step, flashes KERNEL, waits for CDC boot + verify.
zsha = hashlib.sha256(open(PKG + "/zImage", "rb").read()).hexdigest()
r = wrun(ODIN, "execute",
        "--plan", plan["plan"], "--approve-plan", plan["approve_plan_sha256"],
        "--mode", "bootstrap", "--confirm-kernel", zsha, t=900)
show(r, 1500)

# 4) wait for the CDC COM port, then one persistent i9sess for all verbs
port = None
for _ in range(80):
    for line in ps("Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'COM\\d+'} | Select-Object -Expand Name").splitlines():
        if "S2I9100" in line or "USB" in line or "CDC" in line:
            m = re.search(r"COM(\d+)", line)
            if m: port = "COM" + m.group(1)
    if port: break
    time.sleep(5)
print("port:", port)
if not port:
    sys.exit("no COM port; check device state")

fetch = subprocess.run([PYEXE, DROOT + "\\tools\\dbg\\i9sess.py", port,
                        OUTW + "\\f",
                        "ping", "root-status",
                        "threads backboardd", "ports backboardd",
                        "threads SpringBoard", "ports SpringBoard",
                        "threads launchd", "ports launchd"],
                       capture_output=True, timeout=1200)
print((fetch.stderr or b'').decode('utf-8', errors='replace')[-2000:])

# decode threads (symbol annotation) then cross-reference with ports
for f in glob.glob(OUT + "/f-threads-*.bin"):
    if os.path.getsize(f):
        dec = subprocess.run(["python3", WROOT + "/tools/dbg/winfo_decode.py", f],
                             capture_output=True, text=True).stdout
        open(f + ".decoded", "w").write(dec)
        print("==== %s ====" % os.path.basename(f))
        print(dec[:4000])
allf = [OUT + "/" + f for f in os.listdir(OUT)
        if f.endswith(".bin") and "console" not in f]
ana = subprocess.run(["python3", WROOT + "/tools/dbg/winfo_analyze.py"] + allf,
                     capture_output=True, text=True).stdout
open(OUT + "/analyze.txt", "w").write(ana)
print("==== analyze ====")
print(ana[:6000])
print("artifacts:", OUT)
