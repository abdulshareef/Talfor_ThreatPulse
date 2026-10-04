# Hunting hypotheses (v0.1)

Each rule is written as a falsifiable hypothesis: *"If X is happening, we will observe Y."*
A rule hit means the observation exists. It does not by itself prove the hypothesis, so the
fusion score and the analyst's review make that call.

There are **10 primary hypotheses**. H07, H08, H09 and H10 each contain a sub-hypothesis
implemented as its own detection, which gives 14 detections in total.

## ATT&CK mapping policy

- **Per-alert, evidence-based.** Each rule's `technique_map` ties ATT&CK techniques to the
  detection selection that observed them. An alert carries only the techniques of the
  selections that matched, plus any `mitre_always` techniques. The `mitre` list in each rule
  is the hypothesis-level coverage, used for documentation and listing.
- **Analytics decide from what they saw.** Behavioural analytics attach a technique only
  when their observations support it:
  - TP-H04 claims T1071.001 only on web ports.
  - TP-H08b claims T1486 only when encryption indicators are present.
- **Sub-techniques are preferred** where the observation identifies one. The parent
  technique is used when it does not; for example, `wscript`/`cscript` could be running
  either VBScript or JScript, so T1059 is used.
- **Learned anomalies (TP-ML) carry no technique.** An anomaly score does not evidence a technique.

## Detections

| ID | If… | …then we will observe | Data source | ATT&CK (per matched observation) | Main false-positive sources |
|---|---|---|---|---|---|
| TP-H01 | a user opened a weaponised document | Office spawns PowerShell, cmd, wscript/cscript, mshta, rundll32, regsvr32, hh, InstallUtil, MSBuild, certutil, bitsadmin or schtasks | Sysmon 1, Security 4688 | always T1566.001, T1204.002; PowerShell T1059.001; cmd T1059.003; WSH T1059; mshta T1218.005; regsvr32 T1218.010; rundll32 T1218.011; hh T1218.001; InstallUtil T1218.004; MSBuild T1127.001 | Finance macros that shell out |
| TP-H02 | credentials are being harvested | a non-system process opens `lsass.exe` with read rights (0x1010, 0x1410, 0x1fffff…) | Sysmon 10 | T1003.001 | EDR / backup agents |
| TP-H03 | payloads are being staged | PowerShell with `-enc` blobs, obfuscation (`FromBase64String`, `-bxor`, `IEX`) or download cradles (`DownloadString`, `iwr`) | Sysmon 1, 4688 | always T1059.001; encoded/obfuscated T1027; cradle T1105 | Admin scripts pulling from internal repos |
| TP-H04 | an implant is checking in | ≥10 outbound connections to one external destination with inter-arrival CV ≤ 0.15 | Sysmon 3 | T1071.001 on ports 80/443/8080/8443, otherwise T1071. T1573 is not claimed | Monitoring agents with fixed polling |
| TP-H05 | the attacker is avoiding dropping tools | certutil `-urlcache` / `-decode`, rundll32 `javascript:` / URLs, regsvr32 `/i:http` + scrobj, mshta URLs, bitsadmin `/transfer` | Sysmon 1, 4688 | certutil download T1105; certutil decode T1140; rundll32 T1218.011; regsvr32 T1218.010; mshta T1218.005; bitsadmin T1197 + T1105 | Rare legitimate certutil decoding |
| TP-H06 | the attacker wants to survive reboot | Run/RunOnce values, Winlogon Userinit/Shell/Notify, IFEO `Debugger`/`GlobalFlag`, SilentProcessExit `MonitorProcess`, `schtasks /create`, 4698, 7045 (installers excluded) | Sysmon 1/13, 4688, 4698, 7045 | Run keys T1547.001; Winlogon T1547.004; IFEO / SilentProcessExit T1546.012; tasks T1053.005; services T1543.003 | Per-user apps (OneDrive, Teams); the learning layer suppresses them after feedback |
| TP-H07 | the attacker is moving laterally | PsExec/PAExec service or binary, SMBExec `\\127.0.0.1\ADMIN$` service commands, WmiPrvSE or WsmProvHost spawning shells | Sysmon 1, 4688, 7045 | PsExec/PAExec/SMBExec T1569.002 + T1021.002; WMI T1047; WinRM T1021.006 | SCCM / admin tooling |
| TP-H07b | stolen credentials are being reused | a network (type 3/10) logon for a user→host pair never seen before. The first-seen relationship is the analytic; valid-account abuse is the hypothesis it tests | Security 4624 | T1078 | New staff, new servers (learned after first sight) |
| TP-H08 | ransomware is about to encrypt | `vssadmin delete shadows`, `wmic shadowcopy delete`, `Win32_ShadowCopy` delete, `bcdedit recoveryenabled no`, `wbadmin delete` | Sysmon 1, 4688 | T1490 | Backup-software maintenance |
| TP-H08b | files are being encrypted | ≥300 file-create events by one process on one host within 60 s | Sysmon 11 | T1486 **only** if ≥70% of the burst shares one uncommon extension appended to a normal one; otherwise no technique (behavioural signal) | Build tools, archive extraction, sync clients |
| TP-H09 | the attacker is covering tracks | 1102 / 104 log clears, `wevtutil cl`, `Clear-EventLog` / `Remove-EventLog` | Security, System, Sysmon 1 | T1070.001 | Rare admin log maintenance (always review) |
| TP-H09b | the attacker is impairing defences | Defender real-time protection disabled or exclusions added (5001/5013, `Set-MpPreference` / `Add-MpPreference`), WinDefend/Sysmon stopped, Sysmon unloaded (`sysmon -u`, `fltmc unload`) | Defender, Sysmon 1, 4688 | T1562.001 | Authorised troubleshooting by endpoint admins |
| TP-H10 | C2 or data rides over DNS | ≥8 long (≥24-char), high-entropy (≥3.5 bits) labels, or ≥80 unique subdomains, under one parent domain within 5 min | Sysmon 22 | T1071.004 | CDNs and security products that encode data in DNS (allow-list them) |
| TP-H10b | malware uses a domain generation algorithm | ≥15 distinct random-looking registrable domains (label ≥8 chars, ≥3.0 bits entropy) failing to resolve from one host within 10 min | Sysmon 22 (QueryStatus ≠ 0) | T1568.002 | Browser DNS-hijack probes (single-label, so filtered) |
| TP-ML | something new and unusual is running | process launch rarer than ~all baseline launches, combined with rarity, path and masquerading signals (fused score ≥ 0.85) | Sysmon 1, 4688 | none (anomaly, not a technique) | Genuinely new software; label it FP once and it is suppressed |

All thresholds are in the YAML files under `threatpulse/rules/builtin/` and can be tuned per environment.
