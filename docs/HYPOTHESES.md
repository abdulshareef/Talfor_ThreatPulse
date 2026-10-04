# Hunting hypotheses (v0.1)

Each rule is written as a falsifiable hypothesis: *"If X is happening, we will observe Y."*
A rule hit means the observation exists. It does not by itself prove the hypothesis, so the
fusion score and the analyst's review make that call.

| ID | If… | …then we will observe | Data source | Main false-positive sources |
|---|---|---|---|---|
| TP-H01 | a user opened a weaponised document | Office spawns cmd / PowerShell / wscript / mshta / rundll32 / certutil… | Sysmon 1, Security 4688 | Finance macros that shell out |
| TP-H02 | credentials are being harvested | a non-system process opens `lsass.exe` with read rights (0x1010, 0x1410, 0x1fffff…) | Sysmon 10 | EDR / backup agents |
| TP-H03 | payloads are being staged | PowerShell with `-enc` blobs or download cradles (`DownloadString`, `iwr`, `IEX`) | Sysmon 1, 4688 | Admin scripts pulling from internal repos |
| TP-H04 | an implant is checking in | ≥10 outbound connections to one external destination with inter-arrival CV ≤ 0.15 | Sysmon 3 | Monitoring agents with fixed polling |
| TP-H05 | the attacker is avoiding dropping tools | certutil `-urlcache`/`-decode`, rundll32 `javascript:`/URLs, regsvr32 `/i:http` + scrobj, mshta URLs, bitsadmin `/transfer` | Sysmon 1, 4688 | Rare legitimate certutil decoding |
| TP-H06 | the attacker wants to survive reboot | Run / Winlogon / IFEO registry writes, `schtasks /create`, 4698, 7045 (installers excluded) | Sysmon 1/13, 4688, 4698, 7045 | Per-user apps (OneDrive, Teams), so the learning layer suppresses them after feedback |
| TP-H07 | the attacker is moving laterally | PsExec/PAExec services or binaries, WmiPrvSE / WsmProvHost spawning shells, SMBExec `\\127.0.0.1\ADMIN$` | Sysmon 1, 4688, 7045 | SCCM / admin tooling |
| TP-H07b | stolen credentials are being reused | a network (type 3/10) logon for a user→host pair never seen before | Security 4624 | New staff, new servers (learns them after first sight) |
| TP-H08 | ransomware is about to encrypt | `vssadmin delete shadows`, `wmic shadowcopy delete`, `Win32_ShadowCopy` delete, `bcdedit recoveryenabled no`, `wbadmin delete` | Sysmon 1, 4688 | Backup-software maintenance |
| TP-H08b | files are being encrypted | ≥300 file-create events by one process on one host within 60 s | Sysmon 11 | Build tools, sync clients (exclusion list) |
| TP-H09 | the attacker is covering tracks | 1102 / 104 log clears, `wevtutil cl`, Defender exclusions / real-time protection disabled, Sysmon / WinDefend stopped | Security, System, Defender, Sysmon 1 | Rare admin activity, which should always be reviewed |
| TP-H10 | data or C2 rides over DNS | ≥8 long (≥24-char), high-entropy (≥3.5 bits) labels, or ≥80 unique subdomains, under one parent domain within 5 min | Sysmon 22 | CDNs, so allow-listed |
| TP-ML | something new and unusual is running | process launch rarer than ~all baseline launches, combined with rarity, path and masquerading signals (fused score ≥ 0.85) | Sysmon 1, 4688 | Genuinely new software, so label it FP once and it is suppressed |

All thresholds are in the YAML files under `threatpulse/rules/builtin/` and can be tuned per environment.
