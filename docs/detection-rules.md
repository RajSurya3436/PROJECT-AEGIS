# Detection rules

Deterministic, versioned rules over stored events. No model, network or API key is involved, so
detection works with Ollama stopped. Code: `app/detection/`. Every alert records the rule ID and
version, a severity, a plain-language explanation, a dedup key, and the exact event IDs that
matched (with a reason for each).

Rules are **Python classes** (subclasses of `Rule` in `app/detection/base.py`), not a query
language such as Sigma, KQL or SPL. Each one is a pure function of the stored events plus its
integer thresholds; pattern rules use fixed, documented regular expressions. Each rule also
carries a tactic `category` and the MITRE ATT&CK technique IDs it is evidence for (shown in the
UI; they do not change what matches). Register a new rule in `app/detection/registry.py`.

## Rules

| Rule | v | Severity | Fires when | Default thresholds |
|---|---|---|---|---|
| `auth.repeated_failures` | 1 | medium | at least N failed logons for one user from one source IP within a window | `threshold` 5, `window_seconds` 300 |
| `auth.failures_then_success` | 1 | high | a failure burst, then a success for the same user and IP after the last failure | `failure_threshold` 3, `failure_window_seconds` 600, `success_within_seconds` 900 |
| `auth.password_spray` | 1 | medium | failures for at least N distinct users from one source IP within a window | `distinct_users` 5, `window_seconds` 600 |
| `auth.distributed_brute_force` | 1 | medium | failures for one user from at least N distinct source IPs within a window (T1110.001) | `distinct_sources` 4, `window_seconds` 900 |
| `auth.success_from_ioc` | 1 | high | a successful logon whose `src_ip` is in the local IOC list (T1078) | `session_gap_seconds` 3600 |
| `process.suspicious_powershell` | 1 | high | PowerShell command line with an indicator (below) | `min_indicators` 1, `session_gap_seconds` 600 |
| `process.office_child_shell` | 1 | high | an Office app (Word, Excel, Outlook, ...) is the parent of cmd, PowerShell, a script host or a LOLBin (T1566.001, T1204.002) | `min_indicators` 1, `session_gap_seconds` 900 |
| `process.credential_dumping` | 1 | critical | Mimikatz commands, LSASS dumps (procdump, comsvcs MiniDump), `reg save` of SAM/SECURITY/SYSTEM, ntdsutil IFM (T1003) | same |
| `process.discovery_burst` | 1 | medium | at least N *different* discovery commands (whoami, net user/group, nltest, systeminfo, ipconfig, ...) by one user on one host within a window (T1087, T1069, T1082, T1016, T1033) | `distinct_commands` 3, `window_seconds` 600 |
| `process.persistence` | 1 | medium | `schtasks /create`, Run/RunOnce key writes, `sc create`/`New-Service`, cron writes (T1053, T1547.001, T1543.003) | `min_indicators` 1, `session_gap_seconds` 900 |
| `process.account_manipulation` | 1 | high | `net user ... /add`, adding to Administrators / Remote Desktop Users, `useradd`, `usermod -aG sudo` (T1136.001, T1098) | same |
| `process.lolbin_abuse` | 1 | high | certutil `-urlcache`/`-decode`, bitsadmin `/transfer`, mshta with a URL or script, regsvr32 scriptlets, rundll32 JavaScript, msiexec from a URL (T1218, T1105, T1140) | same |
| `process.log_clearing` | 1 | high | `wevtutil cl`, `Clear-EventLog`, deleting `/var/log` files, wiping shell history (T1070.001, T1070.003) | same |
| `process.inhibit_recovery` | 1 | critical | `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, bcdedit recovery off (T1490) | same |
| `network.local_ioc_match` | 1 | by IOC confidence (high, medium, else low) | a network event's `dst_ip` is in the local IOC list | `session_gap_seconds` 3600 |
| `network.port_scan` | 1 | medium | one client reaches at least N distinct `dst_ip:dst_port` pairs within a window (T1046) | `distinct_targets` 20, `window_seconds` 120 |
| `network.lateral_movement` | 1 | high | one client reaches at least N internal hosts on admin ports 22, 135, 139, 445, 3389, 5985, 5986 within a window (T1021) | `distinct_hosts` 5, `window_seconds` 900 |
| `network.suspicious_port` | 1 | medium | a connection to a public IP on a port used by default by C2 frameworks, RATs, IRC botnets or Tor (4444, 1337, 31337, 6667, 9050, 50050, ...) (T1571) | `session_gap_seconds` 3600 |
| `network.large_upload` | 1 | medium | bytes sent by one client to one public IP add up to at least N MB within a window; needs `bytes_out` / `bytes_sent` (T1048, T1041) | `megabytes` 100, `window_seconds` 3600 |
| `siem.high_severity_alert` | 1 | high from `high_level`, else medium | an upstream SIEM alert (e.g. Wazuh, `siem.rule_level`) at or above `min_level`; one alert per upstream alert | `min_level` 10, `high_level` 12 |

"Same" thresholds are `min_indicators` 1 and `session_gap_seconds` 900: matches by one user on
one host closer together than the gap share an alert. Every pattern rule has a benign
look-alike test (`tests/integration/test_detection_extended.py`): for example `vssadmin list
shadows`, `certutil -hashfile`, `schtasks /query` and `net localgroup administrators` do not
fire. For the network rules, RFC 5737 documentation addresses count as public (the synthetic
data uses them for internet hosts).

All windows and gaps are inclusive: exactly `threshold` failures spanning exactly
`window_seconds` fire, one second more does not.

### PowerShell indicators

Matched on `process_name` (`powershell.exe`, `pwsh.exe`) and `command_line` only:
encoded command (`-e`, `-enc`, `-encodedcommand` followed by a base64-looking string), hidden
window (`-w hidden`, `-windowstyle hidden`), download cradle (`DownloadString`, `DownloadFile`,
`DownloadData`, `Net.WebClient`, `Start-BitsTransfer`) and `Invoke-Expression`/`IEX`.
`-ExecutionPolicy Bypass`, `-NoProfile` and ordinary admin commands are **not** indicators.

### Missing fields

Events that lack a field a rule needs are skipped, never guessed: auth rules need `user` and `src_ip`
(so does spray), the PowerShell rule needs `host`, `process_name` and
`command_line`, the IOC rule needs `dst_ip` plus a `host` or `src_ip` to name the client.

## How alerts are built

1. The ingestion service calls `DetectionEngine.detect` after each persisted batch with only the
   new events (the post-persist hook).
2. Each enabled rule works out which entities those events touch (for example a user and IP),
   re-reads that entity's history from SQLite and recomputes its findings.
3. Findings are written with `AlertRepository.upsert_finding`.

Because findings are computed from stored data, not arrival order, loading a file in one go,
replaying it event by event, or re-ingesting it produces the same alerts.

## Deduplication and suppression

- Dedup key: `rule_id | entity | time of the earliest matched event`. Alert IDs are a hash of it,
  so they are reproducible.
- A finding that shares any event with an existing alert of the same rule extends that alert
  instead of creating a new one (so a late-arriving earlier event does not split an alert).
- Separate bursts, further apart than the rule's window or gap, become separate alerts.
- A closed alert (`resolved` or `false_positive`) absorbs later matches: the events are linked but
  its status stays. Reopen it to `new` to work it again.

## Alert lifecycle

`new` to `acknowledged`, `investigating`, `resolved` or `false_positive`; `acknowledged` to
`investigating`, `resolved` or `false_positive`; `investigating` to `resolved` or
`false_positive`; `resolved` and `false_positive` can only go back to `new`.
Invalid moves raise `InvalidTransitionError`.

## Configuring rules

The **Detection rules** page enables or disables a rule and edits integer thresholds (1 to
10,000,000; unknown keys are rejected). Changes apply to events ingested afterwards. **Re-run
detection** evaluates every stored event, which is also how to pick up a rule you just enabled or
an IOC list you loaded later. It never duplicates alerts.

## Known limits

- A rule looks at up to 10,000 events per entity per evaluation.
- Rules do not correlate with each other: dave's demo scenario gives a `repeated_failures` and a
  `failures_then_success` alert. Grouping them is left to the investigation phase.
- Alert text embeds values from logs (user names, hosts). The UI shows it as plain text.
- The IOC rule matches IP addresses only; the list also stores domains and hashes for later use.

## Demo dataset result

Loading `data/demo/` (with its IOC list) yields exactly five alerts: 12 failed logons for `dave`
from 203.0.113.45; a success for `dave` after those failures (13 events); a password spray from
192.0.2.77 across six users; encoded and download-cradle PowerShell on WS-DAVE04; and WS-DAVE04
connecting to the IOC-listed 203.0.113.80. The benign lookalikes (bob's two typos, admin
PowerShell, the signed inventory script, backups) produce nothing. The extended rule pack adds
no demo alerts: dave's `whoami /all`, `net user /domain` and `net group ... /domain` are only two
discovery command types (`net user` and `net group` count as one), below the default of three.

On the evaluation set the extended rules add correct alerts to three malicious holdout
scenarios (h1: Word starting a shell and a scheduled task; h4: shadow copies deleted; h6: a
logon from an IOC-listed address) and nothing to the benign or undetermined ones;
`data/eval/scenarios.json` lists them as expected.
