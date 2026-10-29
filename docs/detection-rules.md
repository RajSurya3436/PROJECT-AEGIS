# Detection rules

Deterministic, versioned rules over stored events. No model, network or API key is involved, so
detection works with Ollama stopped. Code: `app/detection/`. Every alert records the rule ID and
version, a severity, a plain-language explanation, a dedup key, and the exact event IDs that
matched (with a reason for each).

## Rules

| Rule | v | Severity | Fires when | Default thresholds |
|---|---|---|---|---|
| `auth.repeated_failures` | 1 | medium | at least N failed logons for one user from one source IP within a window | `threshold` 5, `window_seconds` 300 |
| `auth.failures_then_success` | 1 | high | a failure burst, then a success for the same user and IP after the last failure | `failure_threshold` 3, `failure_window_seconds` 600, `success_within_seconds` 900 |
| `auth.password_spray` | 1 | medium | failures for at least N distinct users from one source IP within a window | `distinct_users` 5, `window_seconds` 600 |
| `process.suspicious_powershell` | 1 | high | PowerShell command line with an indicator (below) | `min_indicators` 1, `session_gap_seconds` 600 |
| `network.local_ioc_match` | 1 | by IOC confidence (high, medium, else low) | a network event's `dst_ip` is in the local IOC list | `session_gap_seconds` 3600 |

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
PowerShell, the signed inventory script, backups) produce nothing.
