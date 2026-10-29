# Data sources

The app only sees data from sources you configure. It does not read OS logs or EDR by itself.

| Level | Status |
|---|---|
| Bundled demo dataset | implemented (one-shot load, or timed replay with speed, pause, resume, stop, restart) |
| File upload (JSONL, NDJSON, CSV, JSON array / `{"events": [...]}`) | implemented |
| File tail | planned (Phase 8) |
| Loopback HTTP receiver (`POST /api/v1/events`, 127.0.0.1) | planned (Phase 8) |
| SIEM adapter (Wazuh/Elastic) | not implemented; interface only if/when added |

## Field aliases

Defined in `app/ingestion/field_aliases.py` (explicit, case-insensitive, nested keys flattened
with dots, e.g. `source.ip`). Highest-priority alias with a value wins; other keys stay in
`extra` unchanged. Unknown fields are never guessed.

| Canonical | Accepted keys (priority order) |
|---|---|
| timestamp | timestamp, @timestamp, event_time, time, eventtime, TimeCreated, datetime, ts |
| user | user, username, user_name, account_name, TargetUserName, user.name |
| host | host, hostname, host_name, computer, device_name, host.name |
| src_ip | src_ip, source_ip, client_ip, IpAddress, SourceAddress, source.ip, src |
| dst_ip / dst_port | dst_ip, dest_ip, destination_ip, ... / dst_port, dest_port, ... |
| process_name, command_line, parent_process | see file |
| outcome | outcome, result, status, event.outcome (values map to success/failure/unknown) |
| event_type | event_type, type, category, ... (auth/process/network, else `other`) |

## Timestamps

ISO-8601 (with offset), epoch seconds or milliseconds, and `YYYY-MM-DD HH:MM:SS` variants are
accepted and converted to UTC. Naive values are treated as UTC and flagged
`extra._tz_assumed`. Years outside 1990-2100 and unparseable values are quarantined.

## Limits (configurable)

`MAX_UPLOAD_BYTES` 25 MB, `MAX_ROWS_PER_INGEST` 200,000, parse-error snippets 500 characters.

## Demo dataset

`data/demo/` holds 136 synthetic events (regenerate with `scripts/generate_demo_data.py`):
a brute-force-then-success scenario against `dave` followed by encoded PowerShell, a download
from an IOC-listed IP and discovery commands; an ambiguous password spray; and benign
lookalikes (typos, admin PowerShell, signed inventory script, backups). One auth record carries
a prompt-injection string to test agent guardrails later. External IPs use RFC 5737
documentation ranges, so real reputation lookups would skip them; demo reputation is mocked.
