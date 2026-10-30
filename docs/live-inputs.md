# Live inputs and Wazuh (Phase 8)

Three ways in besides the demo replay and file upload, all through the **same ingestion
pipeline** (adapter → normalise → deduplicate → store → detect → source health):

| Input | Use it for | Where |
|---|---|---|
| **Follow a file** | a growing JSONL log, e.g. Wazuh's `alerts.json` | Data sources → Live inputs |
| **HTTP receiver** | a script or tool on this PC that POSTs events | Data sources → Live inputs |
| **Upload** with the *Wazuh alerts* layout | a one-off export of `alerts.json` | Data sources → Upload |

Nothing reads system or SIEM data on its own: you choose the file, start the receiver, or send
the request. Design decisions: [ADR 0004](decisions/0004-live-inputs-and-wazuh.md).

## Record layouts (adapters)

`app/ingestion/adapters/`. An adapter reshapes a vendor's record into keys the field alias
table understands; the record as received is still what is stored and fingerprinted.

- **generic**: no reshaping (the field aliases in [data-sources.md](data-sources.md)).
- **wazuh**: Wazuh `alerts.json`. Explicit mapping, nothing guessed:

| Canonical | Wazuh field(s), first present wins |
|---|---|
| time | `timestamp` |
| unique ID | `id` (so re-reading an alert never duplicates it) |
| host | `agent.name`, `data.win.system.computer` |
| user | `data.dstuser`, `data.win.eventdata.targetUserName`, `data.srcuser`, `data.win.eventdata.user` |
| src_ip / dst_ip / dst_port | `data.srcip` / `data.dstip` / `data.dstport`, or `ipAddress`/`sourceIp`, `destinationIp`, `destinationPort` from Windows event data |
| process / command line / parent | Sysmon or 4688 `image`/`newProcessName`, `commandLine`, `parentImage`/`parentProcessName` |
| message | `rule.description` |
| event type, outcome | rule groups `authentication_success` / `authentication_failed`, `win_authentication_failed`, `invalid_login`; Windows 4624 / 4625 / 4688; Sysmon 1 (process) / 3 (network). Anything else is `other`. |

Wazuh's *aggregate* alerts (group `authentication_failures`, e.g. rule 5720 "multiple
authentication failures") stay `other`, so they are not counted again as logons. Wazuh's own
verdict is kept in `extra` as `siem.vendor`, `siem.rule_id`, `siem.rule_level` (integers 0-15
only), `siem.rule_description`, `siem.rule_groups`, `siem.mitre_ids`, `siem.agent_id`,
`siem.decoder`, `siem.location`, `siem.windows_event_id`. `-` (Windows "no value") counts as
missing. Odd or malformed records never raise; they just yield fewer fields.

To support another SIEM, add an adapter class and register it in `app/ingestion/adapters/__init__.py`;
every input can use it at once.

## Wazuh alerts and detection

Wazuh alerts are stored **as events**, so this app's five rules run on them (sshd and Windows
logon failures feed the authentication rules, Sysmon process and network events feed the
PowerShell and IOC rules) and investigations, agents and reports work unchanged. In addition,
rule **`siem.high_severity_alert`** turns each upstream alert at or above `min_level` (default
10; severity high from `high_level`, default 12) into an alert here, keeping Wazuh's rule ID,
level, description and MITRE IDs. Both thresholds are on the Detection rules page.

## Follow a file

`app/ingestion/file_tail.py`. Each poll (every `FILE_TAIL_POLL_SECONDS`, default 2) opens the
file, reads from the saved offset, ingests complete lines and closes it again.

- A line without its newline yet waits for the next poll.
- File shorter than the offset → **truncated**: read again from the start (duplicates are
  dropped by event ID).
- First line changed → **rotated** (a new file under the same name): read from the start.
  Lines appended to the old file after the last poll and before rotation are not seen.
- A line longer than `FILE_TAIL_MAX_LINE_BYTES` (1 MB) is quarantined and skipped; invalid
  JSON or a non-object line is quarantined. At most `FILE_TAIL_MAX_BYTES_PER_POLL` (4 MB) is read
  per poll.
- The offset is stored on the source, and the list of followed files in the database: after a
  restart the app follows the same files again from where it stopped.
- *Start at the end* skips what is already in the file (and a half-written last line).
- Live following needs a file database; with `:memory:` only *Poll now* works.

## HTTP receiver

`app/ingestion/http_receiver.py`, Python standard library only. Start it on the Data sources
page; it listens on `127.0.0.1:8787` (`HTTP_RECEIVER_PORT`).

```powershell
curl.exe -X POST "http://127.0.0.1:8787/ingest?source=lab&adapter=wazuh" `
  -H "Content-Type: application/x-ndjson" --data-binary "@data\samples\wazuh_alerts.jsonl"
```

- `POST /ingest?source=<a-z0-9->&adapter=generic|wazuh`; body `application/json` (an object,
  an array or `{"events": [...]}`) or `application/x-ndjson`. Returns received / inserted /
  duplicates / quarantined. `GET /health` answers `{"status": "ok"}`. Events land in source
  `http-<source>`.
- **Loopback only.** `HTTP_RECEIVER_HOST` must be `127.0.0.1`, `::1` or `localhost`; anything
  else refuses to start. There is no setting to expose it to the network.
- **No browsers.** Requests with an `Origin` header, a non-loopback `Host` header (DNS
  rebinding) or a content type a web page can send without a CORS preflight are refused, so a
  website you visit cannot post events.
- Optional `HTTP_RECEIVER_TOKEN`: then `Authorization: Bearer <token>` is required (constant-time
  comparison).
- Limits: `HTTP_RECEIVER_MAX_BODY_BYTES` (1 MB), `HTTP_RECEIVER_MAX_RECORDS` (1,000) per request,
  `HTTP_RECEIVER_REQUESTS_PER_MINUTE` (120). The request body is never echoed back.
- Starting and stopping are in the audit log, as are adding and removing followed files.

## Try it without Wazuh

`data/samples/wazuh_alerts.jsonl` (made by `scripts/make_wazuh_sample.py`) holds 17 synthetic
alerts in Wazuh's format: an SSH password-guessing story on `web-01`, a Windows logon brute force
followed by encoded PowerShell and a connection to an IOC on `WIN-FIN01`, and benign noise. Load
the demo IOC list (Data sources → Load demo dataset, or it is loaded with the demo), then follow
or upload the sample: it produces 7 alerts (2 failures-then-success, 1 repeated failures,
1 PowerShell, 1 IOC connection, 2 Wazuh high-level alerts) and none for the benign events.

## Connect a real Wazuh (optional)

Needs **WSL2** and **Docker Desktop**, and about 4-6 GB of free RAM while Wazuh runs.

1. Admin PowerShell: `wsl --install`, then restart Windows.
2. Install Docker Desktop for Windows (WSL2 backend) and start it.
3. Wazuh single-node in Docker (from the official `wazuh-docker` repository, single-node
   deployment; generate its certificates, then `docker compose up -d`).
4. Make the manager's alert file visible on Windows. The simplest way is to copy it out
   periodically, or bind-mount the manager's `/var/ossec/logs/alerts` directory to a Windows
   folder in the compose file. Then *Follow a file* → that `alerts.json` → layout **Wazuh**.
   (A file on a WSL path is reachable from Windows as `\\wsl$\<distro>\...`.)
5. Enrol this Windows PC as a Wazuh agent (Wazuh dashboard → Deploy new agent) to see your own
   logon events arrive as alerts.

Alternatively, forward alerts with a small script that POSTs new lines to the HTTP receiver.
The receiver does not accept connections from containers or other machines by design.
