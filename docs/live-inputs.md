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

Needs **WSL2** and **Docker Desktop**, and about 4-6 GB of free RAM while Wazuh runs. Tested
with `wazuh-docker` v4.14.9, single-node.

1. `winget install -e --id Docker.DockerDesktop`, restart Windows, start Docker Desktop (WSL 2
   engine). Optionally cap its memory in `%UserProfile%\.wslconfig` (`[wsl2]` / `memory=8GB`).
2. Get Wazuh and **bind its ports to this PC only**. The upstream compose file publishes them
   on every interface, with default passwords:
   ```powershell
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.9
   cd wazuh-docker\single-node
   (Get-Content docker-compose.yml) -replace '^(\s*- )"?(\d+:\d+(?:/udp)?)"?\s*$', '$1"127.0.0.1:$2"' | Set-Content docker-compose.yml
   Select-String docker-compose.yml -Pattern '127\.0\.0\.1'   # expect 6 ports, including 443:5601
   docker compose -f generate-indexer-certs.yml run --rm generator
   wsl -d docker-desktop -u root sysctl -w vm.max_map_count=262144   # after every Docker restart
   docker compose up -d
   ```
   Dashboard: https://localhost (self-signed certificate), `admin` / `SecretPassword`.
3. In this app: *Data sources → Live inputs → HTTP receiver → Start*.
4. Forward the manager's alerts to the receiver:
   ```powershell
   .venv\Scripts\python scripts\wazuh_forward.py            # new alerts only
   .venv\Scripts\python scripts\wazuh_forward.py --from-start   # the whole alerts.json first
   ```
   The compose file keeps `alerts.json` in a Docker volume, so the script reads it with
   `docker exec <manager> tail -F` (default container `single-node-wazuh.manager-1`;
   `docker ps` shows the name) and POSTs batches of NDJSON with `adapter=wazuh`. Batches stay
   under the receiver's limits; while the receiver is down they are kept and retried, and a
   batch it rejects is reported and dropped. It only posts to `http://127.0.0.1` and uses
   `HTTP_RECEIVER_TOKEN` when set.
5. Enrol this Windows PC as a Wazuh agent (dashboard → *Agents → Deploy new agent → Windows*,
   server address `127.0.0.1`, then `NET START WazuhSvc` in an admin PowerShell). A few wrong
   passwords at the lock screen then arrive as Wazuh alerts, and five or more within five
   minutes trip `auth.repeated_failures` here. Without locking the screen (no admin, and a
   made-up user so no real account is locked out):
   ```powershell
   1..6 | % { net use \\127.0.0.1\IPC$ /user:soctest WrongPass123! 2>$null; Start-Sleep 35 }
   ```
   Each attempt is a failed network logon (4625, logon type 3, `127.0.0.1`). Space them about
   35 s apart: Windows logs only about one failure per ~30 s for the same user, so faster
   attempts are mostly not recorded. Tested 2026-11-01: 6 failures, one
   `auth.repeated_failures` alert.

Stop Wazuh with `docker compose down` in `wazuh-docker\single-node` (data is kept in volumes).
The receiver does not accept connections from containers or other machines by design; that is
why the forwarder runs on Windows.
