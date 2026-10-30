# ADR 0004: live inputs share one pipeline; Wazuh through a record adapter and file tail

Date: 2026-10-30. Status: accepted.

**Decisions:**

1. **Adapters, not new pipelines.** A SIEM's format is handled by a small record adapter that
   reshapes each record before the alias mapping (`app/ingestion/adapters/`). Upload, file tail
   and the HTTP receiver all accept any adapter; storage, dedup, detection and investigations
   stay one code path. The record is stored exactly as received.
2. **Wazuh alerts are events, plus one rule for Wazuh's verdicts.** Storing each Wazuh alert
   as an event lets our own rules, investigations and agents use it. Wazuh's level and rule are
   kept under `siem.*`, and `siem.high_severity_alert` surfaces alerts at or above a level
   threshold here without re-judging them. Aggregate Wazuh alerts are not counted as logons.
3. **Wazuh via its alert file first.** Following `alerts.json` needs no Wazuh API credentials and
   works the same with a copied file, a mounted volume or an exported sample. Polling the Wazuh
   indexer (OpenSearch) is not built.
4. **The file tail polls and closes** rather than holding the file open: on Windows an open
   handle stops the writer rotating the file. The cost: lines written to the old file after the
   last poll and before a rotation are missed (short default interval, 2 s).
5. **The HTTP receiver is loopback-only, with no option to widen it.** It is stdlib
   `http.server`; browsers are kept out by refusing `Origin`, non-loopback `Host` and
   preflight-free content types. Containers and remote machines cannot post to it; exposing it
   safely would need TLS, authentication and network policy that a local tool should not
   half-implement.

**Cost:** one more indirection for vendor formats; no live Wazuh API integration; a real Wazuh
install needs Docker/WSL2 and a way to share its alert file with Windows.
