# IP reputation

`ReputationService.lookup_ip(ip, providers=None, force_refresh=False)` returns an
`IpReputationReport`: the IP's scope, any local IOC match, and one `ReputationResult` per
provider. It never raises for provider problems.

## Decision order per provider

1. Invalid IP, or scope not `public` (private, loopback, link-local, multicast, reserved,
   documentation, unspecified) -> `skipped`. Nothing is sent.
2. Unexpired cache entry (unless `force_refresh`) -> `cached`.
3. No API key -> `not_configured`.
4. External lookups switched off -> `disabled`.
5. Live request -> `fresh` (then cached), or `rate_limited`, `timeout`, `provider_error`.

## Request handling

- HTTPS only; the key goes in a header (`Key` / `x-apikey`), the URL carries only the IP.
- Timeout `REPUTATION_TIMEOUT_SECONDS` (10 s). Timeouts, connection errors, HTTP 5xx and 408 are
  retried up to `REPUTATION_MAX_RETRIES` (2) times with 1 s, 2 s, 4 s ... backoff (max 8 s).
- HTTP 429: no retry; `Retry-After` (default 60 s, max 1 h) sets a cooldown for that provider.
- Client-side budget per provider (per minute and per day, in memory); when used up the result
  is `rate_limited` and no request is made.
- 401/403 and other 4xx: `provider_error`, not retried. VirusTotal 404 means "no record" and is
  a `fresh` result with `found = false`.
- Error messages are fixed text plus the status code; provider bodies are never shown or stored.

## What is stored

`reputation_cache` (migration 0003): provider, indicator, found, signal, summary JSON,
queried_at, expires_at. The summary holds allowlisted fields only, type-checked and capped at
200 characters per string. Provider strings remain untrusted and are rendered with escaping
widgets. Failed lookups are not cached.

## Signals

Fixed thresholds, reported as evidence rather than a verdict:

| Provider | high | medium | low |
|---|---|---|---|
| AbuseIPDB | confidence score >= 75 | >= 25 | otherwise |
| VirusTotal | >= 3 malicious engines | >= 1 malicious or >= 2 suspicious | otherwise |
