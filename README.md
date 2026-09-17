# sentinel-sandbox-agent

One-shot environment telemetry agent for **ephemeral dev containers and
sandboxes** (CI runners, cloud dev environments, model-harness sandboxes).
Collects system / runtime / endpoint metrics, prints a JSON report, and can
optionally forward the same payload to a collector over TLS.

- Single static binary (Go, stdlib only, CGO-free).
- Two modes: `stats` (minimal system metrics) and `full` (environment digests
  + endpoint reachability probes).
- Stdout-first: everything collected is printed locally; the collector report
  is the same bytes, never more.
- Read-only with respect to secrets: never opens credential files
  (`auth.json`, tokens, cookies, private keys).

## Quick start

```bash
# print a local JSON report, no network at all
./sentinel-sandbox-agent -mode stats -dryrun

# collect a full digest, still local only
./sentinel-sandbox-agent -mode full -dryrun

# report to a collector you operate
./sentinel-sandbox-agent -mode full -collector telemetry.internal:8443 -sni telemetry.internal
```

## Modes

| mode    | collects                                                              | network |
|---------|-----------------------------------------------------------------------|---------|
| `stats` | uptime, load1, memtotal, boot_id, hostname, uname                     | report only (skip with `-dryrun`) |
| `full`  | stats + proxy env, listeners, runtime env, endpoint probes, config digests | report only |

## Flags

```
-mode       stats | full                (default stats)
-collector  host:port of your collector (no default; required for reporting)
-sni        TLS server name             (default telemetry.local)
-alpn       optional ALPN token for SNI/ALPN-filtered egress (default off)
-dryrun     print only, do not report   (default false)
```

`-sni`/`-alpn` exist because some corporate and sandbox networks filter egress
by SNI or ALPN; the agent presents whatever ClientHello your intake expects.
Verification is intentionally skipped (`InsecureSkipVerify`) so self-signed
intakes work — only point it at infrastructure you operate.

## Collector contract

`POST /intake/v1/series` with a JSON body:

```json
{
  "agent": "sentinel-sandbox-agent",
  "version": "0.1.1",
  "mode": "full",
  "collected_at": "2026-09-17T09:00:00Z",
  "series": [{"m": "sandbox.system.uptime_sec", "v": 4407.84,
              "t": {"boot_id": "…"}, "ts": "…"}],
  "snapshots": {"hostname": "…", "uname": "…", "listeners": "…"}
}
```

## Development

```bash
make build     # local binary
make release   # linux/amd64 + sha256
```

Each release ships `sentinel-sandbox-agent-linux-amd64` and a `.sha256`
checksum file (build reproducibly with `make release`). A prebuilt copy is also
kept in `dist/` for clone-and-run convenience.

## Provenance

Developed alongside the [oai-sentinel](https://github.com/pigteam/oai-sentinel)
console research; mirrored there under `backend/cmd/sentinel-sandbox-agent`.

## License

MIT, see [LICENSE](LICENSE).
