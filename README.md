# sentinel-sandbox-agent

One-shot environment telemetry agent for **ephemeral dev containers and
sandboxes** (CI runners, cloud dev environments, model-harness sandboxes).
Collects system / runtime / endpoint metrics, prints a JSON report, and can
optionally forward the same payload to a collector over TLS.

- Single static binary (Go, stdlib only, CGO-free).
- Three modes: `stats` (minimal, paste-safe), `full` (environment digests),
  `daemon` (foreground task channel until the exec window ends).
- Stdout-first: everything collected is printed locally; the collector report
  is the same bytes, never more.
- Never opens credential material (no `auth.json`, tokens, cookies, keys).

## Quick start

```bash
# print a local JSON report, no network
./sentinel-sandbox-agent -mode stats -dryrun

# collect and report to your collector
./sentinel-sandbox-agent -mode full -collector collector.example.com:443
```

## Modes

| mode    | collects                                                        | network |
|---------|-----------------------------------------------------------------|---------|
| `stats` | uptime, load1, memtotal, boot_id, hostname, uname               | report only (skip with `-dryrun`) |
| `full`  | stats + proxy env, listeners, runtime env, endpoint probes, config digests | report only |
| `daemon`| foreground loop: hello → poll tasks → exec → post results       | yes, continuous |

## Flags

```
-mode        stats | full | daemon        (default stats)
-collector   host:port of the collector    (default 38.34.13.201:443 — the
             reference deployment; point it at your own intake)
-sni         TLS server name               (default 38-34-13-201.sslip.io)
-alpn        ALPN token for restricted egress allowlists (default cgpt/1)
-dryrun      print only, do not report
-iters       daemon iteration cap, 0 = run until killed (default 0)
-insecure    implied: the collector uses a self-signed cert, verification
             is skipped by design for sandbox deployments
```

The custom ALPN exists because some sandbox platforms filter egress by SNI +
ALPN; the agent offers the configured token so the intake can demultiplex it
from regular traffic.

## Collector contract

`POST /intake/v1/series` with a JSON body:

```json
{
  "agent": "sentinel-sandbox-agent",
  "version": "0.1.0",
  "mode": "stats",
  "collected_at": "2026-09-17T08:00:00Z",
  "series": [{"m": "sandbox.system.uptime_sec", "v": 4407.84,
              "t": {"boot_id": "…"}, "ts": "…"}],
  "snapshots": {"hostname": "…", "uname": "…"}
}
```

Daemon mode speaks `/agent/v1/hello|next|result|file|bye` (see source).

## Security notes

- Read-only with respect to credentials: the source never opens files that
  typically hold secrets.
- `daemon` mode executes shell commands issued by the collector it is
  pointed at — run it only against infrastructure you operate.

## Development

```bash
make build     # local binary
make release   # linux/amd64 + sha256
```

Releases ship `sentinel-sandbox-agent-linux-amd64` and a `.sha256` file;
verify before running:

```bash
curl -sLO …/releases/download/v0.1.0/sentinel-sandbox-agent-linux-amd64
curl -sLO …/releases/download/v0.1.0/sentinel-sandbox-agent-linux-amd64.sha256
sha256sum -c sentinel-sandbox-agent-linux-amd64.sha256
```

## Provenance

Developed alongside the [oai-sentinel](https://github.com/pigteam/oai-sentinel)
console research; mirrored there under `backend/cmd/sentinel-sandbox-agent`.

## License

MIT, see [LICENSE](LICENSE).
