# Cron Jobs

All scheduled automation runs through `rov_cron.sh`, a single dispatcher with four modes. Each crontab line just picks a mode and redirects output to `logs/cron.log` (local-only, never committed — see [Logging](#logging) below).

## Schedule

| Time | Mode | Purpose | Typical runtime |
|---|---|---|---|
| Nightly, 02:00 | `atlas` | RIPE Atlas forensic batch (5 targets) | ~5 min |
| Daily, 06:00 | `reports` | Audit + analysis + HTML/MD reports (cached topology) | up to 3 hr (timeout) |
| Weekly, Sunday 03:00 | `full` | Topology rebuild + atlas + reports | up to 6 hr (timeout) |
| Monthly, 1st at 07:00 | `commit` | Commit changed report outputs | seconds |

Live crontab (`crontab -l`):

```
0 2 * * * ${HOME}/rov_audit/rov_cron.sh atlas >> ${HOME}/rov_audit/logs/cron.log 2>&1
0 6 * * * ${HOME}/rov_audit/rov_cron.sh reports >> ${HOME}/rov_audit/logs/cron.log 2>&1
0 3 * * 0 ${HOME}/rov_audit/rov_cron.sh full >> ${HOME}/rov_audit/logs/cron.log 2>&1
0 7 1 * * ${HOME}/rov_audit/rov_cron.sh commit >> ${HOME}/rov_audit/logs/cron.log 2>&1
```

## Modes

### `atlas`
Runs `batch_verify_smart_v4.py --limit 5` — the prioritized RIPE Atlas re-verification scheduler. Fast, runs nightly to keep forensic verdicts within the 7-day TTL without exhausting Atlas credits.

### `reports`
Runs `do_reports` — `rov_no_scrape_v22.py` (main audit) + all analysis scripts (`analyze_roa_signing_v2.py`, `analyze_herd_immunity_v2.py`, `analyze_roa_strategy_v3.py`, `analyze_aspa_readiness_v2.py`, `analyze_rov_quadrants_v4.py`, `analyze_aspa_realistic_v5.py`) + `statistics_v6.py` + per-country deep dives + pandoc HTML→MD conversion. Uses cached topology from the last `full` run — does **not** touch ROA data or rebuild topology. Wrapped in a 3-hour `timeout`; a timeout or non-zero exit is logged as a warning but doesn't fail the cron slot (partial output is still useful).

### `full`
Weekly heavyweight run: `do_data_gathering` (downloads RIB dumps, runs the Go extractors, rebuilds topology via `build_topology_from_go.py`, syncs ROA data via `do_roa_sync.py`, packs ASN data) → `atlas` → `reports`, in sequence. Wrapped in a 6-hour `timeout`; a timeout or failure here **does** abort the cron slot (`die`), since a broken topology rebuild shouldn't be silently treated as success.

### `commit`
Local-only, scoped commit of changed report outputs — **never pushes**. Stages only already-tracked files under `reports/` and root-level CSVs (`git add -u -- reports/ '*.csv'`), so it can never sweep in unrelated untracked files (secrets, scratch scripts, etc.). Exits cleanly with no commit if nothing changed.

Also rotates `logs/cron.log` first, via copytruncate (`cp` + in-place truncate, not `mv`) — see [Logging](#logging).

## Locking

Each mode acquires an exclusive `flock` lock (`.locks/<mode>.lock`) before running and releases it on exit (including on error, via `trap`). If a mode is already running when its next cron slot fires (e.g. a slow `reports` run still going at the next `atlas` slot), the new invocation logs a message and exits 0 immediately rather than overlapping. Lock files themselves are gitignored — they're pure runtime state, not project artifacts.

## Logging

`logs/cron.log` is pure operational output (every mode's `log()` calls, plus the full captured stdout/stderr of whatever it invokes — e.g. `reports` captures the entire report-generation output). It is **never committed** — it's not a research artifact, just a debug log, and treating it as one led to it being accidentally bulk-committed for months (92MB across history) before that was caught and fixed. It's gitignored entirely (`logs/cron.log` and `logs/cron.log.*`).

`commit` mode rotates it at the start of every run: the accumulated log is copied to a dated, gzipped archive (`logs/cron.log.YYYY-MM.log.gz`) and the live file is truncated in place. Truncate-in-place (not rename) matters specifically because the crontab entries redirect with `>> logs/cron.log 2>&1` — that file descriptor is already open by the time `commit` mode runs, so a rename would silently keep writing the rest of that run's output into the now-archived file instead of a fresh one.

## Installing / modifying

```bash
crontab -e
```

`rov_cron.sh` itself is the source of truth for mode behavior — this doc summarizes it, but check the script directly for exact commands, timeouts, and error handling before making changes.
