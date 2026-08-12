# TODO List

- [x] Investigate volatile changes where an ASN regresses in RPKI/ROV status. 
    - [x] Example: AS45355 regression detected and implemented in pipeline.
    - [x] Regression detection now uses full historical max from APNIC.
    - [x] Proactive scanning for regressions across all transit ASNs (`sync_transit_timeseries.py`).
- [x] Incorporate raw timeseries data from APNIC for trend analysis.
    - [x] `sync_apnic_timeseries` now handles full history.
    - [x] `regression` flag added to audit results.
- [x] Data Storage Refactoring:
    - [x] Moved from 122k individual files to a single `data/as_data.jsonl.gz`.
    - [x] Implemented `load_all_asn_data()` in `rov_utils.py` for high-performance ingestion (0.8s vs ~20s).
    - [x] Archived legacy `data/html` (7.3GB) and `data/apnic_roa` (272MB) into compressed cold storage.
- [ ] Evaluate moving to SQLite for random access if needed (currently memory-based load is fast enough).
- [ ] Add a command-line tool to "unpack" or "query" the packed ASN data for quick debugging.
- [x] Reactivate Quadrant Analysis:
    - [x] Refactored `old/analyze_rov_quadrants_v3.py` into `analyze_rov_quadrants_v4.py`.
    - [x] Uses `rov_utils.load_topology()`, `load_all_asn_data()`, and `is_secure()`; also now applies the IXP phantom cone-quality filter (`cone_quality()` / `CONE_QUALITY_THRESHOLD`) that v3 never had — 70 phantom networks excluded on the first live run.
    - [x] Integrated into `do_reports`, writing `reports/analyze_rov_quadrants.html`. Verified end-to-end against live data (3.5s runtime, sensible Q1-Q4 placement).
- [x] Write a new ASPA-realistic analysis script:
    - [x] Wrote `analyze_aspa_realistic_v5.py` fresh (not patched from the stale `old/analyze_aspa_realistic_v4.py`).
    - [x] Uses `rov_utils.load_all_asn_data()`, `TIER_1_ASNS`/`NON_TRANSIT_ASNS` for filtering, and `is_secure()`/`is_partial()`. Adds a ranked top-30 "realistic enforcers" table (providers ranked by ROV-weighted leverage, not raw customer count) — the concrete per-provider ranking that `analyze_aspa_readiness_v2.py` doesn't produce (it only reports the aggregate top-100 gap %).
    - [x] Integrated into `do_reports`, writing `reports/analyze_aspa_realistic.html`. Verified end-to-end against live data (1.6s runtime, 69.3% realistic-vs-theoretical protection ratio).
- [x] Update ROA Signing Data:
    - [x] `do_roa_sync.py` + `pack_asn_data.py` run automatically inside `do_data_gathering`, triggered by the `full` cron mode — **weekly (Sunday 03:00), not daily**. The daily `reports` cron job does not touch ROA data, it only reruns analysis against the last weekly-packed archive. Verified 7 consecutive successful runs in `logs/cron.log` (2026-06-28 through 2026-08-09), each ending `[SUCCESS] Global ROA Sync Complete`.
    - [x] Fixed the bare `except:` on the `Fetching IPv4/IPv6 Geo` calls in `rov_utils.py`'s `load_metadata()` — added `resp.raise_for_status()` and now logs the real exception (`FAIL (ExceptionType: message)`) instead of swallowing it silently. Non-fatal either way (Cymru fallback still covers it), but the next real failure will be diagnosable instead of just "FAIL".
- [x] Repository Maintenance:
    - [x] Trimmed the git repository of large data blobs from historical commits using `git filter-repo`. `.git` went from 555MB → 76MB (86% reduction; 95% vs the 1.4GB it was before this session's earlier plain `gc`). Purged ~9.65GB of raw historical content: `data/html/` (legacy scrape cache, 7.3GB), `data/parsed/` (pre-refactor per-file era, 346MB), `bgp-table.txt` (1.6GB), `table.txt`, `output/`, `results/`, `logs/cron.log`, `reports/old/`, `fetch-roa` binary. Explicitly kept: `data/asn_meta.json`/`data/downstream_graph.json` (actively maintained, committed as recently as the day before this work) and all versioned audit CSVs (`rov_audit_v*`, `rov_no_scrape_v*` — historical ROV/ROA research snapshots). Also untracked (but did not delete on disk) `data/parsed/*.json`, `results/*`, `.locks/*` — all covered by `.gitignore` but never actually untracked after the rules were added. Done via an isolated fresh clone (`git clone --no-local`), verified byte-for-byte against the original before force-pushing (full tree hash comparison, 95 of 96 commits preserved — the 1 dropped was a confirmed byte-identical redundant sibling merge commit, zero data loss). A backup bare clone was kept at `/home/terry/rov_audit_backup_pre_filter_repo.git` until the rewrite was verified good, then deleted.
    - [x] `logs/cron.log` fixed to never be committed at all (not just rotated) — it's purely operational logging, not a research artifact. Rotated locally via copytruncate for disk hygiene; rotated archives and the live file are both gitignored.
    - [x] Implement a 7-day TTL for all APNIC Labs data fetches to avoid overloading their servers (Implemented in `rov_utils.py`).
    - [x] Monthly cron commit of report outputs — `rov_cron.sh commit` mode, scoped to `git add -u -- reports/ '*.csv'` (tracked files only, no push). Scheduled 1st of month 07:00.
    - [x] Archived `rov_no_scrape_v21.py` (dead engine snapshot, unreferenced by `do_reports`) into `old/` via `git mv`, alongside the already-archived v19/v20.
- [ ] Forensic Automation:
    - [x] Implement smart "Customer Cone" probe selection to test transit providers from their customers' perspective (`batch_verify_smart_v4.py`).
    - [x] Implement a 7-day TTL for forensic re-verification to catch regressions without wasting Atlas credits.
    - [x] Create a weekly cron-like trigger to run the smart forensic scan — actually implemented as nightly (02:00) via `rov_cron.sh atlas`, which exceeds the original weekly spec.


- [x] Reproduce the archived RPKI RFC routing-security reference page: https://web.archive.org/web/20220724031723/http://rpki-rfc.routingsecurity.net/
    - [x] Original site is dead; reproduced from `RPKI_RFCS.md` at repo root as a static markdown reference (the source was a D3.js reading-dependency graph, not a data page — reproduced the underlying curation, not the visualization). Sourced from the Wayback snapshot at `2022-07-27T16:37:30Z` (nearest crawl of the data file to the `2022-07-24` page snapshot originally noted here).
    - Faithful reproduction of the 2022 snapshot only (63 RFCs, MUST/SHOULD/MAY tiers, 29 UPDATE/OBSOLETE relationships) — RFCs published since then (e.g. ASPA RFC 9582) are deliberately excluded. Extending the list is a separate future item if wanted.
    - 4 of the 63 entries have known title/author corruption baked into the original source data (not introduced here) — flagged inline in `RPKI_RFCS.md` via a footnote.

