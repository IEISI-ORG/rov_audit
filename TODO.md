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
- [ ] Reactivate Quadrant Analysis:
    - [ ] Refactor `old/analyze_rov_quadrants_v3.py` into a modern `analyze_rov_quadrants_v4.py`.
    - [ ] Update to use `rov_utils.load_all_asn_data()` and `rov_utils.is_secure()`.
    - [ ] Integrate into the `do_reports` pipeline.
    - Note: `reports/analyze_rov_quadrants.html` is stale (last generated Apr 22 2026, not wired into `do_reports`). The `.md` mtime looks fresh only because `do_reports`'s pandoc loop reconverts every existing `.html` on each run regardless of whether it was regenerated.
- [ ] Write a new ASPA-realistic analysis script:
    - [ ] `old/analyze_aspa_realistic_v4.py` is the latest prior attempt but is stale (Jan 2 2026) and diverged from current `rov_utils` conventions — write a fresh script rather than patching it, following the same modernization pattern as the quadrant analysis above.
    - [ ] Update to use `rov_utils.load_all_asn_data()` and current verdict/classification helpers.
    - [ ] Integrate into the `do_reports` pipeline.
    - Note: `reports/analyze_aspa_realistic.html` is stale (last generated Apr 22 2026, not wired into `do_reports`), same orphaned-report pattern as quadrants above. Distinct from `analyze_aspa_readiness_v2.py`, which is current and live in `do_reports`.
- [ ] Update ROA Signing Data:
    - [ ] Run `python3 do_roa_sync.py` to refresh global ROA signing percentages.
    - [ ] Run `python3 pack_asn_data.py` to update the high-performance packed archive with new ROA stats.
- [ ] Repository Maintenance:
    - [ ] Trim the git repository of large data blobs from historical commits (using `git filter-repo` or `bfg`) to reduce `.git` directory size.
    - [x] Implement a 7-day TTL for all APNIC Labs data fetches to avoid overloading their servers (Implemented in `rov_utils.py`).
    - [x] Monthly cron commit of report outputs — `rov_cron.sh commit` mode, scoped to `git add -u -- reports/ '*.csv' logs/cron.log` (tracked files only, no push). Scheduled 1st of month 07:00.
- [ ] Forensic Automation:
    - [x] Implement smart "Customer Cone" probe selection to test transit providers from their customers' perspective (`batch_verify_smart_v4.py`).
    - [x] Implement a 7-day TTL for forensic re-verification to catch regressions without wasting Atlas credits.
    - [ ] Create a weekly cron-like trigger to run the smart forensic scan.


Pull https://web.archive.org/web/20220724031723/http://rpki-rfc.routingsecurity.net/ and reproduce it.

