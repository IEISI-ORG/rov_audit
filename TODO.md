# TODO List

- [x] Investigate volatile changes where an ASN regresses in RPKI/ROV status. 
    - [x] Example: AS45355 regression detected and implemented in pipeline.
    - [x] Regression detection now uses full historical max from APNIC.
- [x] Incorporate raw timeseries data from APNIC for trend analysis.
    - [x] `sync_apnic_timeseries` now handles full history.
    - [x] `regression` flag added to audit results.
- [x] Data Storage Refactoring:
    - [x] Moved from 122k individual files to a single `data/as_data.jsonl.gz`.
    - [x] Implemented `load_all_asn_data()` in `rov_utils.py` for high-performance ingestion (0.8s vs ~20s).
    - [x] Archived legacy `data/html` (7.3GB) and `data/apnic_roa` (272MB) into compressed cold storage.
- [ ] Evaluate moving to SQLite for random access if needed (currently memory-based load is fast enough).
- [ ] Add a command-line tool to "unpack" or "query" the packed ASN data for quick debugging.
