# TODO List

- [ ] Investigate volatile changes where an ASN regresses in RPKI/ROV status. 
    - Example: AS45355 regressed according to APNIC Labs: https://stats.labs.apnic.net/rpki/AS45355?c=FJ&w=7&l=1&v=0&p=thisp&x=thisx
    - Potential cause: Partial coverage combined with Traffic Engineering (TE) changes causing loss of coverage.
    - Action: Implement a check to detect such regressions in the audit pipeline.
- [ ] Incorporate raw timeseries data from APNIC for trend analysis.
    - Example URL: https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl?x=FJ4638 (ASN 4638)
    - Action: Explore using this JSON endpoint to track RPKI adoption/regression over time for specific ASNs.
- [ ] Data Storage Refactoring:
    - Evaluate moving from thousands of small JSON files (`data/parsed/`) to a more efficient storage format like SQLite, Parquet, or a single compressed JSONL file to improve I/O and disk space usage.
    - Formalize the archiving of legacy directories (`data/html`, `data/apnic_roa`) into a single compressed archive for cold storage, removing them from the active workspace.
