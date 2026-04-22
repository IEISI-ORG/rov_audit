# TODO List

- [ ] Investigate volatile changes where an ASN regresses in RPKI/ROV status. 
    - Example: AS45355 regressed according to APNIC Labs: https://stats.labs.apnic.net/rpki/AS45355?c=FJ&w=7&l=1&v=0&p=thisp&x=thisx
    - Potential cause: Partial coverage combined with Traffic Engineering (TE) changes causing loss of coverage.
    - Action: Implement a check to detect such regressions in the audit pipeline.
- [ ] Incorporate raw timeseries data from APNIC for trend analysis.
    - Example URL: https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl?x=FJ4638 (ASN 4638)
    - Action: Explore using this JSON endpoint to track RPKI adoption/regression over time for specific ASNs.
