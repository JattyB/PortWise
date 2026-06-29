# Packaged exploitability data

`epss.json` preserves FIRST EPSS API v1 fields (`cve`, probability `epss`,
`percentile`, and `date`). `kev.json` preserves the CISA Known Exploited
Vulnerabilities catalog fields. The packaged subset supports deterministic
offline scans and may be replaced by a sync job without changing enrichment.
