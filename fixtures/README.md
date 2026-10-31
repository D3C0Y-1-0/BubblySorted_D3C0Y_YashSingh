# Fixtures

Each folder under `projects/` is one service, the same shape `hedwig init` expects.

| Folder | Seeded weakness | Purpose |
|---|---|---|
| `node-lodash` | `lodash` 4.17.15 | Success path: the bump keeps tests green. Current OSV data makes 4.18.0 the package fix |
| `broken-after-bump` | `lodash` 4.17.15, `_.template` with a multi-name `variable` option | A bump past 4.17.21 breaks the code, so the fix agents must migrate it |
| `py-yaml` | `PyYAML` 5.3.1, `yaml.load` | Reachable case |
| `py-yaml-safe` | `PyYAML` 5.3.1, `yaml.safe_load` | Unreachable case |
| `maven-log4j` | `log4j-core` 2.14.1 (Log4Shell) | Java detection |
| `cargo-regex` | `regex` 1.5.4 (CVE-2022-24713) | Rust detection |
| `composer-phpmailer` | `phpmailer/phpmailer` 6.4.1 (CVE-2021-34551, CVE-2021-3603) | PHP detection. `composer.lock` is hand-written |

`advisories/` holds raw API responses so offline runs parse the same shapes as live ones:
- `osv/`: `querybatch.request.json` and `querybatch.json`, plus the full record for every returned vuln in `vulns/`
- `kev.json`: CISA KEV catalog trimmed to a few CVEs
- `epss.json`: EPSS scores for the CVEs above

