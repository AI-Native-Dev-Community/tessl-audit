# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-12

### Added
- Initial release
- Security posture table per plugin (Passed / Advisory / Risky / Critical / Not run / Unknown)
- Quality score and uplift columns from the Tessl registry
- Warning codes listed inline (e.g. W007, W011) with descriptions below the table
- Summary section with totals by security status and links to full registry reports
- Recommended Actions section (quality review, evals, skill optimizer)
- `--json` flag for machine-readable output suitable for CI pipelines
- Concurrent registry fetches (pool of 6) for fast audits on large `tessl.json` files
- `--help` and `--version` flags
- Path traversal and argument injection mitigations
