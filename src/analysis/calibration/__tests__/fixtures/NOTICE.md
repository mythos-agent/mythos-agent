# Calibration fixtures — upstream source attribution

The files under this directory are unmodified copies of single source
files from third-party open-source projects, taken at the
`vulnerable_commit` SHA recorded in the matching
`benchmarks/cve-replay/cases/<GHSA>.json`. They exist so the variants
v2 calibration test (`runCalibration`) can run offline and
deterministically in CI.

| Fixture path                                  | Origin                                                                                                  | Upstream license |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------- |
| `GHSA-c2qf-rxjj-qqgw/re.js`                  | `npm/node-semver` @ `2f738e9a70d9b9468b7b69e9ed3e12418725c650`, path `internal/re.js`                  | ISC              |
| `GHSA-cxjh-pqwp-8mfp/index.js`               | `follow-redirects/follow-redirects` @ `8526b4a1b2ab3a2e4044299377df623a661caa76`, path `index.js`     | MIT              |

Each file is redistributed unmodified under its upstream license.
The full license texts are in the upstream repos at the cited commits.

## How to refresh

If a calibration target changes (e.g. a new line band is identified),
re-fetch from GitHub raw at the recorded commit SHA — never from a
branch tip, since the calibration target depends on the exact commit
state:

```sh
curl -fsSL "https://raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>" \
  -o src/analysis/calibration/__tests__/fixtures/<GHSA>/<filename>
```

Then update the case file's `calibration_target.lines` to match the
refreshed file's vulnerable line numbers, and re-run the calibration
test suite.
