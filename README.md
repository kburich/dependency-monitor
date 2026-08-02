# rl-protect-monitor

GitHub Action that periodically re-scans your dependency manifest with
[ReversingLabs rl-protect](https://docs.secure.software/) and alerts you —
via GitHub Issues — **only when something changes**: a new malware verdict,
a new CVE, a worsened finding, or a resolved one.

## Why a monitor?

`rl-protect scan` is a lookup against the Spectra Assure Community database,
not a local analysis. Your lockfile doesn't change, but the verdict on a
pinned package can: a dependency that passed yesterday may be flagged as
malware tomorrow when the database is updated (as happened with
`ua-parser-js`, `event-stream`, and many others). A one-shot scan in CI
catches bad packages *entering* your project; this monitor catches packages
that *go bad after* they're already in.

The core is a **delta engine**: each run is diffed against a baseline
committed to your repo (`.rl-protect/baseline.json`), and you're only
notified about changes — never re-spammed about known findings. The baseline's
git history doubles as an audit trail of exactly when a package went bad.

## Quick start

1. Create a free [Spectra Assure Community](https://secure.software/) account
   and generate a token (starts with `rlcmm`).
2. Add it to your repo as the `RL_TOKEN` secret.
3. Add `.github/workflows/rl-protect-monitor.yml`:

```yaml
name: Dependency monitor
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch: {}
jobs:
  monitor:
    uses: kburich/rl-protect-monitor/.github/workflows/monitor.yml@v1
    permissions:
      contents: write   # commit the baseline back
      issues: write     # open/update notification issues
    secrets:
      rl-token: ${{ secrets.RL_TOKEN }}
```

The first run scans your manifest, records the baseline (no alert), and
commits it. Subsequent runs alert only on deltas:

- **Malware / tampering** → a `🚨`-titled issue labeled `rl-protect-malware`
  (treat as an incident — the package may already be installed).
- **Vulnerabilities / secrets / licenses / hardening** → a separate,
  quieter rolling issue labeled `rl-protect-monitor`.

Both issues are updated in place (with a notifying comment) instead of being
duplicated. See [examples/](examples/) for the direct-action variant with
custom steps (e.g. Slack on malware).

## Inputs

| Input | Default | Description |
|---|---|---|
| `rl-token` | *(required)* | Community (`rlcmm*`) or Portal (`rls3c*`) token |
| `manifest-path` | auto-detect | Lockfiles preferred: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic), `poetry.lock`, `uv.lock`, `requirements.txt`, `Gemfile.lock`, then manifests |
| `scan-profile` | `baseline` | `minimum` / `baseline` / `hardened`. `hardened` is deliberately strict — good for PR gating, noisy for a monitor |
| `check-deps` | `release,develop,transitive` | Passed to `rl-protect scan --check-deps` |
| `baseline-path` | `.rl-protect/baseline.json` | Committed findings baseline |
| `commit-baseline` | `true` | Commit + push the updated baseline |
| `notify` | `issue` | `issue` / `none` (job summary is always written) |
| `issue-label` | `rl-protect-monitor` | Label of the rolling issue |
| `alert-on-first-run` | `false` | Alert on all findings when no baseline exists |
| `fail-on` | `never` | `never` / `critical` / `any-new`. A monitor should not gate — evaluated *after* notifications and baseline commit |
| `heartbeat-url` | — | Ping URL (e.g. healthchecks.io) hit after each successful run |
| `python-version` | `3.12` | Runtime for rl-protect + the diff engine |
| `github-token` | `github.token` | Needs `issues: write`; `contents: write` for the push |

## Outputs

`new-count`, `new-critical-count`, `resolved-count`, `has-alerts`,
`has-critical-alerts`, `first-run`, `delta-json` (path to the
machine-readable delta).

## Operational notes

- **Cron auto-disable**: GitHub disables scheduled workflows after 60 days
  without repo activity, and cron firing is best-effort. For a security
  monitor that failure mode is silent — set `heartbeat-url` to a
  [healthchecks.io](https://healthchecks.io)-style check so you're alerted
  when the monitor *stops running*.
- **Quota**: Community accounts are metered in monthly entitlement units.
  The action checks `rl-protect server list` after each scan and warns in
  the job summary at ≥80% usage. Daily cadence is plenty; the database
  doesn't update faster than that.
- **Ecosystems**: whatever rl-protect supports — npm, PyPI, RubyGems.
  Modern `yarn.lock` (Yarn 2+) is not supported by rl-protect.
- **Monitor the lockfile, not the manifest** — otherwise you're monitoring
  a version range instead of what's actually installed.

## Development

```bash
python -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/
```

The diff engine is stdlib-only Python (`monitor/`), unit-tested against
fixture reports shaped like the
[documented rl-protect report schema](https://docs.secure.software/cli/rl-protect-schema).

Local dry run without a token:

```bash
python -m monitor.main \
  --report tests/fixtures/report_new_malware.json \
  --baseline /tmp/baseline.json --manifest package-lock.json --out-dir /tmp/out
```

## Roadmap

Slack/SARIF/email notifiers · multi-manifest matrix · org-wide central mode.

## License

MIT. Not affiliated with ReversingLabs; `rl-protect` and Spectra Assure are
their products — this action just orchestrates them.
