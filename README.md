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

Both issues roll rather than duplicate: each delta is posted as a comment
(which notifies subscribers) and the issue body is updated to show the latest
one. Consecutive deltas don't overlap — each is measured against the previous
run's baseline — so the comment thread is the full history, while the body
answers "what changed most recently?". Set `issue-comment: notice` for a
one-line ping instead of the full delta — quieter in the inbox, but the delta
then survives only in the body until the next run overwrites it (and in that
run's `delta.json` artifact). See [examples/](examples/) for the
direct-action variant with
custom steps (e.g. Slack on malware).

## Inputs

| Input | Default | Description |
|---|---|---|
| `rl-token` | *(required)* | Community (`rlcmm*`) or Portal (`rls3c*`) token |
| `manifest-path` | auto-detect | Lockfiles preferred: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic), `poetry.lock`, `uv.lock`, `requirements.txt`, `Gemfile.lock`, then manifests |
| `scan-profile` | `baseline` | `minimum` / `baseline` / `hardened`. `hardened` is deliberately strict — good for PR gating, noisy for a monitor |
| `check-deps` | `release,develop,transitive` | Passed to `rl-protect scan --check-deps` |
| `baseline-path` | `.rl-protect/baseline.json` | Committed findings baseline |
| `baseline-branch` | — | Store the baseline on a dedicated orphan branch (e.g. `rl-protect-baseline`) instead of the scanned branch — use when the scanned branch is protected |
| `commit-baseline` | `true` | Commit + push the updated baseline |
| `notify` | `issue` | `issue` / `none` (job summary is always written) |
| `issue-label` | `rl-protect-monitor` | Label of the rolling issue |
| `issue-comment` | `delta` | What each run posts on the rolling issue: `delta` (the full findings) or `notice` (a one-line ping at the updated body) |
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

- **Protected branches**: if your default branch requires PRs, the baseline
  push will be rejected. Either add the `github-actions` app as a bypass
  actor in your branch ruleset, or set `baseline-branch: rl-protect-baseline`
  to keep the baseline on a dedicated orphan branch that `main`'s protection
  doesn't cover. The scanned branch is never touched in that mode, and the
  baseline branch keeps its own audit-trail history.
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
- **Upgrades don't page you**: findings are keyed by package *without* the
  version, so bumping a dependency that carries the same CVE forward is
  silent. Without that, one lockfile bump of a package like `esbuild` — which
  ships ~20 per-platform variants, each carrying the same Go stdlib CVEs —
  would report ~800 findings as resolved and ~800 as new.
- **Alerts are grouped and capped**: the issue body groups one row per
  finding (listing the affected packages) and caps the table, since a real
  scan can produce 1200+ findings from 58 distinct CVEs. The complete,
  ungrouped delta is always in the `delta.json` workflow artifact.

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

## License

MIT

## Disclaimer

Not an official ReversingLabs project. This is an independent action that
calls the public `rl-protect` CLI.
