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

Both issues roll rather than duplicate: each delta is posted as a collapsible
comment — a visible one-line headline with the tables tucked into a
`<details>` block, so the thread scans like a changelog. Comments are what
notify subscribers, and most email clients ignore `<details>`, so the
notification email still shows the full delta. The issue body is the landing
page: cumulative stats (monitoring since, runs with alerts, findings
alerted/resolved, currently outstanding) and a pointer at the newest comment.
Consecutive deltas don't overlap — each is measured against the previous
run's baseline — so the comment thread is the complete history. See
[examples/](examples/) for the direct-action variant with custom steps
(e.g. Slack on malware).

## Inputs

| Input | Default | Description |
|---|---|---|
| `rl-token` | *(required)* | Community (`rlcmm*`) or Portal (`rls3c*`) token |
| `manifest-path` | auto-detect | Lockfiles preferred: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic), `poetry.lock`, `uv.lock`, `requirements.txt`, `Gemfile.lock`, then manifests |
| `scan-profile` | `baseline` | `minimum` / `baseline` / `hardened`. `hardened` is deliberately strict — good for PR gating, noisy for a monitor |
| `check-deps` | `release,develop,transitive` | Passed to `rl-protect scan --check-deps` |
| `baseline-path` | `.rl-protect/baseline.json` | Committed findings baseline |
| `baseline-branch` | — | Store the baseline on a dedicated orphan branch (e.g. `rl-protect-baseline`) instead of the scanned branch — use when the scanned branch is protected |
| `commit-baseline` | `true` | Commit + push the updated baseline. If `false`, persist the rewritten baseline yourself — against a stale baseline every run repeats the same alerts and the issue's cumulative stats reset to a single-run snapshot |
| `notify` | `issue` | `issue` / `none` (job summary is always written) |
| `issue-label` | `rl-protect-monitor` | Label of the rolling issue |
| `alert-on-first-run` | `false` | Alert on all findings when no baseline exists |
| `fail-on` | `never` | `never` / `critical` / `any-new`. A monitor should not gate — evaluated *after* notifications and baseline commit |
| `heartbeat-url` | — | Ping URL (e.g. healthchecks.io) hit after each successful run |
| `python-version` | `3.12` | Runtime for rl-protect + the diff engine |
| `github-token` | `github.token` | Needs `issues: write`; `contents: write` for the push |

## Outputs

`new-count`, `new-critical-count`, `resolved-count`, `has-alerts`,
`has-critical-alerts`, `has-updates` (alerts *or* resolutions), `first-run`,
`delta-json` (path to the machine-readable delta), `delta-artifact` (name of
the uploaded artifact holding it).

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
- **Alerts are grouped and capped**: the delta comments group one row per
  finding (listing the affected packages) and cap the table, since a real
  scan can produce 1200+ findings from 58 distinct CVEs. The complete,
  ungrouped delta is uploaded as a workflow artifact on every run — named by
  the `delta-artifact` output and kept for 90 days — which is what the
  comment's truncation notice points at.
- **Resolutions refresh the issue quietly**: a run that only resolves
  findings re-renders the issue body, so its "resolved" and "outstanding"
  counters stay true, but posts no comment — a body edit doesn't notify, and
  good news shouldn't page you. When a bucket's outstanding count reaches
  zero the body says so; closing the issue is left to you.
- **Stats live in the baseline**: the cumulative counters shown on the issue
  body are stored in the baseline's `stats` block and only count alerts since
  monitoring started — including "currently outstanding", so all four numbers
  reconcile. The backlog absorbed on the first run is reported separately, as
  "pre-existing backlog". Which findings have alerted is recorded as an
  `alerted` flag on the finding records themselves, so the baseline carries
  no duplicate copy of their keys. Deleting or regenerating the baseline
  resets all of it. Baselines written before schema 2 are migrated on the
  next run, at the cost of one extra baseline commit.
- **Two units, both labelled**: counters and headlines are package-level (one
  per package × finding, matching `delta.json` and the count outputs), while
  a table row is one *distinct* finding across every package carrying it.
  Where they differ the table says so, so a comment reading "1218 new" above
  58 rows reconciles instead of looking wrong.

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
