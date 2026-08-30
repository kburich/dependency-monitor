# rl-protect-monitor

GitHub Action that periodically re-scans your dependencies for security
issues with [ReversingLabs rl-protect](https://docs.secure.software/) and
alerts you when something changes.

## Why rl-protect-monitor?

Advisory-based dependency scanners can only tell you about a package once
someone has reported it. rl-protect reports the same known vulnerabilities,
and on top of them ReversingLabs' own analysis of every package as it lands
in npm, PyPI and the other registries: install scripts, obfuscation, network
calls, tampering, leaked secrets. That covers packages nobody has filed an
advisory for, and categories advisories don't have.

The monitor makes that a standing check rather than a one-off: a package
that passed yesterday may be flagged tomorrow, as `ua-parser-js` and
`event-stream` were. Each scheduled re-scan is diffed against a baseline so
you hear about changes only, malware is split into its own `🚨` issue you
can page on, and the baseline history shows exactly when a package went
bad.

It complements those scanners rather than replacing them — it opens no
upgrade PRs, runs on a schedule rather than in real time, and needs a
Spectra Assure token. Run both.

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
    uses: kburich/rl-protect-monitor/.github/workflows/monitor.yml@v3
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

## Alerting

Alerts are delivered as GitHub Issues by default. When a scan finds
something new — a malware verdict, a CVE, or a finding that got worse — the
action opens a rolling issue for it, or comments on the one already open.
When a finding goes away, that is reported as a comment on the same issue.

Each rolling issue is an append-only log: its body is the delta that opened
it, and every later delta is a comment. Nothing is edited, so the thread is
the complete history, newest at the bottom.

**Email.** An issue comment is an email to everyone subscribed to the issue.
Use the `assignees` input to subscribe people automatically when an issue is
opened; without it, only those watching the repository are notified.

**Slack and everything else.** [GitHub's Slack app](https://github.com/integrations/slack)
can subscribe a channel to the repo's issues filtered by label, so
`rl-protect-malware` alone can page a channel. Or guard your own step with
the action's [outputs](#outputs) — `has-critical-alerts`, `has-alerts` —
and post anywhere; [examples/consumer-action.yml](examples/consumer-action.yml)
shows a Slack webhook on malware. `notify: none` skips the issues entirely
and leaves the outputs and `delta-artifact` to drive your channel.

## Inputs

| Input | Default | Description |
|---|---|---|
| `rl-token` | *(required)* | Community (`rlcmm*`) or Portal (`rls3c*`) token |
| `manifest-path` | auto-detect | Lockfiles preferred: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic), `poetry.lock`, `uv.lock`, `requirements.txt`, `Gemfile.lock`, then manifests |
| `scan-profile` | `baseline` | `minimum` / `baseline` / `hardened`. `hardened` is deliberately strict — good for PR gating, noisy for a monitor |
| `check-deps` | `release,develop,transitive` | Passed to `rl-protect scan --check-deps` |
| `baseline-path` | `.rl-protect/baseline.json` | Path the baseline is stored at, within whichever branch holds it |
| `monitor-id` | `auto` | Names this monitor's baseline branch and rolling issues; derived from the manifest so two monitors in one repo stay apart. Set it to separate two monitors on the same manifest |
| `baseline-branch` | `auto` | `auto` → `rl-protect-baseline/<monitor-id>`, an orphan branch your default branch's protection doesn't cover. A name uses that branch; empty commits the baseline to the default branch, where it shows up in PR diffs but needs direct pushes to be allowed |
| `commit-baseline` | `true` | Commit + push the updated baseline. If `false`, persist the rewritten baseline yourself — against a stale baseline every run repeats the same alerts |
| `notify` | `issue` | `issue` / `none` (job summary is always written) |
| `issue-label` | `rl-protect-monitor` | Extra label on both rolling issues, for filtering. It doesn't identify them — the per-monitor marker label does |
| `assignees` | — | Comma-separated usernames assigned when a rolling issue is opened, which subscribes them. Without it, only repo watchers are notified |
| `alert-on-first-run` | `false` | Alert on all findings when no baseline exists |
| `fail-on` | `never` | `never` / `critical` / `any-new`. A monitor should not gate — evaluated *after* notifications and baseline commit |
| `heartbeat-url` | — | Ping URL (e.g. healthchecks.io) hit after each successful run |
| `python-version` | `3.12` | Runtime for rl-protect + the diff engine |
| `github-token` | `github.token` | Needs `issues: write`; `contents: write` for the push |

## Outputs

`new-count`, `changed-count` (worsened), `new-critical-count` (new *or*
worsened malware/tampering), `resolved-count`, `has-alerts`,
`has-critical-alerts`, `has-updates` (alerts *or* resolutions), `first-run`,
`delta-json` (path to the machine-readable delta), `delta-artifact` (name of
the uploaded artifact holding it).

The reusable workflow passes all of these through as job outputs except
`delta-json`, a path inside a runner that is gone by the time your next job
starts — download the `delta-artifact` instead.

## Operational notes

- **Default branch only**: GitHub fires scheduled workflows nowhere else,
  and periodic re-scanning is the whole point, so runs triggered on
  another branch are rejected with an error.
- **Protected branches**: nothing to do — the default `baseline-branch: auto`
  keeps the baseline on an orphan branch your default branch's protection
  doesn't cover, and never touches the scanned branch. Only if you set
  `baseline-branch: ""` to commit the baseline in-tree do you need the
  default branch to accept direct pushes (add the `github-actions` app as a
  bypass actor in your ruleset). That case is checked before scanning, so a
  protected branch fails with a clear error rather than a rejected push.
- **One monitor per manifest**: a monitor's baseline branch and its two
  rolling issues are named after the manifest it scans, so a monorepo can run
  one job per manifest without them overwriting each other. Two jobs pointed
  at the *same* manifest need distinct `monitor-id` values.
- **Cron auto-disable**: GitHub disables scheduled workflows after 60 days
  without repo activity, and cron firing is best-effort. For a security
  monitor that failure mode is silent — set `heartbeat-url` to a
  [healthchecks.io](https://healthchecks.io)-style check so you're alerted
  when the monitor *stops running*.
- **Quota**: Community accounts are metered in monthly entitlement units.
  The action checks `rl-protect server list` after each scan and warns in
  the job summary at ≥85% usage. A daily or twice-daily cadence is plenty.
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
- **A resolution never opens an issue**: with no open issue for its bucket, a
  resolution-only run posts nothing — there is nothing to alert on.
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
