# Changelog

All notable changes to this action are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Consumers pin the floating major tag (`@v1`), which always points at the
newest release in the `1.x` line. Pin an exact tag (`@v1.0.0`) if you need
behaviour to stay frozen.

## [Unreleased]

Hardening driven by a real pnpm workspace scan: 1237 findings across 64
packages, 1193 of them from 36 `@esbuild` platform variants carrying the same
58 Go stdlib CVEs.

No inputs or outputs changed, and existing baselines are read as-is — finding
identity is derived from the stored purl on load, so both sides of the first
diff after upgrading use the new identity and no upgrade-triggered alerts
appear. Expect one extra baseline commit on the first run, because the record
sort order changed.

### Changed

- Findings are keyed by package **without** the version. A version-pinned
  identity re-keyed every finding on an upgraded package, so a single lockfile
  bump of a package like `esbuild` reported ~800 findings as resolved and ~800
  as new — and "new" is the alerting path. Upgrades that carry a finding
  forward are now silent; a version change is annotated on the row when it
  accompanies a genuine escalation.
- Alert tables group one row per finding, listing the affected packages, and
  are capped. The complete ungrouped delta stays in the `delta.json` artifact.
- The baseline is only rewritten when findings actually change. Its
  `generated` stamp previously dirtied the file on every run, so each
  scheduled scan committed and pushed a 450 KB baseline even when nothing was
  found.
- Baseline records sort by `(key, purl)`, so a package present at several
  versions cannot churn file order between otherwise identical scans.
- CVSS scores are rounded for display — 476 of 1205 scored findings rendered
  as float32 artifacts such as `5.300000190734863`.

### Fixed

- Issue bodies could exceed GitHub's 65,536-character limit and fail
  `gh issue create` with a 422, which killed the notify step. Rendering every
  finding as its own row came to ~230 KB; the same delta now renders at ~13 KB,
  with a hard clip as a backstop.
- Findings that collide under the version-independent key are merged, keeping
  the more severe. Real lockfiles routinely carry one package at two versions
  (20 of them in the reference scan); the tie-break is by purl so the retained
  finding never depends on report ordering.

## [1.0.0] - 2026-08-02

Initial release.

### Added

- Scheduled rl-protect scan of a lockfile, diffed against a committed
  baseline so alerts fire only on *new* findings, worsened findings, or
  resolutions — not on the standing backlog.
- Severity split: malware and tampering raise a separate, louder rolling
  issue from ordinary vulnerability, licence, secret, and hardening findings.
- Rolling GitHub issues, one per severity bucket, updated in place with a
  comment rather than duplicated on each run.
- GitHub Actions job summary, plus `delta.json` and Markdown artifacts.
- `baseline-branch` mode, keeping the baseline on a dedicated orphan branch
  for repositories whose default branch rejects direct pushes.
- `heartbeat-url` ping, so a monitor that silently stops running (GitHub
  disables cron after 60 days of repo inactivity) is itself detectable.
- Entitlement-quota warning in the job summary at ≥80% usage.
- `alert-on-first-run` for repositories that want the initial backlog
  reported rather than absorbed into the baseline.

[Unreleased]: https://github.com/kburich/rl-protect-monitor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kburich/rl-protect-monitor/releases/tag/v1.0.0
