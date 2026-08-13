# Changelog

All notable changes to this action are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Consumers pin the floating major tag (`@v1`), which always points at the
newest release in the `1.x` line. Pin an exact tag (`@v1.0.0`) if you need
behaviour to stay frozen.

## [1.3.0] - 2026-08-12

The rolling issues change shape: the body becomes a cumulative-stats landing
page and each delta lives in a collapsible comment, so the latest delta is no
longer shown twice. No inputs or outputs changed; existing workflows upgrade
without modification. Expect one extra baseline commit on the first run after
upgrading, when the baseline adopts its `stats` block.

### Changed

- The issue body no longer repeats the latest delta. It now shows cumulative
  monitoring stats — monitoring since, runs with alerts, findings alerted /
  worsened / resolved, currently outstanding — plus a one-line "latest
  change" headline pointing at the newest comment, which carries the delta.
- Delta comments collapse: a visible headline ("New findings: 2 new · 1
  worsened — 2026-08-12") with the tables inside a `<details>` block, so a
  long thread scans like a changelog. Notification emails are unaffected:
  most mail clients ignore `<details>` and render the full delta.
- Creating a rolling issue now also posts the first delta comment, so the
  body's pointer at the newest comment holds from the issue's first minute
  (at the cost of a second notification on that first alert).

### Added

- Cumulative counters in the baseline (`stats` block), kept per severity
  bucket and counting only alerts since monitoring started — the backlog
  absorbed on the first run is not counted. They move only when findings
  change, so the "no commit churn on quiet runs" guarantee from 1.1.0 holds.
  Deleting or regenerating the baseline resets them.

## [1.2.0] - 2026-08-08

No inputs, outputs, or baseline formats changed. Existing workflows upgrade
without modification; the only visible difference is that the rolling issues
gain a comment carrying the full delta.

### Fixed

- Each run's delta is posted as a comment on the rolling issue, not just
  written over the body. Because a delta is measured against the baseline the
  *previous* run wrote, consecutive deltas never overlap — so overwriting the
  body discarded the earlier findings entirely, and the notifying comment
  ("the issue body above has been updated") pointed at a body that no longer
  contained what it had announced. Once the workflow artifact expired, the
  only surviving copy was gone. The comment is now posted before the body
  edit, so a failure between the two calls cannot lose a delta.

### Changed

- The issue footer states that the body shows the latest delta and that
  earlier ones are in the comments, replacing wording that implied the body
  accumulated.
- Marketplace listing name is now "Dependency malware & vulnerability monitor
  (rl-protect)" — the repository, and therefore every `uses:` reference, is
  unchanged.
- README drops the banner and tagline; the opening paragraph already stated
  the same claim more precisely.

## [1.1.0] - 2026-08-02

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

[Unreleased]: https://github.com/kburich/rl-protect-monitor/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kburich/rl-protect-monitor/releases/tag/v1.0.0
