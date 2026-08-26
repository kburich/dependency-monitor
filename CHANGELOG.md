# Changelog

All notable changes to this action are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Consumers pin the floating major tag (`@v2`), which always points at the
newest release in the `2.x` line. Pin an exact tag (`@v2.0.0`) if you need
behaviour to stay frozen.

## [Unreleased]

The rolling issues become append-only alert logs. The issue body is written
once, at creation, and carries that run's delta — the same rendering every
comment uses — so the very first notification email already contains the
findings. Nothing is edited afterwards: the cumulative-stats landing page,
the "latest change" pointer, and the title refresh are gone, and every later
delta — resolutions now included — arrives as a comment. The monitor alerts;
it does not track. Remediation state belongs in a work tracker, and the
committed baseline already *is* the current full state.

**Upgrading:** rolling issues opened by earlier versions are reused as-is —
new deltas continue as comments — but their stats bodies freeze at the last
pre-upgrade edit. Close them if the stale body bothers you; the next alert
opens a fresh issue in the new shape. The baseline migrates itself (schema 3
drops the `stats` block and the per-record `alerted` flags) in one extra
baseline commit, and resolutions now notify subscribers where they used to
be silent.

### Changed

- Each run's delta is the only thing ever written to the rolling issue: as
  its body when it has to be opened, as a comment otherwise. The
  comment-first/edit-second ordering, the `--body-only` refresh mode and the
  stats renderer are gone with the body edits; the notifier makes exactly
  one write per bucket per run.
- Resolutions are posted as comments — and therefore notify. A run that
  only resolves findings used to refresh the issue body silently; now the
  stand-down lands in the thread, keeping it a complete changelog. It still
  never *opens* an issue: a resolution of something never reported stays
  unreported.
- Malware comments drop the "treat this as an incident" sentence — the 🚨
  title and headline already carry the urgency — and a resolution-only
  malware comment drops the siren too. The standard bucket's headline label
  is now "Dependency findings" (was "New findings"), since a delta can now
  be resolutions alone.

### Removed

- The cumulative monitoring stats: monitoring-since, runs-with-alerts,
  alerted-so-far, currently-outstanding and the pre-existing-backlog line,
  along with everything that fed them. Baseline schema 3 drops the `stats`
  block and the per-record `alerted` flags; older baselines are read as-is
  and shed both in a single migration rewrite.

### Added

- An `assignees` input: comma-separated usernames assigned when a rolling
  issue is opened, which subscribes them to the thread. Until now the action
  had no way to reach anyone who was not already watching the repository —
  the rolling issues are opened by `github-actions[bot]`, so they notify
  watchers and nobody else. On an unwatched repo that meant alerts landed in
  an issue and paged no one, which is indistinguishable from the monitor not
  running. Assignment happens at issue creation only, so someone who
  unassigns themselves is not re-added on the next run, and it is
  best-effort: a name that cannot be assigned warns rather than failing the
  run, because a malware alert must land even when its assignee is misspelt.

### Changed

- The bundled actions move to their Node 24 majors: `actions/checkout@v7`,
  `actions/setup-python@v7` and `actions/upload-artifact@v7`. GitHub forced
  the old Node 20 majors onto Node 24 and annotated every run with a
  deprecation warning, so this only makes explicit what the runner was
  already doing. **Self-hosted runners must be on 2.327.1 or newer** —
  Node 24 actions will not start on anything older. GitHub-hosted runners are
  long past it. Consumers who copied `examples/consumer-action.yml` should
  bump their own `actions/checkout` pin too; the reusable workflow carries
  its own and needs nothing.
- `issue-label` is documented as being for filtering only. It previously said
  "for filtering and subscribing", but GitHub has no per-label notification
  subscription — a reader who applied the label and expected to be paged got
  nothing. Use `assignees`, or watch the repository.

### Fixed

- Manifests whose name ends in `.lock` no longer derive an unusable baseline
  branch. git reserves that suffix on a ref component and refuses the refspec
  outright, so `poetry.lock`, `uv.lock`, `yarn.lock` and `Gemfile.lock` — four
  of the manifests auto-detection looks for — each named a branch that could
  not be created. The failure landed at the push, which runs *after* the
  issue notification, so every run alerted and then died with the baseline
  unwritten; with no baseline ever persisted, the next run re-alerted the same
  findings. The suffix is now defused to `-lock`
  (`rl-protect-baseline/poetry-lock`), matched case-sensitively as git matches
  it, so a `.LOCK` path that was always valid keeps its id.
- A `..` sequence in a manifest path no longer does the same. `.` survives the
  slug's character whitelist while `..` is forbidden anywhere in a ref, so a
  path like `pkgs/../uv.lock` reached the push and was refused there. Runs of
  dots now collapse to one.

  Monitors on the affected manifests never completed a first run, so no
  baseline is orphaned by the new ids. Any rolling issues those runs managed
  to open beforehand carry the old marker label and will not be recognised —
  close them by hand.

## [2.0.0] - 2026-08-17

The monitor becomes multi-manifest safe, and its durable state moves off your
default branch. Each monitor — one per manifest — now owns a baseline branch
and a pair of rolling issues named after the manifest it scans.

**Upgrading from 1.x requires attention.** The baseline moves from
`.rl-protect/baseline.json` in your repo to the orphan branch
`rl-protect-baseline/<monitor-id>`, so the first run after upgrading records a
fresh baseline and the cumulative stats restart. Set `baseline-branch: ""` to
keep the old in-tree location. Your existing rolling issues are also no longer
recognised — they carry the old bare labels, while the lookup now uses a
per-monitor marker — so 2.0.0 opens new ones; close the old threads by hand.
Workflows triggering the action anywhere but the default branch now fail.

### Changed

- The entitlement-quota warning now fires at ≥85% usage instead of ≥80%,
  for both the workflow annotation and the job-summary line. It also names
  upgrading from a Community account alongside reducing scan cadence and
  narrowing `check-deps` scope.
- The action's labels are created if missing and then left alone. They were
  created with `--force`, an upsert that reset the colour and description on
  every notifying run — so restyling a label to fit your own scheme, or
  describing it for your team, was silently reverted by the next scan. How
  the labels look is now yours; only their names matter to the action.
- The baseline is stored on a dedicated orphan branch by default
  (`baseline-branch: auto` → `rl-protect-baseline/<monitor-id>`) instead of
  being committed to the scanned branch. Branch protection no longer needs
  bypass rules, the default branch's history stays free of bot commits, and
  the in-tree behaviour remains available as `baseline-branch: ""`.
- A monitor's rolling issues are identified by a per-monitor, per-bucket
  marker label (`rl-protect-monitor/<id>`, `rl-protect-malware/<id>`). The
  malware bucket's marker used to be hardcoded, so every monitor in a repo
  shared one incident issue — and each overwrote its title and stats body
  with its own. `issue-label` is now an extra label for filtering and
  subscribing, not the identifier.
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
- **Baseline schema 2.** The set of finding keys that have alerted moved out
  of `stats.*.alerted` and onto the finding records themselves, as an
  `alerted: true` flag. The old parallel list duplicated the key of a record
  already in the file: on a 1239-finding scan it added ~122 KB (a 24% larger
  baseline) and a 6,213-line `stats` block, so a routine lockfile bump
  produced a multi-thousand-line diff hunk. It is now 15 lines. Existing
  schema-1 baselines are migrated automatically on the next run — one extra
  commit, and nothing already alerted is forgotten.

### Added

- Input validation, as the action's first step so a misconfiguration costs
  no entitlement units.
- The action runs on the default branch only, enforced with an error naming
  the branch it expected. GitHub fires `schedule:` nowhere else, so a run
  elsewhere could not be periodic — and would write to the same baseline and
  issues as the real monitor, silently alternating them.
- `monitor-id`, identifying a monitor's durable state. Derived from the
  manifest by default, so a monorepo can run one job per manifest without
  them overwriting each other's baseline and issues.
- Opting into an in-tree baseline is checked against the default branch's
  protection *before* scanning, so it fails with an actionable message rather
  than a rejected push after entitlement has been spent.
- The baseline push to a dedicated branch is retried, like the in-tree push
  already was. Each attempt rebuilds on the branch's current tip and stages
  only its own path, so a concurrent monitor's commit is preserved.
- `has-updates` output: true when anything was new, worsened, *or* resolved.
  The notification step gates on it rather than `has-alerts`, so a
  resolution-only run still refreshes the issue's stats body.
- `delta-artifact` output: the name of the uploaded artifact holding the
  complete, ungrouped `delta.json`.
- Cumulative counters in the baseline (`stats` block), kept per severity
  bucket and counting only alerts since monitoring started — the backlog
  absorbed on the first run is not counted, and neither are its resolutions
  (each bucket tracks the finding keys it has alerted on; `resolved` counts
  only those). They move only when findings change, so the "no commit churn
  on quiet runs" guarantee from 1.1.0 holds. Deleting or regenerating the
  baseline resets them.

### Removed

- `--exclude-label` on the notifier, along with the lookup's page-scanning
  and its full-page warning. It existed only because both buckets' issues
  carried the same identifying label; per-bucket markers are disjoint by
  construction, so the lookup is now one row by one label.

### Fixed

- The heartbeat is now pinged before the `fail-on` gate is evaluated, not
  after. It reports that the monitor *ran*, not that it found nothing, so
  running it after the gate skipped the ping on exactly the runs that
  worked: `fail-on: critical` plus a real malware finding exited the job
  before the ping, and the healthcheck raised a dead-monitor alert on top of
  the malware issue. Only `fail-on: critical` or `any-new` combined with
  `heartbeat-url` was affected; the default `fail-on: never` never reached
  the exit.
- A non-numeric `count` in a scan report or a baseline no longer crashes the
  run. Counts came straight from `int()`, so one malformed value from the
  vendor's report — or a hand-edited baseline — raised `ValueError` and took
  down the whole alerting run. They now heal to 0, matching how the stats
  counters have always behaved. 0 can never read as an escalation, so a
  corrupt count under-alerts rather than pages falsely.
- A malformed finding record in the baseline no longer kills the run. A
  record missing `purl`, `category`, or `id` — or holding a non-string one,
  or not an object at all — raised straight out of the baseline read, before
  any output was written, so a single hand-edit left the monitor dead and
  silent. Such records are now dropped with a note on stderr, and a baseline
  that is not a JSON object at all is treated as absent. Dropping errs the
  safe way: the finding looks new on the next run and alerts again.
- An unusable CVSS base score no longer crashes rendering. The score went
  from the report to `f"{score:.1f}"` unchecked, so a non-numeric one raised
  `TypeError` while building the issue body. Such scores now read as unknown
  and render as "—", the same as a finding the report scored not at all —
  deliberately not 0.0, which would print a reassuring score beside a real
  CVE. Numeric strings are still accepted; `true`, `Infinity`, and `NaN` are
  not. Scores are excluded from finding identity, so nothing about which
  findings alert changes.
- The baseline commit can no longer be lost silently. `git pull --rebase ||
  true` swallowed a conflict, which left HEAD detached at the upstream
  commit — the following push then sent origin its own tip back and exited
  0, so the step went green while the baseline never landed and the next run
  re-alerted everything it had already reported. The step now pushes first
  (so an uncontended run never rewrites history), rebases and retries only
  on rejection, and fails loudly if the rebase cannot be completed. Affected
  only the in-tree mode (`baseline-branch: ""`), where the baseline lives on
  the scanned branch; a dedicated baseline branch builds its commit in a
  separate worktree and never rebased.
- Angle brackets in a package purl are substituted before it is rendered
  into a code-span table cell. GitHub escapes a tag inside a code span, so
  nothing rendered as HTML — but the clipping guard counts `<details>` tags
  on the raw text, and a purl carrying the closing tag made an open block
  look closed. An oversized body could then be truncated with its "body
  truncated" notice hidden inside the collapsed block.
- The delta comment names the manifest again, and malware comments carry the
  incident guidance. Both moved to the issue body when the delta was split
  into a comment, but the body is edited silently — the comment is what
  notifies — so the alert email named neither what was scanned nor why the
  finding was urgent.
- A malformed entry in a baseline's `stats.*.alerted` list no longer takes
  down the run. Entries are validated against the finding-key shape (three
  strings) instead of only being checked for being lists, so a hand-edited or
  merge-mangled entry is dropped like every other corrupt stats value. It
  previously raised while folding in the run's delta — before any output was
  written, so the notify and baseline-commit steps were skipped and a live
  malware finding was silently dropped on every run until someone deleted the
  baseline.
- An `Infinity` counter in a baseline's `stats` block heals to 0 like every
  other corrupt value. `json.load` accepts the non-standard literal, and
  `int()` on the resulting float raises `OverflowError` rather than the
  `ValueError` the healing caught — so it took the run down with it.
- Finding titles, ids, categories and package URLs are escaped before going
  into a Markdown table cell. They come from the vendor's finding database,
  so a `|` added a phantom column, a newline ended the row and the table, and
  a literal `</details>` closed the collapsible block early — leaving the
  rest of the delta rendered expanded.
- The full delta is actually uploaded now. Truncation notices and the README
  both pointed readers at "the `delta.json` workflow artifact", but no step
  ever uploaded one — and runner temp is discarded at job end, so for a
  capped delta the hidden findings were unrecoverable. A new step uploads it
  on every run, before the notification, under the name given by the new
  `delta-artifact` output.
- A run that only *resolves* findings now refreshes the issue body. Its
  `resolved` and `outstanding` counters move in the committed baseline, but
  the body was re-rendered only for new-or-worsened findings, so an open
  issue kept asserting the pre-resolution numbers indefinitely — a fixed
  malware incident still reading "Currently outstanding: 1". No comment is
  posted for such a run (a body edit does not notify), no issue is opened if
  none is open, and a bucket whose outstanding count reaches zero now says so
  on the body.
- "Currently outstanding" is now on the same basis as the three counters
  beside it. It counted every finding present in the bucket, including the
  first-run backlog the others deliberately exclude, so the body could read
  "Alerted so far: 1 new · Resolved since then: 0 · Currently outstanding: 3"
  and leave a reader concluding that two findings appeared without ever
  alerting. It now counts what the bucket has alerted on and not seen
  resolved; the backlog is reported on its own line as "Pre-existing
  backlog", so it stays visible instead of being folded into another number.
- Delta tables state their own unit. A headline counts findings per affected
  package while a row is one distinct finding, which on a real scan differ by
  an order of magnitude — a comment headed "1218 new" showing 58 rows, both
  called "findings". Tables that collapsed anything now say how many findings
  grouped into how many distinct ones, and the truncation note counts
  "distinct findings".
- Whether to rewrite the baseline is decided by comparing everything durable
  in it, rather than by naming the fields that count. Naming them worked only
  as long as nobody added another: any new counter would have re-committed
  and pushed the whole baseline after every scheduled scan, undoing the
  no-churn guarantee from 1.1.0, and nothing would have caught it. A rewrite
  on a run where no finding changed now also logs a warning naming the cause.
- The body-size guard can no longer return a body *larger* than the limit.
  Its reserve for reclosing open `<details>` blocks was sized from the whole
  body's tag count, which for a body dense with tags exceeded the limit and
  made the slice index negative, trimming from the tail instead of
  truncating. It now searches for the largest prefix that fits, so it neither
  overshoots the limit nor discards more of the body than it has to.

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

[2.0.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kburich/rl-protect-monitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kburich/rl-protect-monitor/releases/tag/v1.0.0