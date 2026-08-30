"""Derive a monitor's identity from the manifest it scans.

One repo can run several monitors — a monorepo scanning `web/package-lock.json`
and `api/requirements.txt` needs one job per manifest, since manifest
auto-detection stops at the first match. Each of those monitors owns durable
state: a baseline and a pair of rolling issues. Without an identity they share
it, and sharing is silently destructive — two monitors overwriting one baseline
alternate their findings, so every run reports the other's as resolved and its
own as new, forever.

The branch is deliberately *not* part of the identity. GitHub fires `schedule:`
on the default branch only, so no other branch can be monitored periodically at
all; the action rejects them instead of half-supporting them.

The id is a slug, so it can be dropped verbatim into both a branch name and a
label name:

    package-lock.json          -> package-lock.json
    web/package-lock.json      -> web-package-lock.json
    poetry.lock                -> poetry-lock  (git rejects a ref ending .lock)
    a/very/deeply/nested/…     -> truncated with a hash suffix (see MAX_ID_LEN)

Usage:
    python -m monitor.identity \
        --manifest package-lock.json \
        --baseline-branch auto

Writes `id`, `baseline-branch`, `marker-standard` and `marker-critical` to
$GITHUB_OUTPUT (or stdout when that is unset).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from typing import List, Optional

#: Prefix of the orphan branch each monitor stores its baseline on.
BASELINE_BRANCH_PREFIX = "dependency-baseline"

#: Marker-label prefixes. The marker identifies a bucket's rolling issue; the
#: two are disjoint by construction, which is what lets the issue lookup be a
#: plain "newest issue carrying this label" with no exclusion rules.
MARKER_STANDARD_PREFIX = "dependency-monitor"
MARKER_CRITICAL_PREFIX = "dependency-malware"

#: A GitHub label name is capped at 50 characters and the longest prefix above
#: is 19 including its slash, so an id longer than this cannot be expressed as
#: a label. Nested manifest paths pass it easily, so truncation is the normal
#: path rather than an exotic one.
MAX_ID_LEN = 50 - len(MARKER_STANDARD_PREFIX + "/")

#: How a too-long id is shortened: a readable head plus a digest of the *whole*
#: slug, so two manifests sharing a long prefix cannot collide after truncation.
_HEAD_LEN = 24
_HASH_LEN = 6

#: The sentinel meaning "derive it"; see the module docstring for the tri-state
#: `--baseline-branch` takes.
AUTO = "auto"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_RUNS = re.compile(r"-{2,}")

#: `..` is forbidden anywhere in a ref name, and `.` survives `_UNSAFE`, so a
#: path like `pkgs/../lock.json` would otherwise slug straight through into an
#: unpushable branch.
_DOT_RUNS = re.compile(r"\.{2,}")

#: A ref component may not end in `.lock` — git reserves that suffix for its
#: own lockfiles, and rejects the refspec outright. Lowercase only, matching
#: git's own check. This is the common case rather than an exotic one:
#: `poetry.lock`, `uv.lock`, `yarn.lock` and `Gemfile.lock` are four of the
#: manifests auto-detection looks for, and each would name a branch that
#: cannot be created.
_TRAILING_LOCK = re.compile(r"\.lock$")


def slugify(value: str) -> str:
    """Reduce `value` to characters safe in both a branch name and a label.

    The character whitelist alone is not enough: the id is dropped verbatim
    into a branch name, so the result also has to satisfy
    `git check-ref-format` — no `..` sequence, and no trailing `.lock`. Both
    are reachable from ordinary manifest paths, and both fail late, at the
    push, after the delta has already been posted.

    Leading and trailing `-` and `.` are stripped for the same reason: a
    branch component may not start or end with a dot, and a label that does
    reads like a typo.
    """
    slug = _UNSAFE.sub("-", value or "")
    slug = _RUNS.sub("-", slug)
    slug = _DOT_RUNS.sub(".", slug)
    slug = slug.strip("-.")
    # After the strip, so a bare `.lock` reduces to `lock` rather than `-lock`.
    return _TRAILING_LOCK.sub("-lock", slug)


def _shorten(slug: str) -> str:
    if len(slug) <= MAX_ID_LEN:
        return slug
    digest = hashlib.sha256(slug.encode("utf-8")).hexdigest()[:_HASH_LEN]
    # rstrip so a head ending at a separator does not yield `foo--a1b2c3`.
    return f"{slug[:_HEAD_LEN].rstrip('-.')}-{digest}"


def monitor_id(manifest: str, override: str = AUTO) -> str:
    """Identity for the monitor scanning `manifest`.

    `override` is the `monitor-id` input: `auto` derives from the manifest, any
    other value names the monitor explicitly — which is how two monitors on the
    same manifest (differing scan profiles, say) stay apart, and how two that
    should share a thread are made to.
    """
    source = manifest if override in ("", AUTO) else override
    slug = _shorten(slugify(source))
    if not slug:
        raise ValueError(
            f"cannot derive a monitor id from {source!r} — it has no "
            "characters usable in a branch or label name; set the monitor-id "
            "input explicitly")
    return slug


def resolve_baseline_branch(value: str, identity: str) -> str:
    """Tri-state `baseline-branch`: derive, name explicitly, or opt out.

    `auto` derives a per-monitor orphan branch, an explicit value is used as
    given, and empty means the baseline is committed to the scanned branch
    itself. Empty has to stay meaningful, which is why the derived case needs a
    sentinel rather than reusing it.
    """
    if value == AUTO:
        return f"{BASELINE_BRANCH_PREFIX}/{identity}"
    return value


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="dependency-monitor-identity")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--monitor-id", default=AUTO,
                        help=f"'{AUTO}' derives the id from the manifest")
    parser.add_argument("--baseline-branch", default=AUTO,
                        help=f"'{AUTO}' derives the branch from the id; empty "
                             "keeps the baseline on the scanned branch")
    args = parser.parse_args(argv)

    try:
        identity = monitor_id(args.manifest, args.monitor_id)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    lines = [
        f"id={identity}",
        f"baseline-branch={resolve_baseline_branch(args.baseline_branch, identity)}",
        f"marker-standard={MARKER_STANDARD_PREFIX}/{identity}",
        f"marker-critical={MARKER_CRITICAL_PREFIX}/{identity}",
    ]
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(run())
