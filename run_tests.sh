#!/usr/bin/env bash
# Run the test suite in Docker, across the same Python versions as CI.
#
#   ./run_tests.sh                      # CI's matrix: 3.9 and 3.12
#   ./run_tests.sh 3.12                 # one version
#   ./run_tests.sh 3.12 -- -k gh_issue  # extra arguments for pytest
set -euo pipefail

cd "$(dirname "$0")"

versions=()
while [[ $# -gt 0 && "$1" != "--" ]]; do
  versions+=("$1")
  shift
done
if [[ "${1:-}" == "--" ]]; then
  shift
fi
pytest_args=("$@")
if [[ ${#versions[@]} -eq 0 ]]; then
  versions=(3.9 3.12)
fi

status=0
for version in "${versions[@]}"; do
  printf '\n\033[1m── Python %s ──\033[0m\n' "$version"
  # The repo is mounted read-only: the container runs as root, so a writable
  # mount leaves root-owned __pycache__/.pytest_cache behind in the worktree.
  # The named volume keeps pip's download of pytest out of the repo.
  # --network host: container DNS does not resolve on this setup, so pip
  # cannot reach PyPI on the default bridge network.
  # ${arr[@]+...}: bash < 4.4 (macOS ships 3.2) treats expanding an empty
  # array as unbound under `set -u`.
  if ! docker run --rm --network host \
    -v "$PWD:/src:ro" -w /src \
    -v dependency-monitor-pip:/root/.cache/pip \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "python:${version}-slim" \
    bash -c 'python -m pip install --quiet pytest &&
             exec python -m pytest tests/ -v -p no:cacheprovider "$@"' \
      _ ${pytest_args[@]+"${pytest_args[@]}"}; then
    status=1
  fi
done

exit "$status"
