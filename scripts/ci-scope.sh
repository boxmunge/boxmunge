#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CI's scope step: whether a job whose check is required does its work.
# Runs scripts/ci-touches.sh with the given arguments and records the answer
# for the job's later steps (`if: steps.scope.outputs.relevant == 'true'`):
# exit 0 (touched, or not comparable) is relevant=true, exit 1 is
# relevant=false. Anything else (bad usage, git failing) fails the step, so
# a broken comparison never looks like a skip.
#
# Usage: scripts/ci-scope.sh [--outside] <base-sha> <path>...
set -euo pipefail

: "${GITHUB_OUTPUT:?ci-scope.sh runs as a GitHub Actions step}"
rc=0
bash "$(dirname "$0")/ci-touches.sh" "$@" || rc=$?
case "${rc}" in
    0) echo "relevant=true" >> "${GITHUB_OUTPUT}" ;;
    1) echo "Skipping this job's checks: the change touches nothing they test."
       echo "relevant=false" >> "${GITHUB_OUTPUT}" ;;
    *) echo "scripts/ci-touches.sh failed (exit ${rc})" >&2; exit "${rc}" ;;
esac
