#!/usr/bin/env bash
# Stage: lint the pipeline's own shell.
#
# The stage scripts are the part of this repository that decides whether a
# release ships, so they get the same treatment as the application code. An
# unquoted variable in a gate is not a style issue: it is a gate that stops
# gating the moment a path contains a space.
#
# It goes through `tool` rather than calling docker directly, so that the pinned
# linter version lives in exactly one place and the Makefile, CI and a laptop
# all run the same check.

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="lint"

log "${STAGE}: shellcheck ${VER_SHELLCHECK} over pipeline/*.sh"

# --external-sources plus --source-path=SCRIPTDIR let shellcheck follow the
# `. lib.sh` in every stage, so it checks each script against the functions and
# variables it actually inherits instead of guessing.
tool shellcheck \
    --shell=bash \
    --external-sources \
    --source-path=SCRIPTDIR \
    pipeline/*.sh

ok "${STAGE}: shell is clean"
