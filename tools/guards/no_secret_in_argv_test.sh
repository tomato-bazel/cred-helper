#!/usr/bin/env bash
# Guard: this repo's build config must never put a secret on a command line.
#
# ⛔ The trap this exists for: `--remote_header=x-buildbuddy-api-key=$KEY` reads
# like "auth via a header" but it is an ARGV entry — readable by `ps aux` from
# any other process on the runner for the whole build. GitHub Actions masks
# secrets in LOG TEXT, so the leak is invisible in the log that would otherwise
# catch it. A live BuildBuddy key leaked from this estate on 2026-08-04; this
# repo was one of the places it was still wired in.
#
# ⚠ The check is deliberately about the SHAPE (a `--…=$SECRET` argv flag), not
# about BuildBuddy. Pointing a future remote cache at roma the same way would be
# the same bug, so roma is not exempt. Authenticate a remote cache with the
# credential helper this repo BUILDS.
set -euo pipefail

rc=0
fail() { echo "FAIL: $*" >&2; rc=1; }

for f in "$@"; do
  [ -f "$f" ] || { fail "guarded file missing: $f"; continue; }

  # A `--flag=…$VAR…` where VAR names a secret. Comments are stripped first so
  # this file's own prose — and the .bazelrc note explaining the removal — do
  # not trip it.
  if sed 's/#.*//' "$f" \
     | grep -nE -- '--[A-Za-z_]+=[^[:space:]]*\$\{?[A-Za-z_]*(SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL)' ; then
    fail "$f passes a secret-shaped variable inside a command-line flag (visible in \`ps aux\`)"
  fi

  # GitHub's own secret interpolation reaching a command line directly.
  if sed 's/#.*//' "$f" \
     | grep -nE -- '--[A-Za-z_]+=[^[:space:]]*\$\{\{[[:space:]]*secrets\.' ; then
    fail "$f interpolates \${{ secrets.* }} into a command-line flag"
  fi
done

[ "$rc" -eq 0 ] && echo "PASS: no secret-shaped value reaches an argv flag in $#: $*"
exit "$rc"
