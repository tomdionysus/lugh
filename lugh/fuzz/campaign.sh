#!/bin/bash
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#
# A fuzzing campaign (P12): every target in a build made with LUGH_BUILD_FUZZING, each for
# SECONDS_EACH (default 600), JOBS (default 2) at a time, from its seeds in lugh/fuzz/corpus/<name>/
# when it has some. Its working corpus and any crash go under <build>/fuzz-campaign/<name>/.
# One line per target at the end: what ran, for how long, and whether it found anything.
#
#   lugh/fuzz/campaign.sh <build directory> [target ...]
#
# Needs a kernel ASan can start on: on the build nodes, the 16K-page one (node-b, 2026-11-16).

set -eu

build=$(cd "$1" && pwd)
shift
source_dir=$(cd "$(dirname "$0")" && pwd)
seconds=${SECONDS_EACH:-600}
jobs=${JOBS:-2}
out="$build/fuzz-campaign"
mkdir -p "$out"

if [ "$#" -eq 0 ]; then
    set -- $(cd "$build" && ls fuzz_* 2>/dev/null)
fi

run_one() {
    name=$1
    short=${name#fuzz_}
    work="$out/$name"
    mkdir -p "$work/corpus" "$work/crashes"
    if [ -d "$source_dir/corpus/$short" ]; then
        cp -n "$source_dir/corpus/$short"/* "$work/corpus/" 2>/dev/null || true
    fi
    set +e
    "$build/$name" "$work/corpus" -max_total_time="$seconds" -artifact_prefix="$work/crashes/" -print_final_stats=1 > "$work/log" 2>&1
    status=$?
    set -e
    found=$(ls "$work/crashes" | wc -l)
    runs=$(grep -m1 "stat::number_of_executed_units" "$work/log" | awk '{print $2}')
    printf '%s: exit %s, %s runs in %ss, %s found\n' "$name" "$status" "${runs:-?}" "$seconds" "$found" >> "$out/summary"
}

: > "$out/summary"
running=0
for name in "$@"; do
    run_one "$name" &
    running=$((running + 1))
    if [ "$running" -ge "$jobs" ]; then
        wait -n
        running=$((running - 1))
    fi
done
wait
sort "$out/summary"
