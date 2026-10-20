#!/usr/bin/env bash
# The local stack's process ownership check, without building or starting a
# stack: `down` ends a process it launched, whatever the size of its
# environment, and leaves alone one that differs only in its launch marker,
# saying why without logging the environment.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux ]] || { echo 'Local stack ownership: skipped (needs /proc)'; exit 0; }
stack=scripts/local-stack.sh
LOCAL_STACK_DIR=$(mktemp -d)
export LOCAL_STACK_DIR
pids=()
# Process $1's state and start time, or nothing once it has gone.
stat_of() {
  local line
  local -a f
  { line=$(<"/proc/$1/stat"); } 2>/dev/null || return 0
  read -ra f <<< "${line##*) }"
  printf '%s %s' "${f[0]}" "${f[19]}"
}
# Still the process started as "$1 $2" (PID, start time), not ended.
running() {
  local state born
  read -r state born <<< "$(stat_of "$1")"
  [[ -n $state && $state != Z && $born == "$2" ]]
}
cleanup() {
  # Only this script's own children, by their start time.
  for entry in "${pids[@]}"; do
    running $entry && kill -KILL "${entry%% *}" 2>/dev/null || :
  done
  rm -rf "$LOCAL_STACK_DIR"
}
trap cleanup EXIT
marker() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sleeper=$(command -v sleep)
id=$(marker)
printf '%s\n' "$id" > "$LOCAL_STACK_DIR/launch-id"
# A quarter MiB of harmless filler after the marker: four times a pipe's buffer.
value=$(head -c 1000 /dev/zero | tr '\0' x)
filler=()
for i in {0..255}; do filler+=("FILLER_$i=$value"); done
start() {
  env -i "LOCAL_STACK_LAUNCH_ID=$1" "${filler[@]}" "$sleeper" 60 &
  local pid=$! state born
  read -r state born <<< "$(stat_of "$pid")"
  pids+=("$pid $born")
  # Until env has exec'd the sleeper, the environment is still this shell's.
  for _ in {1..100}; do
    [[ $(tr '\0' ' ' < "/proc/$pid/cmdline") == "$sleeper 60 " ]] && return
    sleep 0.05
  done
  echo 'sleeper did not start' >&2; exit 1
}
start "$id"
start "$(marker)"
owned=${pids[0]} other=${pids[1]}
printf '%s sleep\n%s sleep\n' "$owned" "$other" > "$LOCAL_STACK_DIR/pids"
bash "$stack" down
! running $owned || { echo 'down left its own process running' >&2; cat "$LOCAL_STACK_DIR/stop.log" >&2; exit 1; }
running $other || { echo 'down ended a process it did not launch' >&2; exit 1; }
grep -q "not verified, left alone: $other sleep: launch marker: expected LOCAL_STACK_LAUNCH_ID=${id:0:12}, present LOCAL_STACK_LAUNCH_ID=" \
  "$LOCAL_STACK_DIR/stop.log" || { echo 'refusal not explained' >&2; cat "$LOCAL_STACK_DIR/stop.log" >&2; exit 1; }
! grep -q FILLER_ "$LOCAL_STACK_DIR/stop.log" || { echo 'environment logged' >&2; exit 1; }
printf 'Local stack ownership: own process ended, other left alone, refusal explained\n'
