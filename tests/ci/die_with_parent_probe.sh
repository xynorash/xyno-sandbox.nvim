#!/bin/sh
# Diagnostic (CI): does `bwrap --die-with-parent` take its sandbox with it when the launcher is killed -9,
# for growing flag sets, WITHOUT any xyno-sandbox code? One line per case: which survivors after 10 s.
bwrap --version; uname -r
n=0
run_case() {
  name=$1; shift
  for i in 1 2 3; do
    n=$((n + 1)); secs=$((300 + n))
    sh -c 'bwrap "$@" & wait' probe "$@" --ro-bind / / --proc /proc --dev /dev sleep "$secs" &
    sh_pid=$!
    sleep 1.5
    kill -9 "$sh_pid" 2>/dev/null
    sleep 8
    left=$(pgrep -af "sleep $secs" | grep -v pgrep | head -3 | tr '\n' ';')
    states=$(for p in $(pgrep -f "bwrap .*sleep $secs"); do echo "$p:$(grep -E '^(State|NSpid)' /proc/$p/status | tr -s '\t\n ' ' ')"; done)
    if [ -n "$left" ]; then echo "case $name try $i: SURVIVORS [$left] bwrap=[$states]"; else echo "case $name try $i: all gone"; fi
    pkill -9 -f "sleep $secs" 2>/dev/null
    pkill -9 -f "bwrap .*sleep $secs" 2>/dev/null
  done
}
run_case A-pid --die-with-parent --unshare-pid
run_case B-user --die-with-parent --unshare-pid --unshare-user
run_case C-disable-userns --die-with-parent --unshare-pid --unshare-user --disable-userns
run_case D-capdrop --die-with-parent --unshare-pid --unshare-user --disable-userns --cap-drop ALL
run_case E-net-session --die-with-parent --new-session --unshare-user --disable-userns --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup-try --cap-drop ALL --unshare-net
run_case F-net-only --die-with-parent --unshare-pid --unshare-net
exit 0
