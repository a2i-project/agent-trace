#!/usr/bin/env bash
# Runs as the operator in a run's guest (vm/run.sh campaign).
#   campaign.sh start [CAMPAIGN FLAGS]  start scripts/capture-campaign.sh
#       --run-as agenttrace on the results disk's plan.txt and out/, detached
#       from the SSH session; NAME=value lines on stdin are exported to it
#       (the profiles' secret_env), and written nowhere
#   campaign.sh follow                  print its log until it ends; exit 0 when
#       it has ended (its status is in campaign.exit)
set -euo pipefail
r=/var/lib/agent-trace/results
case ${1:-} in
  start)
    shift
    rm -f "$r/campaign.exit"
    while IFS='=' read -r n v; do [ -z "$n" ] || export "$n=$v"; done
    printf '\n=== %s campaign start (%s)\n' "$(date --iso-8601=seconds)" "$*" >>"$r/campaign.log"
    cd ~/agent-trace
    setsid bash -c 'scripts/capture-campaign.sh --run-as agenttrace "$@" '"$r"'/plan.txt '"$r"'/out >>'"$r"'/campaign.log 2>&1 </dev/null; echo $? >'"$r"'/campaign.exit' campaign "$@" >/dev/null 2>&1 </dev/null &
    echo $! >"$r/campaign.pid"
    ;;
  follow)
    pid=$(cat "$r/campaign.pid")
    tail -n +1 -F --pid="$pid" "$r/campaign.log" 2>/dev/null || true
    [ -f "$r/campaign.exit" ]
    ;;
  *) echo "usage: campaign.sh start|follow" >&2; exit 2 ;;
esac
