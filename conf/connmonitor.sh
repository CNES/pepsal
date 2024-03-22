#!/bin/sh


function on_upper_limit {
    local handle=$(nft -a list ruleset | grep "$1" | awk '{print $NF}')
    if test -n "$handle"; then
        nft delete rule inet mangle PREROUTING handle "$handle"
    fi
}


function on_lower_limit {
    echo "lower"
    systemctl restart nftables
}


if [ $# -lt 1 ]; then
    >&2 echo "Missing rule template argument"
    exit 1
fi

ARGUMENTS="\"$@\""

trap "on_upper_limit $ARGUMENTS" SIGUSR1
trap on_lower_limit SIGUSR2
sleep infinity & PID=$!
trap "kill $PID; echo Bye; exit" HUP INT QUIT ABRT ALRM STOP TERM

while true; do
    wait
done
