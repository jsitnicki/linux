#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        echo "FAIL"
        exit 1
fi

# Run the script in a dedicated network namespace.
if [[ -z $(ip netns identify $$) ]]; then
        ../net/in_netns.sh "$0" "$@"
        exit $?
fi

readonly IP6_1="fd00::1"
readonly IP6_2="fd00::2"

setup()
{
        ip -6 addr add ${IP6_1}/128 dev lo
        ip -6 addr add ${IP6_2}/128 dev lo
}

cleanup()
{
        ip -6 addr del ${IP6_1}/128 dev lo
        ip -6 addr del ${IP6_2}/128 dev lo
}

trap cleanup EXIT
setup

./test_inet_lookup
exit $?
