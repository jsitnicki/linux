#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

./in_netns.sh sh <(cat <<-EOF
        sysctl -q -w net.mptcp.enabled=1
        sysctl -q -w net.ipv4.ip_local_port_range="40000 49999"
        ip -6 addr add dev lo 2001:db8::1/32 nodad
        ip -6 addr add dev lo 2001:db8::2/32 nodad
        exec ./ip_local_port_range
EOF
)
