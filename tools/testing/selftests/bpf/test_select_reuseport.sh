#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -eu

DIR=$(dirname $0)

echo "Testing reuseport with REUSEPORT_SOCKARRAY..."
$DIR/test_select_reuseport -m reuseport_sockarray

echo "Testing reuseport with SOCKMAP (TCP only)..."
$DIR/test_select_reuseport -m sockmap -t

exit 0
