#!/usr/bin/env sh

set -eux

# Try to create openwec db if not already existing
# This also applies migrations
./openwec db init

# Load subscriptions configuration files if provided
if [ -d /etc/openwec.d/ ]; then
    ./openwec subscriptions load /etc/openwec.d
fi

# Start openwecd
exec ./openwecd
