#!/bin/sh

# Defaults:
PORT=8080

if [ -z "$1" ]; then
    echo "Usage: $0 query"
    exit 1
fi

URL="http://$(hostname):$PORT/q"

set -e
ID=$(curl --silent --data-urlencode "q=$1" "$URL")
set +e

while true; do
    sleep 1
    if DATA=$(curl --silent --fail "$URL/$ID"); then
        echo "$DATA"
        exit
    fi
done
