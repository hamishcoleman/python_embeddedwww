#!/bin/sh

# Defaults:
PORT=8080

if [ -n "$1" ]; then
    QUERY="$1"
else
    QUERY="default"
fi

if [ "$QUERY" = "-h" ]; then
    echo "Usage: $0 query"
    exit 1
fi

URL="http://localhost:$PORT/q"

set -e
ID=$(curl --silent -H "Host: $(hostname)" --data-urlencode "q=$QUERY" "$URL")
set +e

while true; do
    sleep 1
    if DATA=$(curl --silent --fail "$URL/$ID"); then
        echo "$DATA"
        exit
    fi
done
