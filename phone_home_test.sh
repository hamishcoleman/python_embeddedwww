#!/bin/sh
#
# Generate some test data

PORT=8080
URL="http://localhost:$PORT/phone_home"

set -e
curl \
    "$URL" \
    --data-urlencode "pub_key_ed25519=ed25519_$RANDOM" \
    --data-urlencode "instance_id=i-87$RANDOM" \
    --data-urlencode "hostname=$(hostname -s)" \
    --data-urlencode "fqdn=$(hostname -f)"
