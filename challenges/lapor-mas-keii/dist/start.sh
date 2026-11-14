#!/bin/bash
set -e

service ssh start

make -C /app/src clean >/dev/null 2>&1 || true
make -C /app/src

chmod 644 /flag.txt || true

cd /app/src
exec setpriv --reuid=svc --regid=svc --clear-groups /app/src/lmk 9000
