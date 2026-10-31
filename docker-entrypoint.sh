#!/bin/sh
# Bind mounts keep the host's ownership (often root), so the data dir may not be writable for the app user.
# Started as root, this hands it over and then drops privileges; started with --user, it changes nothing.
set -e

VAR_DIR=/app/var

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$VAR_DIR"
    # Only what isn't the app user's already, so restarts with many uploads stay fast.
    find "$VAR_DIR" \! -user openid -exec chown openid:openid {} +
    exec setpriv --reuid=openid --regid=openid --init-groups "$@"
fi

exec "$@"
