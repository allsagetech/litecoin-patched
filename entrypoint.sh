#!/bin/bash
set -e

if [ -n "${UID+x}" ] && [ "${UID}" != "0" ]; then
  usermod -u "$UID" litecoin
fi

if [ -n "${GID+x}" ] && [ "${GID}" != "0" ]; then
  groupmod -g "$GID" litecoin
fi

echo "$0: assuming uid:gid for litecoin:litecoin of $(id -u litecoin):$(id -g litecoin)"

if [ "$(echo "$1" | cut -c1)" = "-" ]; then
  echo "$0: assuming arguments for litecoind"

  set -- litecoind "$@"
fi

if [ "$(echo "$1" | cut -c1)" = "-" ] || [ "$1" = "litecoind" ]; then
  mkdir -p "$LITECOIN_DATA"
  chmod 700 "$LITECOIN_DATA"
  # Fix permissions for home dir.
  chown -R litecoin:litecoin "$(getent passwd litecoin | cut -d: -f6)"
  # Fix permissions for litecoin data dir.
  chown -R litecoin:litecoin "$LITECOIN_DATA"

  echo "$0: setting data directory to $LITECOIN_DATA"

  set -- "$@" -datadir="$LITECOIN_DATA"
fi

if [ "$1" = "litecoind" ] || [ "$1" = "litecoin-cli" ]; then
  echo
  exec gosu litecoin "$@"
fi

echo
exec "$@"
