#!/bin/sh
# Seed a LOCAL development database with a fixed set of test accounts.
#
#   ./seed-dev.sh                 # uses config.toml
#   ./seed-dev.sh other.toml      # another local config
#
# Builds sora-admin, migrates the database named in [database.write] (so it
# works straight after a reset, before the server's first start), then creates
# the accounts below. Safe to re-run: accounts and aliases that exist are
# skipped. Every account has the password "password". Refuses to run unless
# every [database.write] host is localhost or loopback, so it cannot seed a
# real deployment by accident.
#
# Accounts:
#   alice@example.com      primary; alias alice.alias@example.com (same password)
#   bob@example.com        same domain as alice (sharing / ACL grants)
#   carol@example.com      same domain
#   dave@example.com       same domain
#   eve@example.org        other domain (cross-domain ACL refusals)
#   legacy@example.com     SSHA512 hash (legacy-hash login and rehash path)
#   josé@example.com       non-ASCII local part (SMTPUTF8 / IMAP UTF8)
set -eu

cd "$(dirname "$0")"
CONFIG="${1:-config.toml}"
PASSWORD="password"

[ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; exit 1; }

# The [database.write] hosts line must name only localhost / loopback.
HOSTS=$(awk '
  /^\[/ { in_write = ($0 ~ /^\[database\.write\]/) }
  in_write && /^hosts[[:space:]]*=/ { sub(/#.*/, ""); sub(/^[^=]*=/, ""); sub(/[[:space:]]+$/, ""); print; exit }
' "$CONFIG")
if [ -z "$HOSTS" ] || printf '%s' "$HOSTS" | tr -d ' []"' | tr ',' '\n' |
  grep -qvE '^(localhost|127\.0\.0\.1|::1)(:[0-9]+)?$'; then
  echo "refusing to seed: [database.write] hosts =$HOSTS is not all localhost/loopback" >&2
  exit 1
fi

go build -o sora-admin ./cmd/sora-admin

admin() {
  ./sora-admin --config "$CONFIG" "$@"
}

admin migrate up >/dev/null 2>&1 || {
  echo "migrating the database failed; run: ./sora-admin --config $CONFIG migrate up" >&2
  exit 1
}

exists() {
  admin accounts show --email "$1" >/dev/null 2>&1
}

create() { # email [hash-type]
  if exists "$1"; then
    echo "skip    $1 (exists)"
    return
  fi
  admin accounts create --email "$1" --password "$PASSWORD" --hash "${2:-bcrypt}" >/dev/null 2>&1
  exists "$1" || { echo "FAILED  $1" >&2; exit 1; }
  echo "created $1"
}

alias_of() { # primary alias
  if exists "$2"; then
    echo "skip    $2 (exists)"
    return
  fi
  admin credentials add --primary "$1" --email "$2" --password "$PASSWORD" >/dev/null 2>&1
  exists "$2" || { echo "FAILED  $2" >&2; exit 1; }
  echo "created $2 (alias of $1)"
}

create alice@example.com
alias_of alice@example.com alice.alias@example.com
create bob@example.com
create carol@example.com
create dave@example.com
create eve@example.org
create legacy@example.com ssha512
create josé@example.com

echo "done - all passwords: $PASSWORD"
