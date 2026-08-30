#!/usr/bin/env bash
#
# File: postgres/generate-tls.sh
#
# ---------------------------------------------------------------------------
# A SERVER KEY PAIR FOR POSTGRES, GENERATED AT CONTAINER START.
#
# This is the same decision `common/helpers.js` and `tls/tls_server.js` make
# about every other key in this stack, applied to the one process that did not
# have one: **nothing about a mock is worth persisting, and a certificate
# committed to a repository is a private key committed to a repository.** So
# the pair is made on first start, lives in the data volume beside the
# database, and is remade if it is ever removed.
#
# IT IS NOT REGENERATED ON EVERY START, and that is the one place this differs
# from the STS's own keys. Those are regenerated per start deliberately — the
# `kid` is derived from the key material, and a client is expected to refetch.
# A database client is not: `sslmode=verify-*` pins this certificate, and a
# stack that handed its client a different one every morning would be teaching
# people to turn verification off, which is the habit this whole change exists
# to break. Delete the files (or the volume) to get a new pair.
#
# WHY openssl AND NOT THE STS'S OWN GENERATOR. The STS mints certificates with
# forge and could mint this one — but it would have to be RUNNING to do it, and
# this key is needed by the database the STS refuses to start without. A
# circular dependency at boot is a worse thing to own than four lines of
# openssl in the image that already ships it.
# ---------------------------------------------------------------------------
set -euo pipefail

TLS_DIR="${POSTGRES_TLS_DIR:-/var/lib/postgresql/tls}"
CRT="${TLS_DIR}/server.crt"
KEY="${TLS_DIR}/server.key"
# The name the STS dials, which is the compose service name on the private
# bridge. It is a SAN and not only a CN because RFC 6125 has said the CN is
# ignored since 2011, and `sslmode=verify-full` is the mode this exists to make
# possible.
CN="${POSTGRES_TLS_CN:-postgres}"

mkdir -p "${TLS_DIR}"

if [ -s "${CRT}" ] && [ -s "${KEY}" ]; then
  echo "postgres-tls: a key pair is already in ${TLS_DIR}; keeping it."
else
  echo "postgres-tls: generating a server key pair in ${TLS_DIR} for CN=${CN}."
  openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 825 \
    -subj "/CN=${CN}/O=mock-sts" \
    -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "${KEY}" -out "${CRT}" 2>/dev/null
fi

# POSTGRES REFUSES TO START IF THE KEY IS GROUP- OR WORLD-READABLE, and the
# message it gives ("private key file has group or world access") names the
# permission and not the cause. Set both every time rather than only after a
# generation: a volume restored from a backup, or copied between machines,
# commonly arrives with the mode widened.
chmod 600 "${KEY}"
chmod 644 "${CRT}"
chown postgres:postgres "${KEY}" "${CRT}" 2>/dev/null || true

echo "postgres-tls: ready."
