#!/bin/sh
# Builds a pinned PostgreSQL server from upstream source into a caller-chosen
# directory, for the SQL test harness only. Nothing is installed system-wide,
# no service is registered and no listener is opened: the harness starts its
# own throwaway cluster on a private Unix socket (see harness/cluster.js).
#
# Usage: tests/sql/runtime/build-postgres.sh <runtime-dir> [version]
#   version                  17.11 (default) or 15.19; each has a pinned SHA-256
#   <runtime-dir>/downloads  source tarball (verified before extraction)
#   <runtime-dir>/build      out-of-tree build
#   <runtime-dir>/install    binaries; pass <runtime-dir>/install/bin to the
#                            harness as DWARPAL_PG_BIN
#
# Prerequisites on PATH: a C toolchain, make, curl, tar, bzip2, and (because
# PostgreSQL 17 tarballs no longer ship generated parser files) bison >= 2.3,
# flex >= 2.5.35 and the m4 they call. See tests/sql/README.md.
#
# Versions are pinned to the current hosted Supabase major (17, default) and
# the previous one still in service (15). Each SHA-256 below is the value
# published next to the tarball on ftp.postgresql.org and in the signed PGDG
# apt source index for the same release.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
  echo "usage: $0 <runtime-dir> [17.11|15.19]" >&2
  exit 2
fi
PG_VERSION=${2:-17.11}
case "$PG_VERSION" in
  17.11) PG_SHA256=dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979 ;;
  15.19) PG_SHA256=e1a64a87a46b825b88c082e4518161a47aab53c45694964f8ba1df28f7859f89 ;;
  *) echo "unsupported version $PG_VERSION; pinned versions are 17.11 and 15.19" >&2; exit 2 ;;
esac
PG_URL="https://ftp.postgresql.org/pub/source/v${PG_VERSION}/postgresql-${PG_VERSION}.tar.bz2"
mkdir -p "$1"
ROOT=$(cd "$1" && pwd)
DOWNLOADS="$ROOT/downloads"
BUILD="$ROOT/build"
INSTALL="$ROOT/install"
TARBALL="$DOWNLOADS/postgresql-${PG_VERSION}.tar.bz2"
STAMP="$INSTALL/.dwarpal-build-${PG_VERSION}"

if [ -f "$STAMP" ] && [ -x "$INSTALL/bin/postgres" ]; then
  echo "PostgreSQL ${PG_VERSION} already built in $INSTALL"
  exit 0
fi

mkdir -p "$DOWNLOADS"
if [ ! -f "$TARBALL" ]; then
  curl --fail --silent --show-error --location --max-time 600 -o "$TARBALL.part" "$PG_URL"
  mv "$TARBALL.part" "$TARBALL"
fi
ACTUAL=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ "$ACTUAL" != "$PG_SHA256" ]; then
  echo "checksum mismatch for $TARBALL: expected $PG_SHA256, got $ACTUAL" >&2
  exit 1
fi

rm -rf "$BUILD" "$INSTALL"
mkdir -p "$BUILD"
tar -xjf "$TARBALL" -C "$BUILD"
SRC="$BUILD/postgresql-${PG_VERSION}"
cd "$SRC"
# Optional libraries are disabled so the build needs only a C toolchain; the
# migrations use core functions only (sha256, gen_random_uuid, jsonb).
./configure --prefix="$INSTALL" --without-readline --without-zlib --without-icu --without-openssl >"$BUILD/configure.log" 2>&1
JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
make -j"$JOBS" >"$BUILD/make.log" 2>&1
make install >"$BUILD/install.log" 2>&1
"$INSTALL/bin/postgres" --version
touch "$STAMP"
