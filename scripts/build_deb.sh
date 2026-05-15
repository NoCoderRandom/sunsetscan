#!/usr/bin/env bash
#
# Build a Debian/Ubuntu package for SunsetScan.
#
# The package installs the tracked repository contents under /opt/sunsetscan,
# adds /usr/bin/sunsetscan, and runs the existing venv installer from postinst.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"

if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
    if ! git -C "$ROOT_DIR" diff --quiet || ! git -C "$ROOT_DIR" diff --cached --quiet; then
        echo "Working tree has uncommitted tracked changes; commit them before building a release package." >&2
        echo "Set ALLOW_DIRTY=1 only for local test packages." >&2
        exit 1
    fi
fi

VERSION="${VERSION:-$(awk -F'"' '/version: str = / {print $2; exit}' "$ROOT_DIR/config/settings.py")}"
if [ -z "$VERSION" ]; then
    echo "Could not determine SunsetScan version from config/settings.py" >&2
    exit 1
fi
PACKAGE_REVISION="${PACKAGE_REVISION:-1}"
PACKAGE_VERSION="${PACKAGE_VERSION:-$VERSION-$PACKAGE_REVISION}"
PACKAGE_NAME="sunsetscan"
DEB_NAME="${PACKAGE_NAME}_${PACKAGE_VERSION}_all.deb"

BUILD_ROOT="$(mktemp -d)"
trap 'rm -rf "$BUILD_ROOT"' EXIT

PKG_ROOT="$BUILD_ROOT/${PACKAGE_NAME}_${PACKAGE_VERSION}_all"
APP_DIR="$PKG_ROOT/opt/sunsetscan"

mkdir -p "$APP_DIR" "$PKG_ROOT/DEBIAN" "$PKG_ROOT/usr/bin" "$OUT_DIR"

git -C "$ROOT_DIR" archive --format=tar HEAD | tar -x -C "$APP_DIR"

chmod 0755 "$APP_DIR/install.sh" "$APP_DIR/bootstrap.sh" "$APP_DIR/sunsetscan" "$APP_DIR/sunsetscan.py"
ln -s /opt/sunsetscan/sunsetscan "$PKG_ROOT/usr/bin/sunsetscan"

cat > "$PKG_ROOT/DEBIAN/control" <<CONTROL
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: all
Maintainer: SunsetScan Contributors <NoCoderRandom@users.noreply.github.com>
Homepage: https://github.com/NoCoderRandom/sunsetscan
Depends: python3 (>= 3.9), python3-venv, python3-pip, python3-dev, nmap, git, libpcap-dev, build-essential, ca-certificates
Recommends: masscan, avahi-utils
Description: local network EOL scanner and security assessment tool
 SunsetScan audits local networks, fingerprints devices and services, checks
 software and hardware lifecycle data, and creates HTML security reports.
CONTROL

cat > "$PKG_ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

case "$1" in
    configure)
        if [ -x /opt/sunsetscan/install.sh ]; then
            /opt/sunsetscan/install.sh --no-system
        fi
        ;;
esac

exit 0
POSTINST

cat > "$PKG_ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

case "$1" in
    purge)
        rm -rf /opt/sunsetscan/venv /opt/sunsetscan/.venv
        ;;
esac

exit 0
POSTRM

chmod 0755 "$PKG_ROOT/DEBIAN/postinst" "$PKG_ROOT/DEBIAN/postrm"

DEB_PATH="$OUT_DIR/$DEB_NAME"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_PATH"
(cd "$OUT_DIR" && sha256sum "$DEB_NAME" > "$DEB_NAME.sha256")

printf '%s\n' "$DEB_PATH"
