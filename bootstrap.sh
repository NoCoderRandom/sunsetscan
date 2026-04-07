#!/usr/bin/env bash
#
# NetWatch one-line bootstrap installer.
#
# Clones the repository (or pulls latest changes if already present), then
# runs install.sh. Designed to be safe to invoke via:
#
#   curl -fsSL https://raw.githubusercontent.com/NoCoderRandom/netwatch/main/bootstrap.sh | bash
#
# Environment variables:
#   INSTALL_DIR  Where to clone the repo            (default: $HOME/netwatch)
#   BRANCH       Branch to checkout                 (default: main)
#   REPO         Repository URL                     (default: NoCoderRandom/netwatch)
#
# Anything passed after `bash` is forwarded to install.sh — for example:
#   curl ... | bash -s -- --symlink

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/netwatch}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://github.com/NoCoderRandom/netwatch.git}"

echo "==> NetWatch bootstrap"
echo "    Repo:    $REPO"
echo "    Branch:  $BRANCH"
echo "    Target:  $INSTALL_DIR"
echo

if ! command -v git >/dev/null 2>&1; then
    cat >&2 <<'EOF'
git is not installed. Install it first:
  Debian / Ubuntu / Pi OS:  sudo apt install git
  Fedora / RHEL:            sudo dnf install git
  Arch / Manjaro:           sudo pacman -S git
  openSUSE:                 sudo zypper install git
  macOS:                    brew install git
EOF
    exit 1
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "==> $INSTALL_DIR already exists — pulling latest changes"
    cd "$INSTALL_DIR"
    git fetch --quiet origin "$BRANCH"
    git checkout --quiet "$BRANCH"
    git pull --ff-only --quiet origin "$BRANCH"
else
    if [ -e "$INSTALL_DIR" ]; then
        echo "Refusing to clone into $INSTALL_DIR — path exists but is not a git checkout." >&2
        echo "Move it aside or set INSTALL_DIR=/some/other/path and re-run." >&2
        exit 1
    fi
    echo "==> Cloning into $INSTALL_DIR"
    git clone --quiet --branch "$BRANCH" --depth 1 "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo
echo "==> Running installer"
exec bash install.sh "$@"
