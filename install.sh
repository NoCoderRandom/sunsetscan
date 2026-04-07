#!/usr/bin/env bash
#
# NetWatch installer
#
# Installs system tools (nmap, masscan, avahi-utils, git, python venv) via
# the OS package manager, then creates a project-local Python virtual env in ./venv
# and installs Python dependencies inside it. Avoids PEP 668 issues entirely
# by never touching system Python packages.
#
# Tier 1 (tested):       Debian, Ubuntu, Raspberry Pi OS, Linux Mint, Pop!_OS
# Tier 2 (best-effort):  Fedora, RHEL, CentOS, Arch, Manjaro, openSUSE, macOS
#
# Usage:
#   ./install.sh                  # default install
#   ./install.sh --force          # rebuild venv from scratch
#   ./install.sh --symlink        # also install /usr/local/bin/netwatch
#   ./install.sh --no-system      # skip apt/dnf/etc (system tools already present)
#   ./install.sh --help           # show this help
#
# Re-running this script is safe; existing components are detected and reused.

set -euo pipefail

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
FORCE=0
SYMLINK=0
SKIP_SYSTEM=0

for arg in "$@"; do
    case "$arg" in
        --force)      FORCE=1 ;;
        --symlink)    SYMLINK=1 ;;
        --no-system)  SKIP_SYSTEM=1 ;;
        --help|-h)
            sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Use --help for options." >&2
            exit 2
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Pretty output (TTY-aware so curl|bash logs stay clean)
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""
fi

step() { echo; echo "${BOLD}${BLUE}==>${NC} ${BOLD}$1${NC}"; }
ok()   { echo "  ${GREEN}✓${NC} $1"; }
warn() { echo "  ${YELLOW}!${NC} $1"; }
err()  { echo "  ${RED}✗${NC} $1" >&2; }
die()  { err "$1"; exit 1; }

# ----------------------------------------------------------------------------
# sudo wrapper — empty when already root, so this script works in containers
# and other minimal environments without sudo installed.
# ----------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        die "Not running as root and 'sudo' is not installed. Re-run as root or install sudo."
    fi
fi

# ----------------------------------------------------------------------------
# Locate ourselves (the repo root)
# ----------------------------------------------------------------------------
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

[ -f "netwatch.py" ]      || die "netwatch.py not found in $SCRIPT_DIR. Run install.sh from inside the cloned repository."
[ -f "requirements.txt" ] || die "requirements.txt not found in $SCRIPT_DIR."

echo
echo "${BOLD}${BLUE}╔════════════════════════════════════════════╗${NC}"
echo "${BOLD}${BLUE}║          NetWatch Installer                ║${NC}"
echo "${BOLD}${BLUE}╚════════════════════════════════════════════╝${NC}"

# ----------------------------------------------------------------------------
# Step 1: Detect OS and package manager
# ----------------------------------------------------------------------------
step "1/6  Detecting operating system"

OS_ID=""
OS_NAME="$(uname -s)"
PKG_MGR=""
TIER="Untested"

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_NAME="${PRETTY_NAME:-$OS_NAME}"
fi

if [ "$(uname -s)" = "Darwin" ]; then
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo)"
    if command -v brew &>/dev/null; then
        PKG_MGR="brew"
    else
        die "macOS detected but Homebrew is not installed. Install Homebrew from https://brew.sh and re-run."
    fi
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
elif command -v zypper &>/dev/null; then
    PKG_MGR="zypper"
fi

case "$OS_ID" in
    debian|ubuntu|raspbian|linuxmint|pop)         TIER="Tier 1 (fully tested)" ;;
    fedora|rhel|centos|rocky|almalinux|arch|manjaro|opensuse*|sles)
                                                  TIER="Tier 2 (best-effort)" ;;
    *)
        [ "$(uname -s)" = "Darwin" ] && TIER="Tier 2 (best-effort)"
        ;;
esac

ok "OS: $OS_NAME"
if [ -n "$PKG_MGR" ]; then
    ok "Package manager: $PKG_MGR"
else
    warn "No supported package manager detected — system tools must be installed manually."
fi
ok "Support level: $TIER"

# ----------------------------------------------------------------------------
# Step 2: Install system packages
# ----------------------------------------------------------------------------
step "2/6  Installing system packages"

install_system_packages() {
    # Package notes:
    #   nmap, masscan — active scanning
    #   git, python3* — repo + venv
    #   libpcap, build-essential — needed by scapy for raw-socket capture
    #   avahi-utils / avahi-tools — provides 'avahi-browse', used by
    #       core/active_mdns.py to piggyback on the system mDNS cache
    #       on Linux hosts running avahi-daemon (standard on Pi OS,
    #       Debian, Ubuntu). Without it NetWatch falls back to the
    #       Python zeroconf library, which misses Bonjour Sleep Proxy
    #       forwarded records (e.g. sleeping Apple TVs).
    case "$PKG_MGR" in
        apt)
            $SUDO apt-get update -qq
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                nmap masscan git \
                python3 python3-venv python3-pip python3-dev \
                libpcap-dev build-essential \
                avahi-utils
            ;;
        dnf)
            $SUDO dnf install -y \
                nmap masscan git python3 python3-pip python3-devel libpcap-devel gcc \
                avahi-tools
            ;;
        yum)
            $SUDO yum install -y epel-release || true
            $SUDO yum install -y \
                nmap masscan git python3 python3-pip python3-devel libpcap-devel gcc \
                avahi-tools
            ;;
        pacman)
            $SUDO pacman -Sy --noconfirm --needed \
                nmap masscan git python python-pip libpcap base-devel \
                avahi
            ;;
        zypper)
            $SUDO zypper install -y \
                nmap masscan git python3 python3-pip python3-devel libpcap-devel gcc \
                avahi-utils
            ;;
        brew)
            # macOS ships its own mDNSResponder — no avahi needed. NetWatch
            # falls back to the Python zeroconf library on Darwin.
            brew install nmap masscan git python3
            ;;
        *)
            return 1
            ;;
    esac
}

if [ "$SKIP_SYSTEM" -eq 1 ]; then
    warn "Skipping system package install (--no-system)"
elif [ -z "$PKG_MGR" ]; then
    warn "No package manager detected. Make sure these are installed manually:"
    warn "  nmap, masscan, git, python3 (>=3.9), python3-venv, libpcap dev headers,"
    warn "  avahi-utils (Linux only, for 'avahi-browse' — improves mDNS discovery)"
else
    if install_system_packages; then
        ok "System packages installed/verified"
    else
        warn "Some system packages may have failed. Continuing — Python check will catch fatal misses."
    fi
fi

# Hard requirements check (after install attempt)
for tool in python3 git nmap; do
    command -v "$tool" &>/dev/null || \
        die "$tool is required but not on PATH. Install it manually and re-run."
done

# Python version >= 3.9
PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="$(echo "$PY_VERSION" | cut -d. -f1)"
PY_MINOR="$(echo "$PY_VERSION" | cut -d. -f2)"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
    die "Python $PY_VERSION found, but NetWatch needs Python 3.9 or newer."
fi

ok "python3 $PY_VERSION"
ok "nmap $(nmap --version | head -n1 | awk '{print $3}')"
if command -v masscan &>/dev/null; then
    MASSCAN_VER="$(masscan --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo unknown)"
    ok "masscan $MASSCAN_VER"
else
    warn "masscan not installed (optional — slower port discovery without it)"
fi
if command -v avahi-browse &>/dev/null; then
    ok "avahi-browse available (preferred mDNS path)"
else
    warn "avahi-browse not installed (optional — falls back to python zeroconf)"
fi

# ----------------------------------------------------------------------------
# Step 3: Create / reuse venv
# ----------------------------------------------------------------------------
step "3/6  Setting up Python virtual environment"

VENV_DIR="$SCRIPT_DIR/venv"

if [ -d "$VENV_DIR" ] && [ "$FORCE" -eq 1 ]; then
    warn "Removing existing venv (--force)"
    rm -rf "$VENV_DIR"
fi

if [ -d "$VENV_DIR" ] && [ -x "$VENV_DIR/bin/python3" ]; then
    ok "Reusing existing venv at $VENV_DIR"
else
    VENV_ERR="$(mktemp)"
    if ! python3 -m venv "$VENV_DIR" 2>"$VENV_ERR"; then
        cat "$VENV_ERR" >&2
        rm -f "$VENV_ERR"
        die "Failed to create venv. On Debian/Ubuntu/Pi OS, install python3-venv: $SUDO apt install python3-venv"
    fi
    rm -f "$VENV_ERR"
    ok "Created venv at $VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python3"

# ----------------------------------------------------------------------------
# Step 4: Install Python dependencies inside the venv
# ----------------------------------------------------------------------------
step "4/6  Installing Python dependencies (this may take a few minutes)"

# Inside the venv, PEP 668 does not apply — pip install is safe.
"$VENV_PY" -m pip install --upgrade pip wheel setuptools >/dev/null
if "$VENV_PY" -m pip install -r requirements.txt; then
    ok "Python dependencies installed"
else
    err "pip install failed. Inspect the error above and re-run with --force."
    exit 1
fi

# Sanity check: every module NetWatch actually imports must load.
"$VENV_PY" - <<'PYCHECK' || die "Import sanity check failed. Try: ./install.sh --force"
import sys
modules = [
    "nmap", "rich", "requests", "jinja2", "cryptography",
    "dns", "paramiko", "pysnmp", "impacket", "zeroconf",
    "scapy", "packaging",
]
missing = []
for m in modules:
    try:
        __import__(m)
    except ImportError as e:
        missing.append(f"{m}: {e}")
if missing:
    print("Missing or broken Python modules:")
    for m in missing:
        print(f"  - {m}")
    sys.exit(1)
PYCHECK
ok "All required Python modules import OK"

# ----------------------------------------------------------------------------
# Step 5: Make launcher executable + optional global symlink
# ----------------------------------------------------------------------------
step "5/6  Configuring launcher"

LAUNCHER="$SCRIPT_DIR/netwatch"
[ -f "$LAUNCHER" ] || die "Launcher script $LAUNCHER missing from repository."

chmod +x "$LAUNCHER"
chmod +x "$SCRIPT_DIR/netwatch.py"
ok "Launcher: $LAUNCHER (run as: ./netwatch  or  sudo ./netwatch)"

if [ "$SYMLINK" -eq 1 ]; then
    if $SUDO ln -sf "$LAUNCHER" /usr/local/bin/netwatch; then
        ok "Global symlink: /usr/local/bin/netwatch"
    else
        warn "Could not create /usr/local/bin/netwatch (permission denied)"
    fi
fi

# ----------------------------------------------------------------------------
# Step 6: Self-test
# ----------------------------------------------------------------------------
step "6/6  Self-test"

if VERSION_OUT="$("$LAUNCHER" --version 2>&1)"; then
    ok "Self-test passed: $(echo "$VERSION_OUT" | tail -n1)"
else
    err "Self-test failed:"
    echo "$VERSION_OUT" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
# Done
# ----------------------------------------------------------------------------
echo
echo "${BOLD}${GREEN}NetWatch installed successfully.${NC}"
echo
echo "Next steps:"
echo "  1. Download EOL/CVE/credential databases (one-time, ~1 minute):"
echo "       sudo ./netwatch --setup"
echo "  2. Try an instant scan of your local network:"
echo "       sudo ./netwatch --instant"
echo "  3. Or run a full security assessment:"
echo "       sudo ./netwatch --full-assessment --target 192.168.1.0/24"
echo
echo "${DIM}On Raspberry Pi or hosts running Pi-hole, NetWatch automatically enables${NC}"
echo "${DIM}safe-mode scanning to avoid saturating the local DNS resolver.${NC}"
echo
