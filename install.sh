#!/bin/bash
#
# NetWatch Installer Script for Linux and macOS
# 
# This script installs NetWatch and all its dependencies:
# - Python 3.9+
# - pip
# - nmap binary
# - Python packages from requirements.txt
#
# Usage: ./install.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Track step results
declare -A STEP_STATUS
declare -A STEP_MESSAGES

# ASCII Banner
echo ""
echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║                                                              ║${NC}"
echo -e "${BLUE}${BOLD}║              NetWatch Installer                              ║${NC}"
echo -e "${BLUE}${BOLD}║              Network EOL Scanner Setup                       ║${NC}"
echo -e "${BLUE}${BOLD}║                                                              ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Helper functions
print_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
}

print_info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

print_warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

record_step() {
    local step_num=$1
    local status=$2
    local message=$3
    STEP_STATUS[$step_num]=$status
    STEP_MESSAGES[$step_num]=$message
}

# ============================================================================
# STEP 1: Detect Operating System
# ============================================================================
STEP_NUM=1
print_info "Step ${STEP_NUM}: Detecting Operating System..."

OS=""
DISTRO=""

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$NAME
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO=$(cat /etc/redhat-release)
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="Debian $(cat /etc/debian_version)"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    DISTRO=$(sw_vers -productName 2>/dev/null || echo "macOS")
else
    OS="Unknown"
fi

print_pass "Detected OS: ${OS} (${DISTRO})"
record_step $STEP_NUM "PASS" "OS: ${OS} (${DISTRO})"

# ============================================================================
# STEP 2: Check Python >= 3.9
# ============================================================================
STEP_NUM=2
print_info "Step ${STEP_NUM}: Checking Python version..."

PYTHON_CMD=""
PYTHON_VERSION=""

# Check for python3 first, then python
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
fi

if [[ -z "$PYTHON_CMD" ]]; then
    print_fail "Python is not installed"
    echo ""
    echo -e "${RED}CRITICAL: Python 3.9 or higher is required.${NC}"
    echo ""
    echo "Installation instructions:"
    echo "  Ubuntu/Debian:  sudo apt-get install python3 python3-pip"
    echo "  RHEL/CentOS:    sudo yum install python3 python3-pip"
    echo "  Fedora:         sudo dnf install python3 python3-pip"
    echo "  Arch Linux:     sudo pacman -S python python-pip"
    echo "  macOS:          brew install python3"
    echo "  Or visit:       https://www.python.org/downloads/"
    echo ""
    record_step $STEP_NUM "FAIL" "Python not installed"
    exit 1
fi

# Check version
REQUIRED_VERSION="3.9"
CURRENT_VERSION=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$CURRENT_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    print_fail "Python version ${PYTHON_VERSION} is too old (requires >= 3.9)"
    echo ""
    echo -e "${RED}CRITICAL: Python 3.9 or higher is required.${NC}"
    echo "Please upgrade Python and try again."
    echo "Visit: https://www.python.org/downloads/"
    record_step $STEP_NUM "FAIL" "Python ${PYTHON_VERSION} < 3.9"
    exit 1
fi

print_pass "Python ${PYTHON_VERSION} found (${PYTHON_CMD})"
record_step $STEP_NUM "PASS" "Python ${PYTHON_VERSION}"

# ============================================================================
# STEP 3: Check pip
# ============================================================================
STEP_NUM=3
print_info "Step ${STEP_NUM}: Checking pip..."

if ! $PYTHON_CMD -m pip --version &>/dev/null; then
    print_warn "pip not found, attempting to install..."
    $PYTHON_CMD -m ensurepip --upgrade 2>/dev/null || {
        print_fail "Failed to install pip"
        echo ""
        echo -e "${RED}CRITICAL: pip is required but could not be installed.${NC}"
        echo "Try installing manually:"
        echo "  curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py"
        echo "  $PYTHON_CMD get-pip.py"
        record_step $STEP_NUM "FAIL" "pip installation failed"
        exit 1
    }
fi

PIP_VERSION=$($PYTHON_CMD -m pip --version | awk '{print $2}')
print_pass "pip ${PIP_VERSION} installed"
record_step $STEP_NUM "PASS" "pip ${PIP_VERSION}"

# ============================================================================
# STEP 4: Install nmap binary
# ============================================================================
STEP_NUM=4
print_info "Step ${STEP_NUM}: Installing nmap binary..."

NMAP_INSTALLED=false

if command -v nmap &>/dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1 | awk '{print $3}')
    print_pass "nmap ${NMAP_VERSION} already installed"
    NMAP_INSTALLED=true
    record_step $STEP_NUM "PASS" "nmap ${NMAP_VERSION} (existing)"
else
    print_info "nmap not found, attempting to install..."
    
    # Detect package manager and install
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get &>/dev/null; then
            print_info "Using apt-get to install nmap..."
            if sudo apt-get update && sudo apt-get install -y nmap; then
                NMAP_INSTALLED=true
            fi
        elif command -v yum &>/dev/null; then
            print_info "Using yum to install nmap..."
            if sudo yum install -y nmap; then
                NMAP_INSTALLED=true
            fi
        elif command -v dnf &>/dev/null; then
            print_info "Using dnf to install nmap..."
            if sudo dnf install -y nmap; then
                NMAP_INSTALLED=true
            fi
        elif command -v pacman &>/dev/null; then
            print_info "Using pacman to install nmap..."
            if sudo pacman -S --noconfirm nmap; then
                NMAP_INSTALLED=true
            fi
        elif command -v zypper &>/dev/null; then
            print_info "Using zypper to install nmap..."
            if sudo zypper install -y nmap; then
                NMAP_INSTALLED=true
            fi
        fi
    elif [[ "$OS" == "macOS" ]]; then
        if command -v brew &>/dev/null; then
            print_info "Using Homebrew to install nmap..."
            if brew install nmap; then
                NMAP_INSTALLED=true
            fi
        elif command -v port &>/dev/null; then
            print_info "Using MacPorts to install nmap..."
            if sudo port install nmap; then
                NMAP_INSTALLED=true
            fi
        fi
    fi
    
    if [[ "$NMAP_INSTALLED" == true ]]; then
        NMAP_VERSION=$(nmap --version | head -n1 | awk '{print $3}')
        print_pass "nmap ${NMAP_VERSION} installed successfully"
        record_step $STEP_NUM "PASS" "nmap ${NMAP_VERSION} (installed)"
    else
        print_fail "Could not install nmap automatically"
        echo ""
        echo -e "${YELLOW}WARNING: nmap binary installation failed.${NC}"
        echo ""
        echo "nmap is required for NetWatch to function."
        echo "Please install it manually:"
        echo ""
        echo "Download from: https://nmap.org/download.html"
        echo ""
        echo "Package manager commands:"
        echo "  Debian/Ubuntu:  sudo apt-get install nmap"
        echo "  RHEL/CentOS:    sudo yum install nmap"
        echo "  Fedora:         sudo dnf install nmap"
        echo "  Arch:           sudo pacman -S nmap"
        echo "  macOS (brew):   brew install nmap"
        echo "  macOS (port):   sudo port install nmap"
        echo ""
        read -p "Press ENTER to continue anyway, or CTRL+C to cancel..."
        record_step $STEP_NUM "WARN" "nmap not installed"
    fi
fi

# ============================================================================
# STEP 5: Create Python virtual environment
# ============================================================================
STEP_NUM=5
print_info "Step ${STEP_NUM}: Creating Python virtual environment..."

if [[ -d "./venv" ]]; then
    print_warn "venv directory already exists, using existing"
else
    if $PYTHON_CMD -m venv ./venv; then
        print_pass "Virtual environment created"
    else
        print_fail "Failed to create virtual environment"
        record_step $STEP_NUM "FAIL" "venv creation failed"
        exit 1
    fi
fi

record_step $STEP_NUM "PASS" "venv created"

# ============================================================================
# STEP 6: Activate virtual environment
# ============================================================================
STEP_NUM=6
print_info "Step ${STEP_NUM}: Activating virtual environment..."

if [[ -f "./venv/bin/activate" ]]; then
    source ./venv/bin/activate
    print_pass "Virtual environment activated"
    record_step $STEP_NUM "PASS" "venv activated"
else
    print_fail "Could not find virtual environment activation script"
    record_step $STEP_NUM "FAIL" "venv activation failed"
    exit 1
fi

# ============================================================================
# STEP 7: Upgrade pip in venv
# ============================================================================
STEP_NUM=7
print_info "Step ${STEP_NUM}: Upgrading pip in virtual environment..."

if pip install --upgrade pip; then
    PIP_NEW_VERSION=$(pip --version | awk '{print $2}')
    print_pass "pip upgraded to ${PIP_NEW_VERSION}"
    record_step $STEP_NUM "PASS" "pip upgraded"
else
    print_fail "Failed to upgrade pip"
    record_step $STEP_NUM "FAIL" "pip upgrade failed"
    exit 1
fi

# ============================================================================
# STEP 8: Install Python dependencies
# ============================================================================
STEP_NUM=8
print_info "Step ${STEP_NUM}: Installing Python dependencies..."

# Check if requirements.txt exists
if [[ ! -f "requirements.txt" ]]; then
    print_fail "requirements.txt not found"
    echo "Creating requirements.txt with default dependencies..."
    cat > requirements.txt << 'EOF'
python-nmap==0.7.1
requests==2.31.0
rich==13.7.0
packaging==24.0
EOF
fi

if pip install -r requirements.txt; then
    print_pass "Python dependencies installed"
    record_step $STEP_NUM "PASS" "dependencies installed"
else
    print_fail "Failed to install Python dependencies"
    echo ""
    echo -e "${RED}CRITICAL: Failed to install required packages.${NC}"
    echo "Check your internet connection and try again."
    record_step $STEP_NUM "FAIL" "pip install failed"
    exit 1
fi

# ============================================================================
# STEP 9: Verify package imports
# ============================================================================
STEP_NUM=9
print_info "Step ${STEP_NUM}: Verifying package installation..."

if python -c "import nmap; import requests; import rich; import packaging" 2>/dev/null; then
    print_pass "All packages import successfully"
    record_step $STEP_NUM "PASS" "imports verified"
else
    print_fail "Package verification failed"
    echo "One or more packages failed to install correctly."
    record_step $STEP_NUM "FAIL" "import verification failed"
    exit 1
fi

# ============================================================================
# STEP 10: Check for sudo/root access
# ============================================================================
STEP_NUM=10
print_info "Step ${STEP_NUM}: Checking privileges..."

if [[ $EUID -eq 0 ]]; then
    print_pass "Running as root"
    record_step $STEP_NUM "PASS" "root user"
else
    print_warn "Not running as root - some features may be limited"
    record_step $STEP_NUM "WARN" "not root"
fi

# ============================================================================
# STEP 11: Make netwatch.py executable
# ============================================================================
STEP_NUM=11
print_info "Step ${STEP_NUM}: Setting executable permissions..."

if [[ -f "netwatch.py" ]]; then
    chmod +x netwatch.py
    print_pass "Made netwatch.py executable"
    record_step $STEP_NUM "PASS" "chmod +x"
else
    print_fail "netwatch.py not found in current directory"
    record_step $STEP_NUM "FAIL" "netwatch.py missing"
    exit 1
fi

# ============================================================================
# STEP 12: Offer global symlink
# ============================================================================
STEP_NUM=12
print_info "Step ${STEP_NUM}: Global installation..."

echo ""
read -p "Create global symlink in /usr/local/bin? (requires sudo) [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    NETWATCH_PATH=$(pwd)/netwatch.py
    if sudo ln -sf "$NETWATCH_PATH" /usr/local/bin/netwatch; then
        print_pass "Created symlink: /usr/local/bin/netwatch"
        record_step $STEP_NUM "PASS" "symlink created"
    else
        print_fail "Failed to create symlink (permission denied?)"
        record_step $STEP_NUM "WARN" "symlink failed"
    fi
else
    print_info "Skipped global symlink"
    record_step $STEP_NUM "SKIP" "no symlink"
fi

# ============================================================================
# STEP 13: Self-test
# ============================================================================
STEP_NUM=13
print_info "Step ${STEP_NUM}: Running self-test..."

if python netwatch.py --version &>/dev/null; then
    VERSION=$(python netwatch.py --version 2>&1 | tail -n1)
    print_pass "Self-test passed: ${VERSION}"
    record_step $STEP_NUM "PASS" "self-test OK"
else
    print_fail "Self-test failed"
    record_step $STEP_NUM "FAIL" "self-test failed"
    exit 1
fi

# ============================================================================
# Installation Summary
# ============================================================================
echo ""
echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║                    Installation Summary                      ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

for i in $(seq 1 $STEP_NUM); do
    status=${STEP_STATUS[$i]:-"UNKNOWN"}
    message=${STEP_MESSAGES[$i]:-"No details"}
    
    if [[ "$status" == "PASS" ]]; then
        printf "${GREEN}✓ PASS${NC} Step %2d: %s\n" "$i" "$message"
    elif [[ "$status" == "WARN" ]] || [[ "$status" == "SKIP" ]]; then
        printf "${YELLOW}⚠ %s${NC} Step %2d: %s\n" "$status" "$i" "$message"
    else
        printf "${RED}✗ %s${NC} Step %2d: %s\n" "$status" "$i" "$message"
    fi
done

echo ""
echo -e "${GREEN}${BOLD}NetWatch installation complete!${NC}"
echo ""
echo "Usage:"
echo "  ./netwatch.py              Launch interactive menu"
echo "  ./netwatch.py --help       Show help"
echo "  ./netwatch.py --version    Show version"
echo ""

if [[ ${STEP_STATUS[12]:-"SKIP"} == "PASS" ]]; then
    echo "Global command available: netwatch"
else
    echo "Run from install directory: ./netwatch.py"
fi

echo ""
echo "For best results, run with sudo: sudo ./netwatch.py"
echo ""
