#!/bin/bash

# Installation script for linux-sec-audit
# Requires root privileges

if [ "$EUID" -ne 0 ]; then 
    echo "Error: This installer requires root privileges"
    echo "Please run with: sudo bash install.sh"
    exit 1
fi

# Detect Python 3 installation
PYTHON3=$(which python3)

if [ -z "$PYTHON3" ]; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3.6 or higher"
    exit 1
fi

echo "======================================"
echo "  linux-sec-audit Installer"
echo "======================================"
echo ""

# Get Python version
PYTHON_VERSION=$($PYTHON3 --version 2>&1 | awk '{print $2}')
echo "✓ Found Python: $PYTHON_VERSION"

# Check Python version
MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || [ "$MAJOR" -eq 3 -a "$MINOR" -lt 6 ]; then
    echo "Error: Python 3.6+ is required (found $PYTHON_VERSION)"
    exit 1
fi

echo "✓ Python version check passed"
echo ""

# Install package
echo "Installing linux-sec-audit..."
$PYTHON3 setup.py install

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✓ Installation successful!"
    echo "======================================"
    echo ""
    echo "Usage:"
    echo "  sudo secscan --quick"
    echo "  sudo secscan --full"
    echo "  sudo secscan --full --output report.txt"
    echo "  sudo secscan --full --json"
    echo ""
    echo "For more information:"
    echo "  secscan --help"
    echo ""
else
    echo ""
    echo "✗ Installation failed"
    exit 1
fi
