#!/bin/bash
# Setup virtual UART pair using socat

echo "Setting up virtual UART pair..."

# Check if socat is installed
if ! command -v socat &> /dev/null; then
    echo "Error: socat is not installed"
    echo "Install it with: sudo apt-get install socat (Ubuntu/Debian)"
    echo "                 sudo yum install socat (RHEL/CentOS)"
    echo "                 brew install socat (macOS)"
    exit 1
fi

# Create a symbolic link to make ports easier to remember
VPORT1="/tmp/vport1"
VPORT2="/tmp/vport2"

# Remove old symlinks if they exist
rm -f $VPORT1 $VPORT2

echo ""
echo "Creating virtual serial port pair..."
echo "This will create two connected ports:"
echo "  - $VPORT1 (for simulator)"
echo "  - $VPORT2 (for monitor)"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Create virtual serial port pair
# PTY creates pseudo-terminals, link creates symlinks, raw disables line editing
# echo=0 disables local echo
socat -d -d pty,raw,echo=0,link=$VPORT1 pty,raw,echo=0,link=$VPORT2
