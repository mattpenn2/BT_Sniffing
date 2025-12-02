#!/bin/bash

################################################################################
# Bluetooth Security Scanner - Raspberry Pi Setup Script
# This script automates the installation and configuration of the scanner
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Raspberry Pi
check_raspberry_pi() {
    log_info "Checking if running on Raspberry Pi..."
    if [ -f /proc/device-tree/model ]; then
        MODEL=$(cat /proc/device-tree/model)
        log_success "Detected: $MODEL"
    else
        log_warning "Could not detect Raspberry Pi model, continuing anyway..."
    fi
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Update system
update_system() {
    log_info "Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq
    log_success "System updated"
}

# Install Bluetooth packages
install_bluetooth() {
    log_info "Installing Bluetooth packages..."
    
    apt-get install -y bluetooth bluez blueman libbluetooth-dev 2>&1 | grep -v "^(" || true
    
    # Verify installation
    if command -v bluetoothctl &> /dev/null; then
        log_success "Bluetooth packages installed"
    else
        log_error "Bluetooth installation failed"
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python development tools..."
    
    apt-get install -y python3-pip python3-dev build-essential 2>&1 | grep -v "^(" || true
    
    # Verify Python installation
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        log_success "Python installed: $PYTHON_VERSION"
    else
        log_error "Python installation failed"
        exit 1
    fi
}

# Enable and start Bluetooth service
enable_bluetooth() {
    log_info "Enabling Bluetooth service..."
    
    systemctl enable bluetooth
    systemctl start bluetooth
    sleep 2
    
    # Check if service is running
    if systemctl is-active --quiet bluetooth; then
        log_success "Bluetooth service is running"
    else
        log_warning "Bluetooth service may not be running properly"
        log_info "Attempting to restart..."
        systemctl restart bluetooth
        sleep 2
    fi
}

# Configure Bluetooth adapter
configure_bluetooth_adapter() {
    log_info "Configuring Bluetooth adapter..."
    
    # Bring up hci0
    hciconfig hci0 up 2>/dev/null || {
        log_warning "Could not bring up hci0, trying alternative method..."
        rfkill unblock bluetooth
        sleep 1
        hciconfig hci0 up 2>/dev/null || log_warning "hci0 may need manual configuration"
    }
    
    # Check adapter status
    if hciconfig hci0 2>/dev/null | grep -q "UP RUNNING"; then
        log_success "Bluetooth adapter is UP and RUNNING"
        ADAPTER_INFO=$(hciconfig hci0 | grep "BD Address" || echo "Address info not available")
        log_info "$ADAPTER_INFO"
    else
        log_warning "Bluetooth adapter may not be fully configured"
        log_info "Current adapter status:"
        hciconfig 2>/dev/null || log_warning "hciconfig not available"
    fi
}

# Clone or update repository
setup_repository() {
    log_info "Setting up project repository..."
    
    # Get the actual user (in case script is run with sudo)
    ACTUAL_USER=${SUDO_USER:-$USER}
    USER_HOME=$(eval echo ~$ACTUAL_USER)
    
    read -p "Enter your GitHub repository URL: " REPO_URL
    
    if [ -z "$REPO_URL" ]; then
        log_error "Repository URL cannot be empty"
        exit 1
    fi
    
    PROJECT_DIR="$USER_HOME/bluetooth-scanner"
    
    if [ -d "$PROJECT_DIR" ]; then
        log_warning "Directory $PROJECT_DIR already exists"
        read -p "Do you want to delete it and clone fresh? (y/n): " RESPONSE
        if [ "$RESPONSE" = "y" ] || [ "$RESPONSE" = "Y" ]; then
            rm -rf "$PROJECT_DIR"
            log_info "Cloning repository..."
            sudo -u $ACTUAL_USER git clone "$REPO_URL" "$PROJECT_DIR"
        else
            log_info "Using existing directory, pulling latest changes..."
            cd "$PROJECT_DIR"
            sudo -u $ACTUAL_USER git pull
        fi
    else
        log_info "Cloning repository..."
        sudo -u $ACTUAL_USER git clone "$REPO_URL" "$PROJECT_DIR"
    fi
    
    cd "$PROJECT_DIR"
    log_success "Repository ready at: $PROJECT_DIR"
}

# Install Python requirements
install_python_requirements() {
    log_info "Installing Python requirements..."
    
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found in current directory"
        exit 1
    fi
    
    # Try installing with pip3
    pip3 install -r requirements.txt 2>&1 | grep -E "(Successfully|Requirement already|ERROR)" || true
    
    # Check if pybluez installed successfully
    if python3 -c "import bluetooth" 2>/dev/null; then
        log_success "Python requirements installed successfully"
    else
        log_warning "PyBluez may have failed to install, attempting fix..."
        
        # Common fix: install libbluetooth-dev and retry
        apt-get install -y libbluetooth-dev
        pip3 install pybluez --no-cache-dir
        
        # Check again
        if python3 -c "import bluetooth" 2>/dev/null; then
            log_success "PyBluez installed successfully after fix"
        else
            log_error "Could not install PyBluez. Manual intervention may be needed."
            log_info "Try: sudo apt-get install libbluetooth-dev && pip3 install pybluez"
        fi
    fi
}

# Download OUI database
download_oui_database() {
    log_info "Downloading OUI database for manufacturer lookup..."
    
    mkdir -p data
    
    if wget -q --show-progress https://standards-oui.ieee.org/oui/oui.txt -O data/oui.txt; then
        log_success "OUI database downloaded successfully"
        OUI_SIZE=$(wc -l < data/oui.txt)
        log_info "OUI database contains $OUI_SIZE lines"
    else
        log_warning "Failed to download OUI database"
        log_info "You can download it manually later from: https://standards-oui.ieee.org/oui/oui.txt"
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p data/vulnerability_cache
    mkdir -p data/reports
    mkdir -p logs
    
    # Set proper permissions
    ACTUAL_USER=${SUDO_USER:-$USER}
    chown -R $ACTUAL_USER:$ACTUAL_USER data logs
    
    log_success "Directories created"
}

# Set Python capabilities (run without sudo)
set_python_capabilities() {
    log_info "Setting Python capabilities for Bluetooth access..."
    
    read -p "Do you want to enable running the scanner without sudo? (y/n): " RESPONSE
    if [ "$RESPONSE" = "y" ] || [ "$RESPONSE" = "Y" ]; then
        PYTHON_PATH=$(readlink -f $(which python3))
        setcap 'cap_net_raw,cap_net_admin+eip' $PYTHON_PATH
        log_success "Python capabilities set. You can now run without sudo."
    else
        log_info "Skipping capability setup. You'll need to use sudo to run scans."
    fi
}

# Test Bluetooth functionality
test_bluetooth() {
    log_info "Testing Bluetooth functionality..."
    
    # Test 1: Check hciconfig
    if hciconfig 2>/dev/null | grep -q "hci0"; then
        log_success "Bluetooth adapter detected"
    else
        log_error "No Bluetooth adapter found"
        log_info "Troubleshooting steps:"
        log_info "  1. Check if USB dongle is plugged in (if using one)"
        log_info "  2. Run: sudo systemctl status bluetooth"
        log_info "  3. Run: sudo rfkill list"
        return 1
    fi
    
    # Test 2: Quick scan
    log_info "Attempting a quick Bluetooth scan (8 seconds)..."
    if timeout 10 hcitool scan 2>/dev/null | grep -q "Scanning"; then
        log_success "Bluetooth scanning works!"
        log_info "Found devices:"
        timeout 10 hcitool scan 2>/dev/null | grep -v "Scanning" || log_info "  No devices found (this is okay if no Bluetooth devices nearby)"
    else
        log_warning "Bluetooth scan may have issues"
        log_info "This could be normal if no devices are nearby"
    fi
}

# Create a test script
create_test_script() {
    log_info "Creating test script..."
    
    cat > test_scanner.sh << 'EOF'
#!/bin/bash

echo "Testing Bluetooth Scanner Setup"
echo "================================"
echo ""

# Test 1: Bluetooth status
echo "1. Checking Bluetooth status..."
if systemctl is-active --quiet bluetooth; then
    echo "   ✓ Bluetooth service is running"
else
    echo "   ✗ Bluetooth service is NOT running"
    echo "   Fix: sudo systemctl start bluetooth"
fi

# Test 2: Bluetooth adapter
echo ""
echo "2. Checking Bluetooth adapter..."
if hciconfig hci0 2>/dev/null | grep -q "UP RUNNING"; then
    echo "   ✓ Bluetooth adapter is UP"
else
    echo "   ✗ Bluetooth adapter is DOWN"
    echo "   Fix: sudo hciconfig hci0 up"
fi

# Test 3: Python imports
echo ""
echo "3. Checking Python dependencies..."
python3 << 'PYEOF'
import sys
try:
    import bluetooth
    print("   ✓ PyBluez installed")
except ImportError:
    print("   ✗ PyBluez NOT installed")
    print("   Fix: pip3 install pybluez")

try:
    import requests
    print("   ✓ Requests installed")
except ImportError:
    print("   ✗ Requests NOT installed")
    print("   Fix: pip3 install requests")
PYEOF

# Test 4: Database
echo ""
echo "4. Checking database..."
if [ -f "data/scans.db" ]; then
    echo "   ✓ Database exists"
else
    echo "   ℹ Database will be created on first scan"
fi

# Test 5: OUI file
echo ""
echo "5. Checking OUI database..."
if [ -f "data/oui.txt" ]; then
    echo "   ✓ OUI database exists"
else
    echo "   ✗ OUI database NOT found"
    echo "   Fix: wget https://standards-oui.ieee.org/oui/oui.txt -O data/oui.txt"
fi

echo ""
echo "================================"
echo "Setup test complete!"
echo ""
echo "To run a scan:"
echo "  sudo python3 main.py passive -d 30 -r"
EOF

    chmod +x test_scanner.sh
    log_success "Test script created: test_scanner.sh"
}

# Print final instructions
print_instructions() {
    echo ""
    echo "========================================================================"
    log_success "Setup Complete!"
    echo "========================================================================"
    echo ""
    log_info "Next steps:"
    echo ""
    echo "1. Test your setup:"
    echo "   ./test_scanner.sh"
    echo ""
    echo "2. Run your first scan:"
    echo "   sudo python3 main.py passive -d 30 -r"
    echo ""
    echo "3. View available commands:"
    echo "   python3 main.py --help"
    echo ""
    echo "Common commands:"
    echo "  - Passive scan:  sudo python3 main.py passive -d 60 -r"
    echo "  - Active scan:   sudo python3 main.py active -r"
    echo "  - List scans:    sudo python3 main.py list-scans"
    echo "  - List devices:  sudo python3 main.py list-devices"
    echo "  - Generate report: sudo python3 main.py report <scan_id> -v"
    echo ""
    log_info "Troubleshooting:"
    echo "  - If Bluetooth issues: sudo systemctl restart bluetooth"
    echo "  - If adapter down: sudo hciconfig hci0 up"
    echo "  - Check logs: cat logs/bluetooth_scanner.log"
    echo ""
    echo "========================================================================"
}

# Main setup function
main() {
    echo "========================================================================"
    echo "        Bluetooth Security Scanner - Setup Script"
    echo "========================================================================"
    echo ""
    
    check_root
    check_raspberry_pi
    
    echo ""
    read -p "Press Enter to continue with installation..."
    echo ""
    
    # Run setup steps
    update_system
    install_bluetooth
    install_python_deps
    enable_bluetooth
    configure_bluetooth_adapter
    setup_repository
    install_python_requirements
    download_oui_database
    create_directories
    set_python_capabilities
    test_bluetooth
    create_test_script
    
    # Print final instructions
    print_instructions
}

# Run main function
main
