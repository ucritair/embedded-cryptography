#!/bin/bash
# Convenience script to test the entire air quality monitoring system

set -e

echo "=========================================="
echo "  CAT Air Quality Monitor - Test Setup"
echo "=========================================="
echo ""

# Check dependencies
echo "Checking dependencies..."

if ! command -v socat &> /dev/null; then
    echo "Error: socat is not installed"
    echo "Install it with: sudo apt-get install socat"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed"
    exit 1
fi

if ! python3 -c "import serial" 2>/dev/null; then
    echo "Error: pyserial is not installed"
    echo "Install it with: pip install -r requirements.txt"
    exit 1
fi

if ! python3 -c "import psycopg2" 2>/dev/null; then
    echo "Error: psycopg2 is not installed"
    echo "Install it with: pip install -r requirements.txt"
    exit 1
fi

echo "All dependencies satisfied!"
echo ""

# Check Docker services
echo "Checking Docker services..."
if ! docker-compose ps | grep -q "air-quality-postgres.*Up"; then
    echo "Warning: PostgreSQL container is not running"
    echo "Starting Docker services..."
    docker-compose up -d
    echo "Waiting for PostgreSQL to be ready..."
    sleep 5
fi

if docker-compose ps | grep -q "air-quality-postgres.*Up"; then
    echo "PostgreSQL is running!"
else
    echo "Error: Failed to start PostgreSQL"
    echo "Run: docker-compose up -d"
    exit 1
fi
echo ""

# Define virtual ports
VPORT1="/tmp/vport1"
VPORT2="/tmp/vport2"

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -P $$ 2>/dev/null || true
    rm -f $VPORT1 $VPORT2
    exit 0
}

trap cleanup SIGINT SIGTERM

# Remove old ports
rm -f $VPORT1 $VPORT2

echo "Step 1: Creating virtual UART pair..."
socat -d -d pty,raw,echo=0,link=$VPORT1 pty,raw,echo=0,link=$VPORT2 &
SOCAT_PID=$!

# Wait for ports to be created
sleep 2

if [ ! -L "$VPORT1" ] || [ ! -L "$VPORT2" ]; then
    echo "Error: Failed to create virtual ports"
    exit 1
fi

echo "Virtual UART pair created:"
echo "  Simulator port: $VPORT1"
echo "  Monitor port:   $VPORT2"
echo ""

echo "Step 2: Starting data simulator..."
python3 simulate_cat_data.py $VPORT1 -n 5 -i 30 &
SIMULATOR_PID=$!
sleep 1
echo "Simulator running (5 devices, 30 second interval)"
echo ""

echo "Step 3: Starting air quality monitor..."
python3 air_quality_monitor.py $VPORT2 &
MONITOR_PID=$!
sleep 1
echo "Monitor running (writing to PostgreSQL: localhost:5432/air_quality)"
echo ""

echo "=========================================="
echo "  System Running!"
echo "=========================================="
echo ""
echo "You should see data being logged above."
echo ""
echo "To view the data in Grafana:"
echo "  1. Open: http://localhost:3000 (admin/admin)"
echo "  2. Navigate to the 'CAT Air Quality Monitor' dashboard"
echo "  3. Data refreshes every 5 seconds"
echo ""
echo "To query the database manually:"
echo "  docker-compose exec postgres psql -U airquality -d air_quality -c 'SELECT * FROM air_quality ORDER BY timestamp DESC LIMIT 10;'"
echo ""
echo "To check data count:"
echo "  docker-compose exec postgres psql -U airquality -d air_quality -c 'SELECT COUNT(*) FROM air_quality;'"
echo ""
echo "Press Ctrl+C to stop all processes"
echo ""

# Wait for user to stop
wait
