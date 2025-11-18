# Testing Guide - Virtual UART Setup

This guide shows you how to test the air quality monitoring system using virtual serial ports (no hardware required).

## Prerequisites

1. Start PostgreSQL and Grafana:
   ```bash
   docker-compose up -d
   ```

2. Wait for services to be ready (about 10 seconds)

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### Option 1: Automated Test (Easiest)

Run everything with one command:

```bash
./test_system.sh
```

This will:
1. Create virtual UART pair at `/tmp/vport1` and `/tmp/vport2`
2. Start the simulator sending data from 3 devices
3. Start the monitor reading and storing data to PostgreSQL
4. Log everything to console

Press `Ctrl+C` to stop.

### Option 2: Manual Setup (More Control)

#### Terminal 1: Create Virtual UART Pair

```bash
./setup_virtual_uart.sh
```

This creates two connected serial ports:
- `/tmp/vport1` - For the simulator
- `/tmp/vport2` - For the monitor

Leave this running.

#### Terminal 2: Start Data Simulator

```bash
python3 simulate_cat_data.py /tmp/vport1
```

Options:
```bash
# Simulate 5 devices
python3 simulate_cat_data.py /tmp/vport1 -n 5

# Send data every 5 seconds
python3 simulate_cat_data.py /tmp/vport1 -i 5

# Different baud rate
python3 simulate_cat_data.py /tmp/vport1 -b 9600

# Verbose logging
python3 simulate_cat_data.py /tmp/vport1 -v
```

#### Terminal 3: Start Monitor

```bash
python3 air_quality_monitor.py /tmp/vport2
```

This connects to the PostgreSQL database running in Docker (localhost:5432).

For verbose logging:
```bash
python3 air_quality_monitor.py /tmp/vport2 -v
```

## What the Simulator Does

The simulator creates realistic air quality data:

- **Multiple devices**: Simulates 3 devices by default (ROOM_A, ROOM_B, ROOM_C)
- **Realistic variations**: Each room has different baseline air quality
- **Natural fluctuations**: Values vary randomly within realistic ranges
- **Events**: Occasionally simulates events like:
  - CO2 spikes (someone enters the room)
  - Air quality drops (window opened)
  - Gradual return to baseline

### Example Output

```
2024-01-15 10:23:45 - INFO - Sent: LORA DATA START ROOM_A 654.3 12.5 45.2
2024-01-15 10:23:45 - INFO - Sent: LORA DATA START ROOM_B 523.1 8.7 38.9
2024-01-15 10:23:45 - INFO - Sent: LORA DATA START ROOM_C 789.4 15.3 52.1
```

## Viewing the Data

### In the Database

```bash
# Count total readings
docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT COUNT(*) FROM air_quality;"

# View last 10 readings
docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT * FROM air_quality ORDER BY timestamp DESC LIMIT 10;"

# View average by device
docker-compose exec postgres psql -U airquality -d air_quality -c "
  SELECT
    device_id,
    ROUND(AVG(co2)::numeric, 1) as avg_co2,
    ROUND(AVG(pm25)::numeric, 1) as avg_pm25,
    ROUND(AVG(pm10)::numeric, 1) as avg_pm10
  FROM air_quality
  GROUP BY device_id;
"

# Direct psql access
docker-compose exec postgres psql -U airquality -d air_quality
```

### In Grafana

1. Ensure Grafana is running:
   ```bash
   docker-compose up -d
   ```

2. Open http://localhost:3000 (admin/admin)

3. The dashboard will automatically show all simulated devices with live updates

4. Data refreshes every 5 seconds

## Troubleshooting

### "socat: command not found"

Install socat:

```bash
# Ubuntu/Debian
sudo apt-get install socat

# RHEL/CentOS
sudo yum install socat

# macOS
brew install socat
```

### "Permission denied" on virtual ports

Virtual ports created by socat should be accessible without sudo. If you still have issues:

```bash
ls -l /tmp/vport*
```

### Ports not connecting

Make sure `setup_virtual_uart.sh` is still running in the background. The virtual ports only exist while socat is running.

### No data in database

1. Check PostgreSQL is running: `docker-compose ps postgres`
2. Check simulator is sending data (you should see log messages)
3. Check monitor is receiving data (you should see log messages)
4. Verify data in database:
   ```bash
   docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT COUNT(*) FROM air_quality;"
   ```
5. Check PostgreSQL logs: `docker logs air-quality-postgres`

### Database connection errors

If monitor shows connection errors:
```bash
# Ensure PostgreSQL is healthy
docker-compose ps

# Check PostgreSQL logs
docker logs air-quality-postgres

# Restart PostgreSQL
docker-compose restart postgres
```

### Kill stuck processes

```bash
# Kill all related processes
pkill -f simulate_cat_data
pkill -f air_quality_monitor
pkill -f socat
rm -f /tmp/vport*
```

## Performance Testing

### High-frequency data

Test with faster sampling:

```bash
# Send data every 0.1 seconds (10 Hz)
python3 simulate_cat_data.py /tmp/vport1 -i 0.1
```

### Many devices

Test with more devices:

```bash
# Simulate 10 devices
python3 simulate_cat_data.py /tmp/vport1 -n 10
```

### Check database growth

```bash
# Watch database size and row count
watch -n 1 'docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT COUNT(*) as total_readings FROM air_quality;" && docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT pg_size_pretty(pg_database_size('\''air_quality'\'')) as db_size;"'
```

## Next Steps

Once virtual testing works:

1. Replace `/tmp/vport2` with your real serial port (e.g., `/dev/ttyUSB0`)
2. Connect your CAT hardware
3. Update baud rate if needed (default is 115200)
4. The same PostgreSQL database is used for both testing and production

## Files Used for Testing

- `simulate_cat_data.py` - Generates realistic test data
- `setup_virtual_uart.sh` - Creates virtual serial port pair
- `test_system.sh` - Runs complete test automatically

## Clearing Test Data

To clear all test data from PostgreSQL:

```bash
docker-compose exec postgres psql -U airquality -d air_quality -c "TRUNCATE TABLE air_quality RESTART IDENTITY;"
```

Or to start completely fresh:

```bash
docker-compose down -v  # Remove all data including PostgreSQL volume
docker-compose up -d    # Start fresh
```
