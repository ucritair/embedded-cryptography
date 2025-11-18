# CAT Air Quality Monitor Dashboard

Real-time air quality monitoring system that reads data from multiple CAT units via UART and displays it in Grafana.

## Features

- Reads UART data in format: `LORA DATA START {DEVICE_ID} {CO2} {PM2.5} {PM10}`
- Stores data in PostgreSQL database with timestamps
- Real-time Grafana dashboard showing:
  - CO2 levels (ppm) over time
  - PM2.5 levels over time
  - PM10 levels over time
  - Current readings for all devices
- Supports multiple CAT units with device IDs

## Prerequisites

- Docker and Docker Compose installed
- Python 3.x installed
- Serial port access (for reading CAT unit data)

## Quick Start

### 1. Clone/Copy the Repository

Copy this dashboard directory to your machine or clone the repository.

### 2. Start PostgreSQL and Grafana

```bash
docker-compose up -d
```

This will start:
- PostgreSQL database on port 5432
- Grafana on port 3000

The Grafana datasource and dashboards will be automatically provisioned from the `grafana-provisioning/` directory.

Wait a few seconds for services to be ready. You can check the status with:

```bash
docker-compose ps
```

Both services should show "Up" status.

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `pyserial` - for reading UART serial data
- `psycopg2-binary` - for PostgreSQL database connection

### 4. Find Your Serial Port

**Linux:**
```bash
ls /dev/ttyUSB* /dev/ttyACM*
```

**Common ports:**
- Linux: `/dev/ttyUSB0`, `/dev/ttyACM0`
- macOS: `/dev/cu.usbserial-*`
- Windows: `COM3`, `COM4`, etc.

### 5. Run the Monitor

```bash
# Basic usage (115200 baud, connects to localhost:5432)
python air_quality_monitor.py /dev/ttyUSB0

# Custom baud rate
python air_quality_monitor.py /dev/ttyUSB0 -b 9600

# Custom database connection
python air_quality_monitor.py /dev/ttyUSB0 --db-host localhost --db-port 5432 --db-name air_quality --db-user airquality --db-password airquality123

# Verbose logging
python air_quality_monitor.py /dev/ttyUSB0 -v
```

The script will:
- Connect to the serial port
- Connect to PostgreSQL database
- Create the table and indexes if they don't exist
- Start reading and storing data
- Log each reading to console

### 6. Access Grafana

Access Grafana at: http://localhost:3000

**Default credentials:**
- Username: `admin`
- Password: `admin`

The dashboard will be automatically loaded and configured.

### 7. View the Dashboard

Open http://localhost:3000 and you'll see the "CAT Air Quality Monitor" dashboard with:

- **Time series graphs** showing CO2, PM2.5, and PM10 trends for all devices
- **Bar gauges** showing current readings for each device
- **Color-coded thresholds** (green/yellow/red based on air quality standards)
- **Auto-refresh** every 5 seconds

## Data Format

The system expects UART data in this format:

```
LORA DATA START DEVICE_001 450.5 12.3 45.2
LORA DATA START DEVICE_002 520.1 8.7 38.9
```

Where:
- `DEVICE_001` = Device ID
- `450.5` = CO2 in ppm
- `12.3` = PM2.5 in µg/m³
- `45.2` = PM10 in µg/m³

## Database Schema

```sql
CREATE TABLE air_quality (
    id SERIAL PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    device_id VARCHAR(50) NOT NULL,
    co2 DOUBLE PRECISION NOT NULL,
    pm25 DOUBLE PRECISION NOT NULL,
    pm10 DOUBLE PRECISION NOT NULL
);

CREATE INDEX idx_timestamp ON air_quality(timestamp);
CREATE INDEX idx_device_id ON air_quality(device_id);
```

**Note:** Timestamps are stored as Unix timestamps in milliseconds (BIGINT).

## Configuration

### Grafana Datasource

The PostgreSQL datasource is automatically configured via `grafana-provisioning/datasources/datasource.yml`.

**Important:** The database name must be specified in the `jsonData` section for compatibility with newer Grafana versions:

```yaml
datasources:
  - name: Air Quality DB
    type: postgres
    url: postgres:5432
    user: airquality
    jsonData:
      database: air_quality  # Must be in jsonData, not top-level
      sslmode: disable
      postgresVersion: 1600
```

If you see an error like "You do not currently have a default database configured", verify that `database` is inside the `jsonData` section.

### Dashboards

Dashboards are auto-provisioned from `grafana-provisioning/dashboards/`:
- `air_quality_dashboard.json` - Full-featured dashboard with all metrics

## Troubleshooting

### Grafana datasource error: "default database not configured"

This occurs when the database field is not in the correct location in `datasource.yml`.

**Solution:** Ensure `database: air_quality` is inside the `jsonData` section (see Configuration section above), then restart Grafana:

```bash
docker-compose restart grafana
```

### Permission denied on serial port

**Linux:**
```bash
sudo usermod -a -G dialout $USER
# Then log out and back in
```

Or run with sudo (not recommended for production):
```bash
sudo python air_quality_monitor.py /dev/ttyUSB0
```

### No data appearing in Grafana

1. Check that the monitor is running and logging data
2. Verify PostgreSQL is running: `docker-compose ps`
3. Check data is being inserted:
   ```bash
   docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT COUNT(*) FROM air_quality;"
   ```
4. Check recent data:
   ```bash
   docker-compose exec postgres psql -U airquality -d air_quality -c "SELECT * FROM air_quality ORDER BY timestamp DESC LIMIT 5;"
   ```
5. Restart services: `docker-compose restart`

### Database connection issues

If the monitor can't connect to PostgreSQL:
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# View PostgreSQL logs
docker logs air-quality-postgres

# Verify database credentials match in docker-compose.yml and your monitor command
```

## Stopping the Services

**Stop monitoring:**
Press `Ctrl+C` in the terminal running the Python script

**Stop Grafana:**
```bash
docker-compose down
```

**Stop Grafana and remove data:**
```bash
docker-compose down -v
```

## Production Considerations

- **Security**: Change default PostgreSQL credentials in `docker-compose.yml`
- **Grafana Auth**: Change the default Grafana admin password (currently `admin/admin`)
- **Data Retention**: Implement data retention policies to prevent unbounded database growth
  ```sql
  -- Example: Delete data older than 30 days
  DELETE FROM air_quality WHERE timestamp < EXTRACT(EPOCH FROM NOW() - INTERVAL '30 days') * 1000;
  ```
- **Backups**: Set up regular PostgreSQL backups using `pg_dump`
- **Performance**: PostgreSQL handles high-frequency data well. For even higher throughput, consider:
  - Batch inserts instead of individual INSERT statements
  - Connection pooling (e.g., pgBouncer)
  - TimescaleDB extension for time-series optimization
- **Monitoring**: Monitor PostgreSQL disk usage and performance metrics

## File Structure

```
dashboard/
├── air_quality_monitor.py          # Main UART reader script
├── requirements.txt                # Python dependencies (pyserial, psycopg2)
├── docker-compose.yml              # PostgreSQL + Grafana containers
├── grafana-provisioning/
│   ├── datasources/
│   │   └── datasource.yml         # Auto-configure PostgreSQL datasource
│   └── dashboards/
│       ├── dashboard.yml          # Dashboard provider config
│       └── air_quality_dashboard.json  # Full-featured dashboard
├── simulate_cat_data.py           # Test data generator
├── setup_virtual_uart.sh          # Virtual serial port setup
├── test_system.sh                 # Automated testing script
├── TESTING.md                     # Testing guide
└── README.md                      # This file
```

## Database Credentials

**Default credentials** (change these for production!):
- **Database**: air_quality
- **User**: airquality
- **Password**: airquality123
- **Port**: 5432
