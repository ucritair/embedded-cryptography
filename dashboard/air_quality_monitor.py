#!/usr/bin/env python3
"""
Air Quality Monitor - UART to Database
Reads air quality data from CAT units via UART and stores in PostgreSQL database
"""

import serial
import psycopg2
from psycopg2 import sql
import re
import time
from datetime import datetime
import argparse
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AirQualityMonitor:
    def __init__(self, serial_port, baud_rate=115200, db_host='localhost',
                 db_port=5432, db_name='air_quality', db_user='airquality',
                 db_password='airquality123'):
        """
        Initialize the air quality monitor

        Args:
            serial_port: Serial port path (e.g., /dev/ttyUSB0 or COM3)
            baud_rate: UART baud rate (default: 115200)
            db_host: PostgreSQL host (default: localhost)
            db_port: PostgreSQL port (default: 5432)
            db_name: Database name (default: air_quality)
            db_user: Database user (default: airquality)
            db_password: Database password (default: airquality123)
        """
        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.ser = None
        self.conn = None

        # Regex pattern to match: LORA DATA START {DEVICE_ID} {CO2} {PM2.5} {PM10}
        self.data_pattern = re.compile(
            r'LORA DATA START\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)'
        )

    def setup_database(self):
        """Create database and table if they don't exist"""
        try:
            self.conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            cursor = self.conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS air_quality (
                    id SERIAL PRIMARY KEY,
                    timestamp BIGINT NOT NULL,
                    device_id VARCHAR(50) NOT NULL,
                    co2 DOUBLE PRECISION NOT NULL,
                    pm25 DOUBLE PRECISION NOT NULL,
                    pm10 DOUBLE PRECISION NOT NULL
                )
            ''')

            # Create indexes for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON air_quality(timestamp)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_device_id
                ON air_quality(device_id)
            ''')

            self.conn.commit()
            logger.info(f"Database initialized: {self.db_user}@{self.db_host}:{self.db_port}/{self.db_name}")
        except psycopg2.Error as e:
            logger.error(f"Database connection error: {e}")
            raise

    def connect_serial(self):
        """Connect to the serial port"""
        try:
            self.ser = serial.Serial(
                port=self.serial_port,
                baudrate=self.baud_rate,
                timeout=1
            )
            logger.info(f"Connected to {self.serial_port} at {self.baud_rate} baud")
            return True
        except serial.SerialException as e:
            logger.error(f"Failed to connect to serial port: {e}")
            return False

    def parse_data(self, line):
        """
        Parse UART data line

        Args:
            line: String in format "LORA DATA START {DEVICE_ID} {CO2} {PM2.5} {PM10}"

        Returns:
            dict with parsed data or None if invalid
        """
        match = self.data_pattern.search(line)
        if match:
            return {
                'device_id': match.group(1),
                'co2': float(match.group(2)),
                'pm25': float(match.group(3)),
                'pm10': float(match.group(4))
            }
        return None

    def insert_data(self, data):
        """Insert parsed data into database"""
        try:
            cursor = self.conn.cursor()
            # Get current timestamp in milliseconds
            timestamp_ms = int(time.time() * 1000)
            cursor.execute('''
                INSERT INTO air_quality (timestamp, device_id, co2, pm25, pm10)
                VALUES (%s, %s, %s, %s, %s)
            ''', (timestamp_ms, data['device_id'], data['co2'], data['pm25'], data['pm10']))
            self.conn.commit()

            logger.info(
                f"Device {data['device_id']}: "
                f"CO2={data['co2']} ppm, "
                f"PM2.5={data['pm25']}, "
                f"PM10={data['pm10']}"
            )
        except psycopg2.Error as e:
            logger.error(f"Database error: {e}")
            self.conn.rollback()

    def run(self):
        """Main loop to read UART and store data"""
        if not self.connect_serial():
            return

        self.setup_database()

        logger.info("Starting data collection... (Ctrl+C to stop)")

        try:
            while True:
                if self.ser.in_waiting > 0:
                    try:
                        # Read line from UART
                        line = self.ser.readline().decode('utf-8', errors='ignore').strip()

                        if line:
                            logger.debug(f"Received: {line}")

                            # Parse the data
                            data = self.parse_data(line)

                            if data:
                                # Insert into database
                                self.insert_data(data)
                            else:
                                logger.debug(f"No match for line: {line}")

                    except UnicodeDecodeError as e:
                        logger.warning(f"Decode error: {e}")
                    except Exception as e:
                        logger.error(f"Error processing line: {e}")

                time.sleep(0.01)  # Small delay to prevent CPU spinning

        except KeyboardInterrupt:
            logger.info("\nStopping data collection...")
        finally:
            self.cleanup()

    def cleanup(self):
        """Close connections"""
        if self.ser and self.ser.is_open:
            self.ser.close()
            logger.info("Serial port closed")
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


def main():
    parser = argparse.ArgumentParser(
        description='Air Quality Monitor - Read UART data and store to PostgreSQL database'
    )
    parser.add_argument(
        'serial_port',
        help='Serial port (e.g., /dev/ttyUSB0 or COM3)'
    )
    parser.add_argument(
        '-b', '--baud-rate',
        type=int,
        default=115200,
        help='Baud rate (default: 115200)'
    )
    parser.add_argument(
        '--db-host',
        default='localhost',
        help='PostgreSQL host (default: localhost)'
    )
    parser.add_argument(
        '--db-port',
        type=int,
        default=5432,
        help='PostgreSQL port (default: 5432)'
    )
    parser.add_argument(
        '--db-name',
        default='air_quality',
        help='Database name (default: air_quality)'
    )
    parser.add_argument(
        '--db-user',
        default='airquality',
        help='Database user (default: airquality)'
    )
    parser.add_argument(
        '--db-password',
        default='airquality123',
        help='Database password (default: airquality123)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    monitor = AirQualityMonitor(
        serial_port=args.serial_port,
        baud_rate=args.baud_rate,
        db_host=args.db_host,
        db_port=args.db_port,
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password
    )

    monitor.run()


if __name__ == '__main__':
    main()
