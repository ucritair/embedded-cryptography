#!/usr/bin/env python3
"""
CAT Air Quality Data Simulator
Sends simulated air quality data to a serial port for testing
"""

import serial
import time
import random
import argparse
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AirQualitySimulator:
    def __init__(self, serial_port, baud_rate=115200, num_devices=5, interval=30):
        """
        Initialize the simulator

        Args:
            serial_port: Serial port to write to
            baud_rate: UART baud rate (default: 115200)
            num_devices: Number of CAT devices to simulate (default: 5)
            interval: Seconds between readings (default: 30)
        """
        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self.num_devices = num_devices
        self.interval = interval
        self.ser = None

        # Device configurations (different rooms have different characteristics)
        self.devices = []
        room_names = ["ROOM_A", "ROOM_B", "ROOM_C", "ROOM_D", "ROOM_E"]

        for i in range(num_devices):
            device_id = room_names[i] if i < len(room_names) else f"CAT_{i+1:03d}"

            # Each room has different baseline air quality
            self.devices.append({
                'id': device_id,
                'co2_base': random.randint(400, 800),      # Base CO2 level
                'pm25_base': random.uniform(5, 20),        # Base PM2.5 level
                'pm10_base': random.uniform(20, 60),       # Base PM10 level
                'co2_variance': random.randint(50, 150),   # How much CO2 varies
                'pm_variance': random.uniform(2, 8)        # How much PM varies
            })

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

    def generate_reading(self, device):
        """
        Generate realistic air quality reading for a device

        Args:
            device: Device configuration dict

        Returns:
            Tuple of (co2, pm25, pm10)
        """
        # Simulate natural variations and trends
        co2 = device['co2_base'] + random.uniform(-device['co2_variance'], device['co2_variance'])
        pm25 = device['pm25_base'] + random.uniform(-device['pm_variance'], device['pm_variance'])
        pm10 = device['pm10_base'] + random.uniform(-device['pm_variance'] * 2, device['pm_variance'] * 2)

        # Keep values realistic (no negatives)
        co2 = max(400, co2)
        pm25 = max(0, pm25)
        pm10 = max(0, pm10)

        # Occasionally simulate events (someone enters, opens window, etc.)
        if random.random() < 0.1:  # 10% chance of event
            event_type = random.choice(['spike', 'drop', 'stable'])
            if event_type == 'spike':
                device['co2_base'] = min(1500, device['co2_base'] + random.randint(100, 200))
                device['pm25_base'] = min(50, device['pm25_base'] + random.uniform(5, 15))
            elif event_type == 'drop':
                device['co2_base'] = max(400, device['co2_base'] - random.randint(50, 100))
                device['pm25_base'] = max(5, device['pm25_base'] - random.uniform(2, 8))

        # Slowly drift back to normal
        device['co2_base'] = device['co2_base'] * 0.95 + 600 * 0.05  # Drift toward 600ppm
        device['pm25_base'] = device['pm25_base'] * 0.95 + 10 * 0.05  # Drift toward 10

        return co2, pm25, pm10

    def send_data(self, device_id, co2, pm25, pm10):
        """Send data in the expected format"""
        message = f"LORA DATA START {device_id} {co2:.1f} {pm25:.1f} {pm10:.1f}\n"

        try:
            self.ser.write(message.encode('utf-8'))
            logger.info(f"Sent: {message.strip()}")
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False

    def run(self):
        """Main simulation loop"""
        if not self.connect_serial():
            return

        logger.info(f"Starting simulation with {self.num_devices} devices...")
        logger.info(f"Sending data every {self.interval} seconds")
        logger.info("Press Ctrl+C to stop\n")

        try:
            cycle = 0
            while True:
                cycle += 1
                logger.info(f"--- Cycle {cycle} ---")

                # Send reading from each device
                for device in self.devices:
                    co2, pm25, pm10 = self.generate_reading(device)
                    self.send_data(device['id'], co2, pm25, pm10)

                    # Small delay between devices to simulate network latency
                    time.sleep(0.1)

                # Wait before next cycle
                time.sleep(self.interval)

        except KeyboardInterrupt:
            logger.info("\nStopping simulation...")
        finally:
            self.cleanup()

    def cleanup(self):
        """Close serial connection"""
        if self.ser and self.ser.is_open:
            self.ser.close()
            logger.info("Serial port closed")


def main():
    parser = argparse.ArgumentParser(
        description='Simulate CAT air quality data over UART'
    )
    parser.add_argument(
        'serial_port',
        help='Serial port to write to (e.g., /dev/pts/3)'
    )
    parser.add_argument(
        '-b', '--baud-rate',
        type=int,
        default=115200,
        help='Baud rate (default: 115200)'
    )
    parser.add_argument(
        '-n', '--num-devices',
        type=int,
        default=5,
        help='Number of devices to simulate (default: 5)'
    )
    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=30.0,
        help='Seconds between readings (default: 30.0)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    simulator = AirQualitySimulator(
        serial_port=args.serial_port,
        baud_rate=args.baud_rate,
        num_devices=args.num_devices,
        interval=args.interval
    )

    simulator.run()


if __name__ == '__main__':
    main()
