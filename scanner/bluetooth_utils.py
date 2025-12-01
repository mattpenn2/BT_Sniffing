import bluetooth
import subprocess
import re
from typing import List, Dict, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BluetoothUtils:
    """Helper functions for Bluetooth operations"""
    
    @staticmethod
    def is_bluetooth_enabled() -> bool:
        """Check if Bluetooth is enabled on the system"""
        try:
            result = subprocess.run(['hciconfig'], capture_output=True, text=True)
            return 'UP RUNNING' in result.stdout
        except Exception as e:
            logger.error(f"Error checking Bluetooth status: {e}")
            return False
    
    @staticmethod
    def enable_bluetooth():
        """Enable Bluetooth adapter"""
        try:
            subprocess.run(['sudo', 'hciconfig', 'hci0', 'up'], check=True)
            logger.info("Bluetooth adapter enabled")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable Bluetooth: {e}")
            raise
    
    @staticmethod
    def get_local_address() -> Optional[str]:
        """Get the local Bluetooth adapter MAC address"""
        try:
            result = subprocess.run(['hciconfig'], capture_output=True, text=True)
            match = re.search(r'BD Address: ([0-9A-F:]{17})', result.stdout)
            if match:
                return match.group(1)
            return None
        except Exception as e:
            logger.error(f"Error getting local address: {e}")
            return None
    
    @staticmethod
    def parse_device_class(device_class: int) -> Dict[str, str]:
        """Parse Bluetooth device class to determine device type"""
        # Major device classes
        major_classes = {
            0x00: "Miscellaneous",
            0x01: "Computer",
            0x02: "Phone",
            0x03: "LAN/Network Access Point",
            0x04: "Audio/Video",
            0x05: "Peripheral",
            0x06: "Imaging",
            0x07: "Wearable",
            0x08: "Toy",
            0x09: "Health"
        }
        
        major = (device_class >> 8) & 0x1F
        minor = (device_class >> 2) & 0x3F
        
        return {
            "major_class": major_classes.get(major, "Unknown"),
            "device_class_raw": hex(device_class)
        }
    
    @staticmethod
    def format_mac(mac: str) -> str:
        """Format MAC address to standard format"""
        mac = mac.upper().replace('-', ':')
        return mac
    
    @staticmethod
    def get_manufacturer_from_oui(mac: str) -> Optional[str]:
        """Get manufacturer from MAC address OUI (first 3 octets)"""
        # This is a placeholder - you'll need to implement OUI lookup
        # against the oui.txt file in the data/ directory
        oui = mac[:8].upper()
        # TODO: Implement actual OUI lookup from file
        return f"OUI:{oui}"
