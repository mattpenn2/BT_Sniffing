import bluetooth
import time
from datetime import datetime
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class PassiveScanner:
    """
    Passive Bluetooth scanner that discovers devices without connecting.
    Captures device information for later analysis.
    """
    
    def __init__(self, duration: int = 60, lookup_names: bool = True):
        """
        Initialize passive scanner
        
        Args:
            duration: Scan duration in seconds
            lookup_names: Whether to lookup device names (more intrusive)
        """
        self.duration = duration
        self.lookup_names = lookup_names
        self.devices_found = []
        
    def scan(self) -> List[Dict]:
        """
        Perform passive Bluetooth scan
        
        Returns:
            List of discovered devices with metadata
        """
        logger.info(f"Starting passive scan for {self.duration} seconds...")
        
        start_time = time.time()
        scan_count = 0
        
        try:
            while time.time() - start_time < self.duration:
                logger.info(f"Scan iteration {scan_count + 1}...")
                
                # Discover nearby devices
                nearby_devices = bluetooth.discover_devices(
                    duration=8,
                    lookup_names=self.lookup_names,
                    flush_cache=True,
                    lookup_class=True
                )
                
                # Process discovered devices
                for device_info in nearby_devices:
                    if self.lookup_names:
                        addr, name, device_class = device_info
                    else:
                        addr = device_info
                        name = None
                        device_class = None
                    
                    device_data = self._process_device(addr, name, device_class)
                    
                    # Check if device already found
                    if not self._is_duplicate(addr):
                        self.devices_found.append(device_data)
                        logger.info(f"Found new device: {addr} - {name}")
                    else:
                        # Update last seen timestamp
                        self._update_device(addr)
                
                scan_count += 1
                time.sleep(2)  # Small delay between scans
                
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Error during passive scan: {e}")
        
        logger.info(f"Passive scan complete. Found {len(self.devices_found)} unique devices")
        return self.devices_found
    
    def _process_device(self, addr: str, name: Optional[str], 
                       device_class: Optional[int]) -> Dict:
        """Process discovered device and extract metadata"""
        device_data = {
            'mac_address': addr,
            'name': name or "Unknown",
            'device_class': device_class,
            'device_type': None,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'scan_type': 'passive',
            'rssi': None  # RSSI not available in basic inquiry
        }
        
        # Parse device class if available
        if device_class:
            from .bluetooth_utils import BluetoothUtils
            class_info = BluetoothUtils.parse_device_class(device_class)
            device_data['device_type'] = class_info['major_class']
        
        return device_data
    
    def _is_duplicate(self, addr: str) -> bool:
        """Check if device already discovered"""
        return any(d['mac_address'] == addr for d in self.devices_found)
    
    def _update_device(self, addr: str):
        """Update last seen timestamp for existing device"""
        for device in self.devices_found:
            if device['mac_address'] == addr:
                device['last_seen'] = datetime.now().isoformat()
                break
    
    def get_results(self) -> List[Dict]:
        """Get scan results"""
        return self.devices_found
    
    def clear_results(self):
        """Clear stored results"""
        self.devices_found = []
