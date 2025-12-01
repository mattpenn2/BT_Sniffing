import bluetooth
from datetime import datetime
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class ActiveScanner:
    """
    Active Bluetooth scanner that connects to devices and performs
    service discovery to gather detailed information.
    """
    
    def __init__(self, target_devices: Optional[List[str]] = None):
        """
        Initialize active scanner
        
        Args:
            target_devices: List of MAC addresses to scan. If None, scans all discovered devices
        """
        self.target_devices = target_devices
        self.scan_results = []
        
    def scan(self, discover_first: bool = True) -> List[Dict]:
        """
        Perform active scan on target devices
        
        Args:
            discover_first: If True and no targets specified, discover devices first
            
        Returns:
            List of devices with detailed service information
        """
        logger.info("Starting active scan...")
        
        # If no targets specified, discover devices first
        if not self.target_devices and discover_first:
            logger.info("No targets specified, discovering devices first...")
            discovered = bluetooth.discover_devices(duration=8, lookup_names=False)
            self.target_devices = discovered
            logger.info(f"Found {len(discovered)} devices to scan")
        
        if not self.target_devices:
            logger.warning("No devices to scan")
            return []
        
        # Scan each target device
        for addr in self.target_devices:
            logger.info(f"Actively scanning {addr}...")
            device_data = self._scan_device(addr)
            if device_data:
                self.scan_results.append(device_data)
        
        logger.info(f"Active scan complete. Scanned {len(self.scan_results)} devices")
        return self.scan_results
    
    def _scan_device(self, addr: str) -> Optional[Dict]:
        """
        Perform active scan on a single device
        
        Args:
            addr: MAC address of target device
            
        Returns:
            Dictionary with device information and services
        """
        device_data = {
            'mac_address': addr,
            'name': None,
            'services': [],
            'scan_type': 'active',
            'timestamp': datetime.now().isoformat(),
            'connection_successful': False
        }
        
        try:
            # Lookup device name
            device_data['name'] = bluetooth.lookup_name(addr, timeout=10)
            logger.info(f"Device name: {device_data['name']}")
            
            # Discover services
            logger.info(f"Discovering services on {addr}...")
            services = bluetooth.find_service(address=addr)
            
            device_data['connection_successful'] = True
            device_data['service_count'] = len(services)
            
            # Process each service
            for service in services:
                service_info = {
                    'name': service.get('name', 'Unknown'),
                    'description': service.get('description', ''),
                    'provider': service.get('provider', ''),
                    'protocol': service.get('protocol', ''),
                    'port': service.get('port', None),
                    'service_classes': service.get('service-classes', []),
                    'profiles': service.get('profiles', []),
                    'service_id': service.get('service-id', '')
                }
                device_data['services'].append(service_info)
                logger.info(f"  Service: {service_info['name']} - {service_info['protocol']}")
            
            # Attempt to get additional device info
            device_data['device_info'] = self._get_device_info(addr)
            
        except bluetooth.BluetoothError as e:
            logger.warning(f"Bluetooth error scanning {addr}: {e}")
            device_data['error'] = str(e)
        except Exception as e:
            logger.error(f"Unexpected error scanning {addr}: {e}")
            device_data['error'] = str(e)
        
        return device_data
    
    def _get_device_info(self, addr: str) -> Dict:
        """
        Attempt to gather additional device information
        
        Args:
            addr: MAC address of device
            
        Returns:
            Dictionary with additional device info
        """
        info = {}
        
        try:
            # Try to get device class
            # Note: This requires special permissions and may not always work
            info['manufacturer'] = "Unknown"
            info['device_version'] = "Unknown"
            
        except Exception as e:
            logger.debug(f"Could not get additional info for {addr}: {e}")
        
        return info
    
    def scan_specific_device(self, addr: str) -> Optional[Dict]:
        """
        Scan a specific device
        
        Args:
            addr: MAC address of device to scan
            
        Returns:
            Device information dictionary
        """
        logger.info(f"Scanning specific device: {addr}")
        return self._scan_device(addr)
    
    def get_results(self) -> List[Dict]:
        """Get scan results"""
        return self.scan_results
    
    def clear_results(self):
        """Clear stored results"""
        self.scan_results = []
