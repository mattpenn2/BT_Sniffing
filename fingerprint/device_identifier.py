import re
import logging
from typing import Dict, Optional, List
from .oui_lookup import OUILookup

logger = logging.getLogger(__name__)


class DeviceIdentifier:
    """
    Identifies device type and infers version information
    from Bluetooth metadata and service characteristics.
    """
    
    def __init__(self):
        """Initialize device identifier"""
        self.oui_lookup = OUILookup()
        
        # Known device patterns for fingerprinting
        self.device_patterns = self._load_device_patterns()
    
    def _load_device_patterns(self) -> Dict:
        """
        Load known device patterns for identification
        These patterns help identify specific device types and versions
        """
        return {
            'apple': {
                'patterns': ['iPhone', 'iPad', 'MacBook', 'AirPods', 'Apple Watch'],
                'services': ['com.apple.', 'continuity'],
                'manufacturer_keywords': ['Apple']
            },
            'android': {
                'patterns': ['Android', 'Samsung', 'Google Pixel', 'OnePlus'],
                'services': ['android'],
                'manufacturer_keywords': ['Samsung', 'Google', 'LG', 'Motorola']
            },
            'windows': {
                'patterns': ['DESKTOP-', 'LAPTOP-'],
                'manufacturer_keywords': ['Microsoft', 'Dell', 'HP', 'Lenovo']
            },
            'iot': {
                'patterns': ['Smart', 'Echo', 'Alexa', 'Google Home', 'Hub'],
                'services': [],
                'manufacturer_keywords': ['Amazon', 'Google', 'Philips', 'TP-Link']
            },
            'audio': {
                'patterns': ['Speaker', 'Headphones', 'Earbuds', 'Soundbar'],
                'services': ['audio', 'a2dp', 'avrcp'],
                'device_classes': ['Audio/Video']
            },
            'wearable': {
                'patterns': ['Watch', 'Band', 'Tracker', 'Fitbit', 'Garmin'],
                'device_classes': ['Wearable']
            }
        }
    
    def identify(self, device_data: Dict) -> Dict:
        """
        Identify device and infer version information
        
        Args:
            device_data: Device information from scanner
            
        Returns:
            Enhanced device data with identification and confidence scores
        """
        result = device_data.copy()
        
        # Get manufacturer from OUI
        manufacturer = self.oui_lookup.lookup(device_data.get('mac_address', ''))
        result['manufacturer'] = manufacturer
        
        # Identify device category
        device_category = self._identify_category(device_data, manufacturer)
        result['device_category'] = device_category
        
        # Infer version
        version_info = self._infer_version(device_data, manufacturer, device_category)
        result['version_info'] = version_info
        
        # Calculate confidence score
        confidence = self._calculate_confidence(device_data, manufacturer, version_info)
        result['confidence_score'] = confidence
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(device_data, manufacturer, device_category)
        result['fingerprint'] = fingerprint
        
        return result
    
    def _identify_category(self, device_data: Dict, manufacturer: Optional[str]) -> str:
        """
        Identify device category based on available data
        
        Args:
            device_data: Device information
            manufacturer: Manufacturer name
            
        Returns:
            Device category string
        """
        device_name = device_data.get('name', '').lower()
        device_type = device_data.get('device_type', '').lower()
        services = device_data.get('services', [])
        
        # Check device type from class
        if device_type:
            if 'phone' in device_type:
                return 'smartphone'
            elif 'computer' in device_type:
                return 'computer'
            elif 'audio' in device_type:
                return 'audio_device'
            elif 'wearable' in device_type:
                return 'wearable'
        
        # Check name patterns
        for category, patterns in self.device_patterns.items():
            # Check name patterns
            if any(pattern.lower() in device_name for pattern in patterns.get('patterns', [])):
                return category
            
            # Check manufacturer
            if manufacturer and any(kw in manufacturer for kw in patterns.get('manufacturer_keywords', [])):
                return category
            
            # Check services
            service_names = [s.get('name', '').lower() for s in services]
            if any(pattern in ' '.join(service_names) for pattern in patterns.get('services', [])):
                return category
        
        return 'unknown'
    
    def _infer_version(self, device_data: Dict, manufacturer: Optional[str], 
                      category: str) -> Dict:
        """
        Infer device version information
        
        Args:
            device_data: Device information
            manufacturer: Manufacturer name
            category: Device category
            
        Returns:
            Dictionary with version information
        """
        version_info = {
            'bluetooth_version': self._infer_bluetooth_version(device_data),
            'os_version': 'Unknown',
            'hardware_version': 'Unknown',
            'firmware_version': 'Unknown'
        }
        
        # Try to extract version from device name
        device_name = device_data.get('name', '')
        
        # Look for version patterns in name
        version_patterns = [
            r'v?(\d+\.?\d*\.?\d*)',  # v1.0, 1.2.3, etc.
            r'(\d{1,2}(?:th|nd|rd|st)?\s+Gen)',  # 5th Gen, 2nd Gen
            r'(20\d{2})',  # Year like 2023
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, device_name, re.IGNORECASE)
            if match:
                version_info['hardware_version'] = match.group(1)
                break
        
        # Infer OS version based on category and manufacturer
        if category == 'smartphone' or category == 'android':
            version_info['os_version'] = 'Android (Unknown Version)'
        elif category == 'apple' and 'iphone' in device_name.lower():
            version_info['os_version'] = 'iOS (Unknown Version)'
        elif category == 'computer':
            if manufacturer and 'apple' in manufacturer.lower():
                version_info['os_version'] = 'macOS (Unknown Version)'
            else:
                version_info['os_version'] = 'Windows/Linux (Unknown Version)'
        
        return version_info
    
    def _infer_bluetooth_version(self, device_data: Dict) -> str:
        """
        Infer Bluetooth version from device characteristics
        
        Args:
            device_data: Device information
            
        Returns:
            Bluetooth version string
        """
        services = device_data.get('services', [])
        
        # Check for BLE characteristics (Bluetooth 4.0+)
        service_ids = [s.get('service_id', '') for s in services]
        
        # If device has many GATT services, likely BLE (4.0+)
        if any('0000' in sid for sid in service_ids):
            return 'Bluetooth 4.0+ (BLE)'
        
        # Check for specific service profiles that indicate version
        service_names = [s.get('name', '').lower() for s in services]
        
        if any('hid' in name for name in service_names):
            return 'Bluetooth 2.1+ (HID supported)'
        
        if any('a2dp' in name or 'audio' in name for name in service_names):
            return 'Bluetooth 2.0+ (A2DP supported)'
        
        return 'Bluetooth Classic (Unknown Version)'
    
    def _calculate_confidence(self, device_data: Dict, manufacturer: Optional[str], 
                             version_info: Dict) -> float:
        """
        Calculate confidence score for identification
        
        Args:
            device_data: Device information
            manufacturer: Manufacturer name
            version_info: Version information
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        score = 0.0
        
        # Has manufacturer: +0.3
        if manufacturer and manufacturer != "Unknown":
            score += 0.3
        
        # Has device name: +0.2
        if device_data.get('name') and device_data.get('name') != "Unknown":
            score += 0.2
        
        # Has services (active scan): +0.3
        services = device_data.get('services', [])
        if services:
            score += 0.3
        
        # Has device class: +0.1
        if device_data.get('device_type'):
            score += 0.1
        
        # Has version info: +0.1
        if version_info['hardware_version'] != 'Unknown':
            score += 0.1
        
        return min(score, 1.0)
    
    def _generate_fingerprint(self, device_data: Dict, manufacturer: Optional[str], 
                             category: str) -> str:
        """
        Generate unique fingerprint for device
        
        Args:
            device_data: Device information
            manufacturer: Manufacturer name
            category: Device category
            
        Returns:
            Fingerprint string
        """
        components = [
            manufacturer or "unknown_manufacturer",
            category,
            device_data.get('device_type', 'unknown_type'),
            str(len(device_data.get('services', [])))
        ]
        
        return '_'.join(components).replace(' ', '_').lower()
