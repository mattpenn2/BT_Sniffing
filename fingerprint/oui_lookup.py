import os
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class OUILookup:
    """
    Lookup manufacturer information from MAC address OUI.
    Uses IEEE OUI database.
    """
    
    def __init__(self, oui_file: str = "data/oui.txt"):
        """
        Initialize OUI lookup
        
        Args:
            oui_file: Path to OUI database file
        """
        self.oui_file = oui_file
        self.oui_dict = {}
        self._load_oui_database()
    
    def _load_oui_database(self):
        """Load OUI database from file"""
        if not os.path.exists(self.oui_file):
            logger.warning(f"OUI database file not found: {self.oui_file}")
            logger.info("You can download it from: https://standards-oui.ieee.org/oui/oui.txt")
            return
        
        try:
            with open(self.oui_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # OUI format: "XX-XX-XX   (hex)		Manufacturer Name"
                    if '(hex)' in line:
                        parts = line.split('(hex)')
                        if len(parts) >= 2:
                            oui = parts[0].strip().replace('-', ':')
                            manufacturer = parts[1].strip()
                            self.oui_dict[oui] = manufacturer
            
            logger.info(f"Loaded {len(self.oui_dict)} OUI entries")
        except Exception as e:
            logger.error(f"Error loading OUI database: {e}")
    
    def lookup(self, mac_address: str) -> Optional[str]:
        """
        Look up manufacturer from MAC address
        
        Args:
            mac_address: MAC address (XX:XX:XX:XX:XX:XX format)
            
        Returns:
            Manufacturer name or None if not found
        """
        if not mac_address:
            return None
        
        # Extract first 3 octets (OUI)
        oui = ':'.join(mac_address.upper().split(':')[:3])
        
        manufacturer = self.oui_dict.get(oui)
        
        if manufacturer:
            logger.debug(f"Found manufacturer for {mac_address}: {manufacturer}")
        else:
            logger.debug(f"No manufacturer found for OUI: {oui}")
        
        return manufacturer
    
    def get_vendor_info(self, mac_address: str) -> Dict[str, str]:
        """
        Get detailed vendor information
        
        Args:
            mac_address: MAC address
            
        Returns:
            Dictionary with OUI and manufacturer info
        """
        oui = ':'.join(mac_address.upper().split(':')[:3])
        manufacturer = self.lookup(mac_address)
        
        return {
            'oui': oui,
            'manufacturer': manufacturer or "Unknown",
            'mac_address': mac_address
        }
