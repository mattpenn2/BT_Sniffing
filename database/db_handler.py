import sqlite3
import json
import logging
from typing import List, Dict, Optional
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class DatabaseHandler:
    """
    Handles all database operations for storing and retrieving
    Bluetooth scan data and vulnerability information.
    """
    
    def __init__(self, db_path: str = "data/scans.db"):
        """
        Initialize database handler
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._ensure_data_directory()
        self.connection = None
        self._initialize_database()
    
    def _ensure_data_directory(self):
        """Create data directory if it doesn't exist"""
        directory = os.path.dirname(self.db_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created data directory: {directory}")
    
    def _initialize_database(self):
        """Initialize database and create tables if they don't exist"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row  # Return rows as dictionaries
        
        cursor = self.connection.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                device_count INTEGER DEFAULT 0,
                notes TEXT
            )
        ''')
        
        # Create devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                device_name TEXT,
                manufacturer TEXT,
                device_category TEXT,
                device_type TEXT,
                fingerprint TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        ''')
        
        # Create scan_results table (links scans to devices)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                raw_data TEXT,
                confidence_score REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        ''')
        
        # Create services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                service_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                service_name TEXT,
                protocol TEXT,
                port INTEGER,
                service_data TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                published_date TEXT,
                cvss_score REAL,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        ''')
        
        self.connection.commit()
        logger.info("Database initialized successfully")
    
    def create_scan(self, scan_type: str, notes: str = None) -> int:
        """
        Create a new scan entry
        
        Args:
            scan_type: Type of scan (passive/active)
            notes: Optional notes about the scan
            
        Returns:
            Scan ID
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO scans (scan_type, start_time, notes)
            VALUES (?, ?, ?)
        ''', (scan_type, datetime.now().isoformat(), notes))
        
        self.connection.commit()
        scan_id = cursor.lastrowid
        logger.info(f"Created scan {scan_id} - Type: {scan_type}")
        return scan_id
    
    def update_scan(self, scan_id: int, device_count: int):
        """
        Update scan with end time and device count
        
        Args:
            scan_id: Scan ID to update
            device_count: Number of devices found
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            UPDATE scans 
            SET end_time = ?, device_count = ?
            WHERE scan_id = ?
        ''', (datetime.now().isoformat(), device_count, scan_id))
        
        self.connection.commit()
        logger.info(f"Updated scan {scan_id} - Found {device_count} devices")
    
    def add_device(self, device_data: Dict) -> int:
        """
        Add or update device in database
        
        Args:
            device_data: Device information dictionary
            
        Returns:
            Device ID
        """
        cursor = self.connection.cursor()
        
        mac_address = device_data['mac_address']
        
        # Check if device already exists
        cursor.execute('SELECT device_id FROM devices WHERE mac_address = ?', (mac_address,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing device
            device_id = existing['device_id']
            cursor.execute('''
                UPDATE devices 
                SET device_name = ?, manufacturer = ?, device_category = ?,
                    device_type = ?, fingerprint = ?, last_seen = ?
                WHERE device_id = ?
            ''', (
                device_data.get('name'),
                device_data.get('manufacturer'),
                device_data.get('device_category'),
                device_data.get('device_type'),
                device_data.get('fingerprint'),
                datetime.now().isoformat(),
                device_id
            ))
            logger.debug(f"Updated device {device_id} - {mac_address}")
        else:
            # Insert new device
            cursor.execute('''
                INSERT INTO devices (mac_address, device_name, manufacturer, device_category,
                                   device_type, fingerprint, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mac_address,
                device_data.get('name'),
                device_data.get('manufacturer'),
                device_data.get('device_category'),
                device_data.get('device_type'),
                device_data.get('fingerprint'),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            device_id = cursor.lastrowid
            logger.info(f"Added new device {device_id} - {mac_address}")
        
        self.connection.commit()
        return device_id
    
    def add_scan_result(self, scan_id: int, device_id: int, raw_data: Dict, 
                       confidence_score: float = None):
        """
        Link a device to a scan with result data
        
        Args:
            scan_id: Scan ID
            device_id: Device ID
            raw_data: Raw scan data
            confidence_score: Confidence score for identification
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO scan_results (scan_id, device_id, raw_data, confidence_score)
            VALUES (?, ?, ?, ?)
        ''', (scan_id, device_id, json.dumps(raw_data), confidence_score))
        
        self.connection.commit()
    
    def add_services(self, device_id: int, services: List[Dict]):
        """
        Add services for a device
        
        Args:
            device_id: Device ID
            services: List of service dictionaries
        """
        cursor = self.connection.cursor()
        
        for service in services:
            cursor.execute('''
                INSERT INTO services (device_id, service_name, protocol, port, service_data)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                device_id,
                service.get('name'),
                service.get('protocol'),
                service.get('port'),
                json.dumps(service)
            ))
        
        self.connection.commit()
        logger.debug(f"Added {len(services)} services for device {device_id}")
    
    def get_all_devices(self) -> List[Dict]:
        """
        Get all devices from database
        
        Returns:
            List of device dictionaries
        """
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict]:
        """
        Get device by MAC address
        
        Args:
            mac_address: MAC address to look up
            
        Returns:
            Device dictionary or None
        """
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM devices WHERE mac_address = ?', (mac_address,))
        
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_scan_results(self, scan_id: int) -> List[Dict]:
        """
        Get all results for a specific scan
        
        Args:
            scan_id: Scan ID
            
        Returns:
            List of result dictionaries with device info
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT sr.*, d.mac_address, d.device_name, d.manufacturer, d.device_category
            FROM scan_results sr
            JOIN devices d ON sr.device_id = d.device_id
            WHERE sr.scan_id = ?
        ''', (scan_id,))
        
        rows = cursor.fetchall()
        results = []
        for row in rows:
            result = dict(row)
            if result['raw_data']:
                result['raw_data'] = json.loads(result['raw_data'])
            results.append(result)
        
        return results
    
    def get_all_scans(self) -> List[Dict]:
        """
        Get all scans from database
        
        Returns:
            List of scan dictionaries
        """
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY start_time DESC')
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
