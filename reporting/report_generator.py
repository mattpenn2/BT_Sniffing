import json
import csv
import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate reports from scan results in various formats
    """
    
    def __init__(self, output_dir: str = "data/reports"):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save report files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_console_report(self, scan_id: int, devices: List[Dict], 
                               vulnerabilities: Dict[str, List[Dict]]):
        """
        Generate console report
        
        Args:
            scan_id: Scan ID
            devices: List of discovered devices
            vulnerabilities: Dictionary mapping device_id to vulnerabilities
        """
        print("\n" + "="*80)
        print(f"BLUETOOTH SECURITY SCAN REPORT - Scan ID: {scan_id}")
        print("="*80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Devices Found: {len(devices)}")
        print("="*80)
        
        if not devices:
            print("\nNo devices found.")
            return
        
        for i, device in enumerate(devices, 1):
            print(f"\n[Device {i}]")
            print(f"  MAC Address: {device.get('mac_address')}")
            print(f"  Name: {device.get('device_name', 'Unknown')}")
            print(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
            print(f"  Category: {device.get('device_category', 'Unknown')}")
            print(f"  Type: {device.get('device_type', 'Unknown')}")
            print(f"  Fingerprint: {device.get('fingerprint', 'Unknown')}")
            print(f"  First Seen: {device.get('first_seen', 'Unknown')}")
            print(f"  Last Seen: {device.get('last_seen', 'Unknown')}")
            
            # Show vulnerabilities if available
            device_id = str(device.get('device_id', ''))
            if device_id in vulnerabilities:
                vulns = vulnerabilities[device_id]
                print(f"\n  Vulnerabilities Found: {len(vulns)}")
                
                if vulns:
                    # Show top 3 highest risk vulnerabilities
                    top_vulns = sorted(vulns, key=lambda x: x.get('risk_score', 0), reverse=True)[:3]
                    
                    for j, vuln in enumerate(top_vulns, 1):
                        print(f"\n    [{j}] {vuln.get('cve_id')}")
                        print(f"        Severity: {vuln.get('severity', 'UNKNOWN')}")
                        print(f"        CVSS Score: {vuln.get('cvss_score', 'N/A')}")
                        print(f"        Risk Score: {vuln.get('risk_score', 0):.2f}")
                        desc = vuln.get('description', 'No description')
                        print(f"        Description: {desc[:100]}...")
                    
                    if len(vulns) > 3:
                        print(f"\n    ... and {len(vulns) - 3} more vulnerabilities")
            else:
                print(f"\n  Vulnerabilities: Not scanned")
            
            print("\n" + "-"*80)
        
        # Summary statistics
        total_vulns = sum(len(v) for v in vulnerabilities.values())
        critical_count = sum(
            sum(1 for vuln in vulns if vuln.get('severity') == 'CRITICAL')
            for vulns in vulnerabilities.values()
        )
        high_count = sum(
            sum(1 for vuln in vulns if vuln.get('severity') == 'HIGH')
            for vulns in vulnerabilities.values()
        )
        
        print(f"\nSUMMARY:")
        print(f"  Total Devices: {len(devices)}")
        print(f"  Total Vulnerabilities: {total_vulns}")
        print(f"  CRITICAL: {critical_count}")
        print(f"  HIGH: {high_count}")
        print("="*80 + "\n")
    
    def generate_json_report(self, scan_id: int, devices: List[Dict], 
                            vulnerabilities: Dict[str, List[Dict]]) -> str:
        """
        Generate JSON report
        
        Args:
            scan_id: Scan ID
            devices: List of discovered devices
            vulnerabilities: Dictionary mapping device_id to vulnerabilities
            
        Returns:
            Path to generated report file
        """
        report_data = {
            'scan_id': scan_id,
            'generated_at': datetime.now().isoformat(),
            'device_count': len(devices),
            'devices': []
        }
        
        for device in devices:
            device_data = device.copy()
            device_id = str(device.get('device_id', ''))
            
            if device_id in vulnerabilities:
                device_data['vulnerabilities'] = vulnerabilities[device_id]
            else:
                device_data['vulnerabilities'] = []
            
            report_data['devices'].append(device_data)
        
        # Calculate summary
        total_vulns = sum(len(v) for v in vulnerabilities.values())
        report_data['summary'] = {
            'total_devices': len(devices),
            'total_vulnerabilities': total_vulns
        }
        
        # Save to file
        filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report saved to: {filepath}")
        return str(filepath)
    
    def generate_csv_report(self, scan_id: int, devices: List[Dict], 
                           vulnerabilities: Dict[str, List[Dict]]) -> str:
        """
        Generate CSV report
        
        Args:
            scan_id: Scan ID
            devices: List of discovered devices
            vulnerabilities: Dictionary mapping device_id to vulnerabilities
            
        Returns:
            Path to generated report file
        """
        filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='') as f:
            fieldnames = [
                'mac_address', 'device_name', 'manufacturer', 'device_category',
                'device_type', 'fingerprint', 'first_seen', 'last_seen',
                'vulnerability_count', 'critical_count', 'high_count'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in devices:
                device_id = str(device.get('device_id', ''))
                vulns = vulnerabilities.get(device_id, [])
                
                critical_count = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
                high_count = sum(1 for v in vulns if v.get('severity') == 'HIGH')
                
                row = {
                    'mac_address': device.get('mac_address'),
                    'device_name': device.get('device_name', 'Unknown'),
                    'manufacturer': device.get('manufacturer', 'Unknown'),
                    'device_category': device.get('device_category', 'Unknown'),
                    'device_type': device.get('device_type', 'Unknown'),
                    'fingerprint': device.get('fingerprint', 'Unknown'),
                    'first_seen': device.get('first_seen', ''),
                    'last_seen': device.get('last_seen', ''),
                    'vulnerability_count': len(vulns),
                    'critical_count': critical_count,
                    'high_count': high_count
                }
                
                writer.writerow(row)
        
        logger.info(f"CSV report saved to: {filepath}")
        return str(filepath)
    
    def generate_vulnerability_report(self, device_id: int, device_data: Dict, 
                                     vulnerabilities: List[Dict]):
        """
        Generate detailed vulnerability report for a single device
        
        Args:
            device_id: Device ID
            device_data: Device information
            vulnerabilities: List of vulnerabilities
        """
        print("\n" + "="*80)
        print(f"VULNERABILITY REPORT - {device_data.get('mac_address')}")
        print("="*80)
        print(f"Device Name: {device_data.get('device_name', 'Unknown')}")
        print(f"Manufacturer: {device_data.get('manufacturer', 'Unknown')}")
        print(f"Category: {device_data.get('device_category', 'Unknown')}")
        print(f"Total Vulnerabilities: {len(vulnerabilities)}")
        print("="*80)
        
        if not vulnerabilities:
            print("\nNo vulnerabilities found for this device.")
            return
        
        # Sort by risk score
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            print(f"\n[{i}] {vuln.get('cve_id')}")
            print(f"  Severity: {vuln.get('severity', 'UNKNOWN')}")
            print(f"  CVSS Score: {vuln.get('cvss_score', 'N/A')}")
            print(f"  Risk Score: {vuln.get('risk_score', 0):.2f}")
            print(f"  Published: {vuln.get('published_date', 'Unknown')}")
            print(f"  Description: {vuln.get('description', 'No description')}")
            
            references = vuln.get('references', [])
            if references:
                print(f"  References:")
                for ref in references[:3]:  # Show first 3 references
                    print(f"    - {ref.get('url')}")
            
            print("-"*80)

