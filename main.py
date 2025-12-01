import sys
import logging
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from scanner import PassiveScanner, ActiveScanner
from fingerprint import DeviceIdentifier
from database import DatabaseHandler
from vulnerability import VulnerabilityMapper
from reporting import ReportGenerator

# Setup logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def passive_scan(args):
    """Run passive scan"""
    logger.info("Starting passive scan...")
    
    # Initialize components
    scanner = PassiveScanner(duration=args.duration, lookup_names=args.lookup_names)
    identifier = DeviceIdentifier()
    db = DatabaseHandler(str(config.DB_PATH))
    
    # Create scan entry
    scan_id = db.create_scan('passive', notes=args.notes)
    
    # Run scan
    print(f"\nStarting passive scan for {args.duration} seconds...")
    print("Press Ctrl+C to stop early\n")
    
    devices = scanner.scan()
    
    # Process and store results
    print(f"\nProcessing {len(devices)} devices...")
    
    for device in devices:
        # Fingerprint device
        enhanced_data = identifier.identify(device)
        
        # Store in database
        device_id = db.add_device(enhanced_data)
        db.add_scan_result(scan_id, device_id, enhanced_data, 
                          enhanced_data.get('confidence_score'))
    
    # Update scan
    db.update_scan(scan_id, len(devices))
    
    print(f"\nScan complete! Scan ID: {scan_id}")
    print(f"Found {len(devices)} devices")
    
    # Generate report if requested
    if args.report:
        generate_report(scan_id, db, args.report_format, args.vuln_scan)
    
    db.close()


def active_scan(args):
    """Run active scan"""
    logger.info("Starting active scan...")
    
    # Initialize components
    scanner = ActiveScanner()
    identifier = DeviceIdentifier()
    db = DatabaseHandler(str(config.DB_PATH))
    
    # Create scan entry
    scan_id = db.create_scan('active', notes=args.notes)
    
    # Run scan
    print("\nStarting active scan...")
    print("This may take several minutes...\n")
    
    devices = scanner.scan(discover_first=True)
    
    # Process and store results
    print(f"\nProcessing {len(devices)} devices...")
    
    for device in devices:
        # Fingerprint device
        enhanced_data = identifier.identify(device)
        
        # Store in database
        device_id = db.add_device(enhanced_data)
        db.add_scan_result(scan_id, device_id, enhanced_data,
                          enhanced_data.get('confidence_score'))
        
        # Store services
        services = device.get('services', [])
        if services:
            db.add_services(device_id, services)
    
    # Update scan
    db.update_scan(scan_id, len(devices))
    
    print(f"\nScan complete! Scan ID: {scan_id}")
    print(f"Found {len(devices)} devices")
    
    # Generate report if requested
    if args.report:
        generate_report(scan_id, db, args.report_format, args.vuln_scan)
    
    db.close()


def list_scans(args):
    """List all scans"""
    db = DatabaseHandler(str(config.DB_PATH))
    scans = db.get_all_scans()
    
    if not scans:
        print("\nNo scans found.")
        db.close()
        return
    
    print(f"\nFound {len(scans)} scans:\n")
    print(f"{'ID':<5} {'Type':<10} {'Start Time':<20} {'Devices':<10}")
    print("-" * 50)
    
    for scan in scans:
        print(f"{scan['scan_id']:<5} {scan['scan_type']:<10} "
              f"{scan['start_time'][:19]:<20} {scan['device_count']:<10}")
    
    print()
    db.close()


def list_devices(args):
    """List all devices"""
    db = DatabaseHandler(str(config.DB_PATH))
    devices = db.get_all_devices()
    
    if not devices:
        print("\nNo devices found.")
        db.close()
        return
    
    print(f"\nFound {len(devices)} devices:\n")
    
    for device in devices:
        print(f"MAC: {device['mac_address']}")
        print(f"  Name: {device['device_name']}")
        print(f"  Manufacturer: {device['manufacturer']}")
        print(f"  Category: {device['device_category']}")
        print(f"  Last Seen: {device['last_seen']}")
        print()
    
    db.close()


def generate_report(scan_id, db, report_format='console', include_vulns=False):
    """Generate report for a scan"""
    # Get scan results
    devices = []
    scan_results = db.get_scan_results(scan_id)
    
    for result in scan_results:
        device = db.get_device_by_mac(result['mac_address'])
        if device:
            devices.append(device)
    
    # Get vulnerabilities if requested
    vulnerabilities = {}
    if include_vulns:
        print("\nScanning for vulnerabilities...")
        mapper = VulnerabilityMapper()
        
        for device in devices:
            device_id = str(device['device_id'])
            vulns = mapper.map_device_to_vulnerabilities(device)
            vulnerabilities[device_id] = vulns
            
            # Store in database
            for vuln in vulns:
                db.connection.execute('''
                    INSERT INTO vulnerabilities 
                    (device_id, cve_id, severity, description, published_date, cvss_score)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    device['device_id'],
                    vuln.get('cve_id'),
                    vuln.get('severity'),
                    vuln.get('description'),
                    vuln.get('published_date'),
                    vuln.get('cvss_score')
                ))
        
        db.connection.commit()
    
    # Generate report
    reporter = ReportGenerator(str(config.REPORT_OUTPUT_DIR))
    
    if report_format == 'console':
        reporter.generate_console_report(scan_id, devices, vulnerabilities)
    elif report_format == 'json':
        filepath = reporter.generate_json_report(scan_id, devices, vulnerabilities)
        print(f"\nReport saved to: {filepath}")
    elif report_format == 'csv':
        filepath = reporter.generate_csv_report(scan_id, devices, vulnerabilities)
        print(f"\nReport saved to: {filepath}")


def report_command(args):
    """Generate report from existing scan"""
    db = DatabaseHandler(str(config.DB_PATH))
    generate_report(args.scan_id, db, args.format, args.vulnerabilities)
    db.close()


def update_vulnerabilities(args):
    """Update vulnerability database"""
    print("\nUpdating vulnerability database...")
    mapper = VulnerabilityMapper()
    mapper.update_vulnerability_database()
    print("Update complete!")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Bluetooth Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Passive scan command
    passive_parser = subparsers.add_parser('passive', help='Run passive scan')
    passive_parser.add_argument('-d', '--duration', type=int, default=60,
                               help='Scan duration in seconds (default: 60)')
    passive_parser.add_argument('-n', '--notes', help='Scan notes')
    passive_parser.add_argument('--no-lookup-names', dest='lookup_names',
                               action='store_false', help='Don\'t lookup device names')
    passive_parser.add_argument('-r', '--report', action='store_true',
                               help='Generate report after scan')
    passive_parser.add_argument('--report-format', choices=['console', 'json', 'csv'],
                               default='console', help='Report format')
    passive_parser.add_argument('--vuln-scan', action='store_true',
                               help='Scan for vulnerabilities')
    passive_parser.set_defaults(func=passive_scan)
    
    # Active scan command
    active_parser = subparsers.add_parser('active', help='Run active scan')
    active_parser.add_argument('-n', '--notes', help='Scan notes')
    active_parser.add_argument('-r', '--report', action='store_true',
                              help='Generate report after scan')
    active_parser.add_argument('--report-format', choices=['console', 'json', 'csv'],
                              default='console', help='Report format')
    active_parser.add_argument('--vuln-scan', action='store_true',
                              help='Scan for vulnerabilities')
    active_parser.set_defaults(func=active_scan)
    
    # List scans command
    list_scans_parser = subparsers.add_parser('list-scans', help='List all scans')
    list_scans_parser.set_defaults(func=list_scans)
    
    # List devices command
    list_devices_parser = subparsers.add_parser('list-devices', help='List all devices')
    list_devices_parser.set_defaults(func=list_devices)
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from scan')
    report_parser.add_argument('scan_id', type=int, help='Scan ID')
    report_parser.add_argument('-f', '--format', choices=['console', 'json', 'csv'],
                              default='console', help='Report format')
    report_parser.add_argument('-v', '--vulnerabilities', action='store_true',
                              help='Include vulnerability scan')
    report_parser.set_defaults(func=report_command)
    
    # Update vulnerabilities command
    update_parser = subparsers.add_parser('update-vulns',
                                         help='Update vulnerability database')
    update_parser.set_defaults(func=update_vulnerabilities)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Run command
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
