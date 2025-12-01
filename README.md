# BT_Sniffing
## Project Layout

├── README.md
├── requirements.txt
├── config.py                    # Configuration settings
│
├── scanner/
│   ├── __init__.py
│   ├── passive_scan.py          # Passive scanning mode
│   ├── active_scan.py           # Active scanning mode
│   └── bluetooth_utils.py       # Helper functions
│
├── fingerprint/
│   ├── __init__.py
│   ├── device_identifier.py     # Identify device type/version
│   └── oui_lookup.py            # MAC address vendor lookup
│
├── database/
│   ├── __init__.py
│   ├── db_handler.py            # SQLite database operations
│   └── schema.sql               # Database schema
│
├── vulnerability/
│   ├── __init__.py
│   ├── nvd_client.py            # Fetch CVE data from NVD
│   └── vuln_mapper.py           # Map devices to vulnerabilities
│
├── reporting/
│   ├── __init__.py
│   └── report_generator.py      # Generate scan reports
│
├── main.py                      # Main CLI entry point
│
├── data/
│   ├── oui.txt                  # MAC vendor database
│   └── scans.db                 # SQLite database (created at runtime)
│
└── tests/
    └── test_basic.py            # Basic tests
