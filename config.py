import os
from pathlib import Path

# Project directories
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"

# Database settings
DB_PATH = DATA_DIR / "scans.db"

# OUI database
OUI_FILE = DATA_DIR / "oui.txt"
OUI_DOWNLOAD_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# Vulnerability cache
VULN_CACHE_DIR = DATA_DIR / "vulnerability_cache"

# NVD API settings
NVD_API_KEY = os.environ.get('NVD_API_KEY', None)  # Optional: set via environment variable
NVD_CACHE_DAYS = 7  # Days to cache vulnerability data

# Scanner settings
DEFAULT_PASSIVE_DURATION = 60  # seconds
DEFAULT_ACTIVE_TIMEOUT = 10  # seconds
LOOKUP_DEVICE_NAMES = True

# Logging settings
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE = LOG_DIR / "bluetooth_scanner.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Reporting settings
REPORT_OUTPUT_DIR = DATA_DIR / "reports"
DEFAULT_REPORT_FORMAT = "console"  # console, json, csv

# Ensure directories exist
for directory in [DATA_DIR, LOG_DIR, VULN_CACHE_DIR, REPORT_OUTPUT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
