"""
Configuration centralisée pour l'application WHOIS
"""
import os
from pathlib import Path

# Répertoire de base
BASE_DIR = Path(__file__).parent

# Configuration Flask
FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.environ.get('FLASK_PORT', 5010))
FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

# Base de données
DATABASE_PATH = BASE_DIR / 'whois_cache.db'
CACHE_EXPIRY_DAYS = 7  # Durée de validité du cache en jours

# GeoLite2
GEOLITE_DB = str(BASE_DIR / 'GeoLite2-City.mmdb')

# Timeouts et limites
REQUEST_TIMEOUT = 10  # secondes
MAX_CONCURRENT_REQUESTS = 10
MAX_IPS_PER_BATCH = 1000

# Cache
ENABLE_CACHE = True
CACHE_TYPE = 'database'  # 'database' ou 'redis'
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

# Export
EXPORT_FORMATS = ['csv', 'json', 'pdf', 'html']
TEMP_EXPORT_DIR = BASE_DIR / 'exports'
TEMP_EXPORT_DIR.mkdir(exist_ok=True)

# Logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = BASE_DIR / 'app.log'
