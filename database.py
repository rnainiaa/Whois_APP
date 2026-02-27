"""
Gestion de la base de données SQLite pour le cache et l'historique
"""
import sqlite3
import json
import secrets
from datetime import datetime, timedelta
from contextlib import contextmanager
import config

class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or config.DATABASE_PATH
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions à la base de données"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def init_db(self):
        """Initialise les tables de la base de données"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table des utilisateurs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    api_key TEXT UNIQUE,
                    abuseipdb_api_key TEXT,
                    virustotal_api_key TEXT,
                    shodan_api_key TEXT,
                    ipqualityscore_api_key TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('PRAGMA table_info(users)')
            existing_columns = {row['name'] for row in cursor.fetchall()}
            missing_columns = {
                'abuseipdb_api_key',
                'virustotal_api_key',
                'shodan_api_key',
                'ipqualityscore_api_key'
            } - existing_columns
            for column in missing_columns:
                cursor.execute(f'ALTER TABLE users ADD COLUMN {column} TEXT')

            # Table pour le cache des résultats WHOIS/IP
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table pour le cache des domaines
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_cache (
                    domain TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table pour l'historique des recherches
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    results_count INTEGER
                )
            ''')
            
            # Table pour les notes et annotations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS annotations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    note TEXT,
                    tags TEXT,
                    severity TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Index pour améliorer les performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_timestamp ON ip_cache(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_timestamp ON domain_cache(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_search_timestamp ON search_history(timestamp)')
    
    def get_cached_ip(self, ip):
        """Récupère les données en cache pour une IP"""
        if not config.ENABLE_CACHE:
            return None
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            expiry_date = datetime.now() - timedelta(days=config.CACHE_EXPIRY_DAYS)
            
            cursor.execute('''
                SELECT data FROM ip_cache 
                WHERE ip = ? AND timestamp > ?
            ''', (ip, expiry_date))
            
            row = cursor.fetchone()
            if row:
                # Mettre à jour last_accessed
                cursor.execute('UPDATE ip_cache SET last_accessed = ? WHERE ip = ?', 
                             (datetime.now(), ip))
                return json.loads(row['data'])
        return None
    
    def cache_ip(self, ip, data):
        """Met en cache les données d'une IP"""
        if not config.ENABLE_CACHE:
            return
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO ip_cache (ip, data, timestamp, last_accessed)
                VALUES (?, ?, ?, ?)
            ''', (ip, json.dumps(data), datetime.now(), datetime.now()))
    
    def get_cached_domain(self, domain):
        """Récupère les données en cache pour un domaine"""
        if not config.ENABLE_CACHE:
            return None
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            expiry_date = datetime.now() - timedelta(days=config.CACHE_EXPIRY_DAYS)
            
            cursor.execute('''
                SELECT data FROM domain_cache 
                WHERE domain = ? AND timestamp > ?
            ''', (domain, expiry_date))
            
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE domain_cache SET last_accessed = ? WHERE domain = ?', 
                             (datetime.now(), domain))
                return json.loads(row['data'])
        return None
    
    def cache_domain(self, domain, data):
        """Met en cache les données d'un domaine"""
        if not config.ENABLE_CACHE:
            return
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO domain_cache (domain, data, timestamp, last_accessed)
                VALUES (?, ?, ?, ?)
            ''', (domain, json.dumps(data), datetime.now(), datetime.now()))
    
    def add_search_history(self, query, query_type, results_count):
        """Ajoute une recherche à l'historique"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO search_history (query, query_type, timestamp, results_count)
                VALUES (?, ?, ?, ?)
            ''', (query, query_type, datetime.now(), results_count))
    
    def get_search_history(self, limit=50):
        """Récupère l'historique des recherches"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM search_history 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def add_annotation(self, target, target_type, note=None, tags=None, severity=None):
        """Ajoute une annotation pour une IP ou un domaine"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO annotations (target, target_type, note, tags, severity, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (target, target_type, note, tags, severity, datetime.now()))
    
    def get_annotations(self, target):
        """Récupère les annotations pour une IP ou un domaine"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM annotations 
                WHERE target = ? 
                ORDER BY timestamp DESC
            ''', (target,))
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_cache(self):
        """Nettoie les entrées de cache expirées"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            expiry_date = datetime.now() - timedelta(days=config.CACHE_EXPIRY_DAYS)
            
            cursor.execute('DELETE FROM ip_cache WHERE timestamp < ?', (expiry_date,))
            cursor.execute('DELETE FROM domain_cache WHERE timestamp < ?', (expiry_date,))
            
            deleted = cursor.rowcount
            return deleted

    # --- Gestion des utilisateurs ---

    def create_user(self, username, email, password_hash):
        """Crée un nouvel utilisateur"""
        api_key = secrets.token_hex(32)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, api_key)
                    VALUES (?, ?, ?, ?)
                ''', (username, email, password_hash, api_key))
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None  # Username ou email déjà pris

    def get_user_by_id(self, user_id):
        """Récupère un utilisateur par son ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email):
        """Récupère un utilisateur par son email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
            
    def get_user_by_api_key(self, api_key):
        """Récupère un utilisateur par sa clé API"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE api_key = ?', (api_key,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_api_key(self, user_id):
        """Génère une nouvelle clé API pour l'utilisateur"""
        new_key = secrets.token_hex(32)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, user_id))
            return new_key

    def update_user_api_keys(self, user_id, abuseipdb_key, virustotal_key, shodan_key, ipqualityscore_key):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE users
                SET abuseipdb_api_key = ?,
                    virustotal_api_key = ?,
                    shodan_api_key = ?,
                    ipqualityscore_api_key = ?
                WHERE id = ?
                ''',
                (abuseipdb_key, virustotal_key, shodan_key, ipqualityscore_key, user_id)
            )

# Instance globale
db = Database()
