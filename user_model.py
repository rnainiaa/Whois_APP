from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

class User(UserMixin):
    def __init__(
        self,
        id,
        username,
        email,
        password_hash,
        api_key=None,
        abuseipdb_api_key=None,
        virustotal_api_key=None,
        shodan_api_key=None,
        ipqualityscore_api_key=None,
        created_at=None
    ):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.api_key = api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.virustotal_api_key = virustotal_api_key
        self.shodan_api_key = shodan_api_key
        self.ipqualityscore_api_key = ipqualityscore_api_key
        self.created_at = created_at

    @staticmethod
    def get(user_id):
        data = db.get_user_by_id(user_id)
        if data:
            return User(**data)
        return None

    @staticmethod
    def get_by_email(email):
        data = db.get_user_by_email(email)
        if data:
            return User(**data)
        return None

    @staticmethod
    def create(username, email, password):
        password_hash = generate_password_hash(password)
        user_id = db.create_user(username, email, password_hash)
        if user_id:
            return User.get(user_id)
        return None

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def regenerate_api_key(self):
        self.api_key = db.update_api_key(self.id)
        return self.api_key

    def update_api_keys(self, abuseipdb_key, virustotal_key, shodan_key, ipqualityscore_key):
        db.update_user_api_keys(self.id, abuseipdb_key, virustotal_key, shodan_key, ipqualityscore_key)
        self.abuseipdb_api_key = abuseipdb_key
        self.virustotal_api_key = virustotal_key
        self.shodan_api_key = shodan_key
        self.ipqualityscore_api_key = ipqualityscore_key
