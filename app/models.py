from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
import string

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relations - CORRIGÉES
    entries = db.relationship('Entry', backref='owner', lazy=True, cascade='all, delete-orphan')
    folders = db.relationship('Folder', backref='owner', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Relations spécifiques pour SharedEntry avec foreign_keys explicites
    shared_entries_received = db.relationship('SharedEntry', foreign_keys='SharedEntry.user_id', backref='recipient', lazy=True, cascade='all, delete-orphan')
    shared_entries_sent = db.relationship('SharedEntry', foreign_keys='SharedEntry.shared_by', backref='sender', lazy=True, cascade='all, delete-orphan')

    def get_encryption_key(self, master_password):
        """Génère une clé de chiffrement à partir du mot de passe maître et du salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    entries = db.relationship('Entry', backref='folder', lazy=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]), lazy=True)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    entry_type = db.Column(db.String(20), nullable=False)  # 'password', 'note', 'file'
    encrypted_data = db.Column(db.Text, nullable=False)
    hmac_signature = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    shared = db.relationship('SharedEntry', backref='entry', lazy=True, cascade='all, delete-orphan')

    def encrypt_data(self, data, encryption_key):
        """Chiffre les données avec AES-256"""
        f = Fernet(encryption_key)
        self.encrypted_data = f.encrypt(data.encode()).decode()
        
        # Génération du HMAC pour l'intégrité
        import hmac
        import hashlib
        self.hmac_signature = hmac.new(
            encryption_key,
            self.encrypted_data.encode(),
            hashlib.sha256
        ).hexdigest()

    def decrypt_data(self, encryption_key):
        """Déchiffre les données"""
        # Vérification de l'intégrité
        import hmac
        import hashlib
        expected_hmac = hmac.new(
            encryption_key,
            self.encrypted_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(expected_hmac, self.hmac_signature):
            raise ValueError("Intégrité des données compromise")
        
        f = Fernet(encryption_key)
        return f.decrypt(self.encrypted_data.encode()).decode()

class SharedEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey('entry.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Qui reçoit le partage
    permission = db.Column(db.String(20), nullable=False)  # 'read', 'write'
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    shared_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Qui fait le partage

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

def generate_password(length=16, include_symbols=True):
    """Génère un mot de passe robuste"""
    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password