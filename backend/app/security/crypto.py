import base64
import bcrypt
from cryptography.fernet import Fernet
from app.config import settings

def _get_fernet() -> Fernet:
    """Return Fernet cipher using configured key or a derived valid 32-byte urlsafe base64 key."""
    raw_key = settings.ENCRYPTION_KEY.strip()
    try:
        # Check if already valid 32-byte urlsafe base64
        decoded = base64.urlsafe_b64decode(raw_key.encode('utf-8'))
        if len(decoded) == 32:
            return Fernet(raw_key.encode('utf-8'))
    except Exception:
        pass
    
    # Pad or slice to 32 bytes and base64-encode
    padded = (raw_key + "0" * 32)[:32].encode('utf-8')
    key = base64.urlsafe_b64encode(padded)
    return Fernet(key)

cipher = _get_fernet()

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def encrypt_token(plain_token: str) -> str:
    """Encrypt OAuth token or secret before database storage."""
    if not plain_token:
        return ""
    return cipher.encrypt(plain_token.encode('utf-8')).decode('utf-8')

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt OAuth token or secret from database."""
    if not encrypted_token:
        return ""
    try:
        return cipher.decrypt(encrypted_token.encode('utf-8')).decode('utf-8')
    except Exception:
        return ""
