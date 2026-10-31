"""Encryption at rest and integrity hashing for protected files.

The ORIGINAL bytes are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
before they touch the disk, and decrypted only for an authorized request.
Users never see ciphertext. A SHA-256 hash of the original is stored
separately so any tampering with the stored copy is detected on read.
"""
import hashlib
import warnings
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# cryptography 40.x is the last release supporting Python 3.6; it warns about
# that on import. The warning is informational only.
warnings.filterwarnings('ignore', message='.*Python 3.6.*')

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

__all__ = ['IntegrityError', 'sha256_hex', 'write_blob', 'read_blob', 'delete_blob']


class IntegrityError(Exception):
    """Stored copy is missing, cannot be decrypted, or its hash changed."""


def _load_key():
    key = getattr(settings, 'SV_FILE_ENCRYPTION_KEY', '') or ''
    if key:
        return key.encode('ascii') if isinstance(key, str) else key
    if settings.DEBUG or getattr(settings, 'TESTING', False):
        # Development only: generate once and keep it, so files stay readable
        # across restarts. Back this file up; without it files are lost.
        key_file = Path(settings.BASE_DIR) / '.dev_file_key'
        if key_file.exists():
            return key_file.read_bytes().strip()
        new_key = Fernet.generate_key()
        key_file.write_bytes(new_key)
        return new_key
    raise ImproperlyConfigured('SV_FILE_ENCRYPTION_KEY must be set when SV_DEBUG is False.')


def _fernet():
    return Fernet(_load_key())


def _storage_dir():
    folder = Path(settings.SV_PROTECTED_STORAGE)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def write_blob(storage_name, data):
    """Encrypt and store the original bytes."""
    (_storage_dir() / storage_name).write_bytes(_fernet().encrypt(data))


def read_blob(storage_name, expected_sha256):
    """Decrypt and verify. Returns the ORIGINAL bytes, unchanged."""
    path = _storage_dir() / storage_name
    try:
        data = _fernet().decrypt(path.read_bytes())
    except (OSError, InvalidToken):
        raise IntegrityError('Stored copy is missing or cannot be decrypted.')
    if sha256_hex(data) != expected_sha256:
        raise IntegrityError('Stored copy does not match its recorded hash.')
    return data


def delete_blob(storage_name):
    try:
        (_storage_dir() / storage_name).unlink()
    except OSError:
        pass