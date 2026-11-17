
import os
import base64

from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()


def get_encryption_key():
    """Load and validate the AES-256 encryption key."""
    key_value = os.getenv("AES_256_KEY")

    if not key_value:
        raise ValueError("AES-256 encryption key is missing.")

    key = base64.urlsafe_b64decode(key_value.encode("utf-8"))

    if len(key) != 32:
        raise ValueError("AES-256 key must contain exactly 32 bytes.")

    return key


def encrypt_sensitive_data(plain_text):
    """Encrypt sensitive text using AES-256-GCM."""
    if not isinstance(plain_text, str):
        raise TypeError("Input must be a string.")

    key = get_encryption_key()
    aes = AESGCM(key)

    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(
        nonce,
        plain_text.encode("utf-8"),
        None
    )

    combined_data = nonce + encrypted_data

    return base64.urlsafe_b64encode(
        combined_data
    ).decode("utf-8")


def decrypt_sensitive_data(encrypted_text):
    """Decrypt AES-256-GCM encrypted text."""
    key = get_encryption_key()
    aes = AESGCM(key)

    combined_data = base64.urlsafe_b64decode(
        encrypted_text.encode("utf-8")
    )

    if len(combined_data) < 29:
        raise ValueError("Invalid encrypted data.")

    nonce = combined_data[:12]
    ciphertext = combined_data[12:]

    decrypted_data = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return decrypted_data.decode("utf-8")
