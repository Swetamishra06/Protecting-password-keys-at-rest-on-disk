
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Generate a key using PBKDF2HMAC
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Generate a secure random salt
salt = os.urandom(16)
password = "my_secure_password"
aes_key = generate_key(password, salt)

# Save the salt and key securely
with open("salt.bin", "wb") as f:
    f.write(salt)

with open("aes_key.bin", "wb") as f:
    f.write(aes_key)
