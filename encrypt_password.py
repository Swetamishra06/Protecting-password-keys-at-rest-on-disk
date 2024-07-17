
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import os

def encrypt_password(password: str, aes_key: bytes) -> bytes:
    iv = os.urandom(16)  # Initialization Vector
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_password = iv + cipher.encrypt(pad(password.encode(), AES.block_size))
    return encrypted_password

# Example usage
password = "user_password"
with open("aes_key.bin", "rb") as f:
    aes_key = f.read()
encrypted_password = encrypt_password(password, aes_key)

# Save the encrypted password securely
with open("encrypted_password.bin", "wb") as f:
    f.write(encrypted_password)
