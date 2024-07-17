import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import pyotp
import logging

# Configure logging
logging.basicConfig(filename='key_management.log', level=logging.INFO)

# Function to log events
def log_event(event: str):
    logging.info(event)

# Generate AES key using PBKDF2HMAC
def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt password using AES key
def encrypt_password(password: str, aes_key: bytes) -> bytes:
    iv = os.urandom(16)  # Initialization Vector
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_password = iv + cipher.encrypt(pad(password.encode(), AES.block_size))
    return encrypted_password

# Decrypt password using AES key
def decrypt_password(encrypted_password: bytes, aes_key: bytes) -> str:
    iv = encrypted_password[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(encrypted_password[16:]), AES.block_size)
    return decrypted_password.decode()

# Generate RSA key pair
def generate_rsa_keys() -> tuple:
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt AES key using RSA public key
def encrypt_aes_key(aes_key: bytes, public_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

# Decrypt AES key using RSA private key
def decrypt_aes_key(encrypted_key: bytes, private_key: bytes) -> bytes:
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

# Generate TOTP secret for multi-factor authentication
def generate_totp_secret() -> str:
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret

# Verify TOTP during login
def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def main():
    # Step 1: Generate AES key
    salt = os.urandom(16)
    password = "my_secure_password"
    aes_key = generate_aes_key(password, salt)

    # Save the salt and AES key
    with open("salt.bin", "wb") as f:
        f.write(salt)
    with open("aes_key.bin", "wb") as f:
        f.write(aes_key)
    
    log_event("AES key generated and saved")

    # Step 2: Encrypt user password
    user_password = "user_password"
    encrypted_password = encrypt_password(user_password, aes_key)
    with open("encrypted_password.bin", "wb") as f:
        f.write(encrypted_password)
    
    log_event("User password encrypted and saved")

    # Step 3: Decrypt user password
    with open("encrypted_password.bin", "rb") as f:
        encrypted_password = f.read()
    decrypted_password = decrypt_password(encrypted_password, aes_key)
    print("Decrypted password:", decrypted_password)
    
    log_event("User password decrypted")

    # Step 4: Key Management (RSA)
    private_key, public_key = generate_rsa_keys()
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    with open("encrypted_aes_key.bin", "wb") as f:
        f.write(encrypted_aes_key)
    
    log_event("AES key encrypted with RSA and saved")

    with open("encrypted_aes_key.bin", "rb") as f:
        encrypted_aes_key = f.read()
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    print("Decrypted AES key:", decrypted_aes_key)
    
    log_event("AES key decrypted with RSA")

    # Step 5: Multi-factor authentication (MFA)
    secret = generate_totp_secret()
    print("Your TOTP secret:", secret)
    log_event("TOTP secret generated")

    token = input("Enter the TOTP token: ")
    if verify_totp(secret, token):
        print("Access granted")
        log_event("MFA successful")
    else:
        print("Access denied")
        log_event("MFA failed")

if __name__ == "__main__":
    main()


# Instructions for Execution
# Install Required Libraries:

# sh
# pip install cryptography pycryptodome pyotp
# Run the Main Program:
# Save the main program code into a file, for example, main.py, and run it using Python:

# sh
# python main.py