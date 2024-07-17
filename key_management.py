
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

def generate_rsa_keys() -> tuple:
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_key(aes_key: bytes, public_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def decrypt_key(encrypted_key: bytes, private_key: bytes) -> bytes:
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

# Example usage
private_key, public_key = generate_rsa_keys()
with open("aes_key.bin", "rb") as f:
    aes_key = f.read()
encrypted_aes_key = encrypt_key(aes_key, public_key)

# Save the encrypted AES key securely
with open("encrypted_aes_key.bin", "wb") as f:
    f.write(encrypted_aes_key)

# Decrypt the AES key when needed
with open("encrypted_aes_key.bin", "rb") as f:
    encrypted_aes_key = f.read()

decrypted_aes_key = decrypt_key(encrypted_aes_key, private_key)
print("Decrypted AES key:", decrypted_aes_key)
