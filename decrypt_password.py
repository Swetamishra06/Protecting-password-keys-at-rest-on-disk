
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def decrypt_password(encrypted_password: bytes, aes_key: bytes) -> str:
    iv = encrypted_password[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(encrypted_password[16:]), AES.block_size)
    return decrypted_password.decode()

# Example usage
with open("encrypted_password.bin", "rb") as f:
    encrypted_password = f.read()

with open("aes_key.bin", "rb") as f:
    aes_key = f.read()

decrypted_password = decrypt_password(encrypted_password, aes_key)
print("Decrypted password:", decrypted_password)
