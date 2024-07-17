
import pyotp
import getpass

def generate_totp_secret() -> str:
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.secret

def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# Generate TOTP secret for a user
secret = generate_totp_secret()
print("Your TOTP secret:", secret)

# Verify TOTP during login
token = input("Enter the TOTP token: ")
if verify_totp(secret, token):
    print("Access granted")
else:
    print("Access denied")
