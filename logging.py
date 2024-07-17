
import logging

# Configure logging
logging.basicConfig(filename='key_management.log', level=logging.INFO)

def log_event(event: str):
    logging.info(event)

# Example usage
log_event("AES key generated")
log_event("Password encrypted")
log_event("Password decrypted")
