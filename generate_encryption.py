from cryptography.fernet import Fernet

# Generate and save a key (do this once and store the key securely)
def generate_key():
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to encryption_key.key")



generate_key()