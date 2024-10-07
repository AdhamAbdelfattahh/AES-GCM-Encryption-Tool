from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt(message, key):
    """Encrypt the message using AES GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(encrypted_message, key):
    """Decrypt the message using AES GCM."""
    encrypted_bytes = base64.b64decode(encrypted_message.encode())
    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def main():
    key = get_random_bytes(16)  # Generate a random 16-byte key
    message = input("Enter a message to encrypt: ")
    encrypted_message = encrypt(message, key)
    print(f"Encrypted Message: {encrypted_message}")

    decrypted_message = decrypt(encrypted_message, key)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
