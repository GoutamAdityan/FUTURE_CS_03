from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Configuration
SALT_SIZE = 16 # 16 bytes is standard
KEY_SIZE = 32  # 32 bytes = 256 bits (AES-256)
ITERATIONS = 100000 # Slows down brute-force attacks

def derive_key(password, salt=None):
    """
    Derives a 32-byte AES key from a password.
    If no salt is provided, it generates a new random one.
    """
    if salt is None:
        salt = get_random_bytes(SALT_SIZE)
    
    # PBKDF2 (Password-Based Key Derivation Function 2)
    # This churns the password + salt thousands of times to make a strong key.
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    
    return key, salt

def encrypt_data(data_bytes, password):
    """
    Encrypts data using AES-GCM.
    Returns: salt, nonce, tag, ciphertext
    """
    # 1. Turn the password into a valid AES key
    key, salt = derive_key(password)
    
    # 2. Initialize AES in GCM mode (Galois/Counter Mode)
    # GCM provides both Encryption AND Integrity (tamper-proofing)
    cipher = AES.new(key, AES.MODE_GCM)
    
    # 3. Encrypt!
    # nonce: A random 'number used once' needed for decryption
    nonce = cipher.nonce
    
    # ciphertext: The scrambled data
    # tag: A cryptographic signature to verify the data hasn't been changed
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    
    return salt, nonce, tag, ciphertext

def decrypt_data(salt, nonce, tag, ciphertext, password):
    """
    Decrypts data using AES-GCM.
    """
    # 1. Re-derive the EXACT same key using the saved salt and user's password
    key, _ = derive_key(password, salt)
    
    # 2. Initialize AES with the same nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # 3. Decrypt and Verify
    try:
        # verify() checks the tag. If the file was corrupted/hacked, this fails.
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except ValueError:
        # This means the password was wrong OR the file was tampered with.
        return None
    
