import os
import time
import sys
import base64
import logging
import json
import platform
import subprocess
import f5_stego
from reedsolo import RSCodec
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Crypto.Random import get_random_bytes
import nacl.bindings
import nacl.signing
from termcolor import colored
from tqdm import tqdm
from getpass import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
from cryptography.fernet import Fernet
import hashlib

# Color
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_PURPLE = "\033[95m"
COLOR_RESET = "\033[0m"

if os.name == 'nt':
    os.system('color')
    os.system('chcp 65001')

sys.stdout.reconfigure(encoding='utf-8')

# Logging
logging.basicConfig(filename='ncp_phase1.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
CONFIG_FILE = "ncp_config.json"
USER_DB_FILE = "ncp_users.json"
NCP_FILE_VERSION = b"NCPv1.0"
VERBOSE = True  # Toggle verbosity

# Platform-specific key directory
if platform.system() == "Windows":
    KEY_DIR = os.path.join(os.getenv("APPDATA"), "ncp", "keys")
else:
    KEY_DIR = os.path.expanduser("~/.ncp/keys")

DEFAULT_CONFIG = {
    "key_dir": KEY_DIR,
    "default_output": "ncp_encrypted.txt",
    "default_aes_key_path": os.path.join(KEY_DIR, "aes_key.bin"),
    "default_rsa_public": os.path.join(KEY_DIR, "rsa_public.pem"),
    "default_rsa_private": os.path.join(KEY_DIR, "rsa_private.pem"),
    "default_x25519_private": os.path.join(KEY_DIR, "x25519_private.bin"),
    "default_x25519_public": os.path.join(KEY_DIR, "x25519_public.bin"),
    "master_key_path": os.path.join(KEY_DIR, "master_key.bin")
}

def load_config():
    """Load configuration from a JSON file or create a default one."""
    if not os.path.exists(CONFIG_FILE):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

CONFIG = load_config()

def apply_ecc(data, ecc_symbols=8):
    """Apply Reed-Solomon error correction to data."""
    rs = RSCodec(ecc_symbols)
    return rs.encode(data)

def decode_ecc(data, ecc_symbols=8):
    """Decode Reed-Solomon error correction."""
    try:
        rs = RSCodec(ecc_symbols)
        return rs.decode(data)[0]
    except Exception as e:
        logging.error(f"ECC decoding failed: {e}")
        return None

def run_f5_stego(mode, input_jpeg, data_file, output_file, password="default_password"):
    """Run F5 Steganography using Python module."""
    logger = f5_stego.Logger("f5_stego.log")
    jpeg = f5_stego.JpegHandler()
    f5 = f5_stego.F5Steganography(logger)
    
    try:
        jpeg.load(input_jpeg, logger)
        if mode == "embed":
            if not check_file_exists(data_file, "Data file"):
                return False
            with open(data_file, "rb") as f:
                data = f.read()
            ecc_data = apply_ecc(data)
            f5.collect_modifiable_coeffs(jpeg)
            if len(ecc_data) * 8 > f5.capacity_bits:
                print(f"{COLOR_RED}Data ({len(ecc_data)*8} bits) exceeds JPEG capacity ({f5.capacity_bits} bits){COLOR_RESET}")
                logging.error(f"Embedding failed: Data exceeds JPEG capacity")
                return False
            embedded = f5.embed_data(jpeg, ecc_data, password, 75)
            if embedded > 0:
                jpeg.save(output_file, 75, logger)
                print(f"{COLOR_GREEN}Embedded data into {output_file}{COLOR_RESET}")
                logging.info(f"F5 Steganography embed completed: {input_jpeg} -> {output_file}")
                return True
            else:
                print(f"{COLOR_RED}Embedding failed{COLOR_RESET}")
                logging.error(f"F5 Steganography embed failed for {input_jpeg}")
                return False
        elif mode == "extract":
            extracted_data = f5.extract_data(jpeg, password)
            if extracted_data:
                extracted_bytes = bytes(extracted_data)
                original_data = decode_ecc(extracted_bytes)
                if original_data is None:
                    print(f"{COLOR_RED}ECC decoding failed{COLOR_RESET}")
                    return False
                with open(output_file, "wb") as f:
                    f.write(original_data)
                print(f"{COLOR_GREEN}Extracted data to {output_file}{COLOR_RESET}")
                logging.info(f"F5 Steganography extract completed: {input_jpeg} -> {output_file}")
                return True
            else:
                print(f"{COLOR_RED}Extraction failed{COLOR_RESET}")
                logging.error(f"F5 Steganography extract failed for {input_jpeg}")
                return False
    except Exception as e:
        print(f"{COLOR_RED}F5 Steganography failed: {e}{COLOR_RESET}")
        logging.error(f"F5 Steganography {mode} failed: {e}")
        return False

# Key Encryption
def derive_master_key(password):
    """Derive a master key from password using Argon2."""
    ph = PasswordHasher()
    hashed = ph.hash(password)
    return hashlib.sha256(hashed.encode()).digest()[:32]

def encrypt_key(key_data, master_key):
    """Encrypt a key using Fernet."""
    fernet = Fernet(base64.urlsafe_b64encode(master_key))
    return fernet.encrypt(key_data)

def decrypt_key(encrypted_key, master_key):
    """Decrypt a key using Fernet."""
    fernet = Fernet(base64.urlsafe_b64encode(master_key))
    return fernet.decrypt(encrypted_key)

# User Authentication
def load_users():
    """Load user database from a JSON file or create an empty one."""
    if not os.path.exists(USER_DB_FILE):
        os.makedirs(os.path.dirname(USER_DB_FILE), exist_ok=True)
        with open(USER_DB_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    with open(USER_DB_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    """Save user database to a JSON file."""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def validate_password(password):
    """Validate password!"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    return True, "Password is valid"

def register_user():
    """Register a new user with a username and password."""
    users = load_users()
    ph = PasswordHasher()

    print(f"\n{COLOR_CYAN}=== NCP: New Operative Registration ==={COLOR_RESET}")
    while True:
        username = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Enter username: ").strip()
        if not username:
            print(f"{COLOR_RED}Username cannot be empty{COLOR_RESET}")
            continue
        if username in users:
            print(f"{COLOR_RED}Username already exists{COLOR_RESET}")
            continue
        break

    while True:
        password = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Enter password: ")
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f"{COLOR_RED}{message}{COLOR_RESET}")
            continue
        confirm_password = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Confirm password: ")
        if password != confirm_password:
            print(f"{COLOR_RED}Passwords do not match{COLOR_RESET}")
            continue
        break

    hashed_password = ph.hash(password)
    users[username] = hashed_password
    save_users(users)
    # Generate and save master key
    master_key = derive_master_key(password)
    os.makedirs(CONFIG["key_dir"], exist_ok=True)
    with open(CONFIG["master_key_path"], "wb") as f:
        f.write(master_key)
    print(f"{COLOR_GREEN}Operative {username} registered successfully!{COLOR_RESET}")
    logging.info(f"Operative {username} registered")
    time.sleep(1)

def authenticate_user():
    """Authenticate a user with a username and password."""
    users = load_users()
    ph = PasswordHasher()
    max_attempts = 3
    attempts_left = max_attempts

    if not users:
        print(f"{COLOR_YELLOW}No operatives found. Initiating registration...{COLOR_RESET}")
        register_user()
        users = load_users()

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{COLOR_PURPLE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{COLOR_RESET}")
    print(f"{COLOR_PURPLE}┃         NCP Secure Access Portal      ┃{COLOR_RESET}")
    print(f"{COLOR_PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{COLOR_RESET}")
    print(f"{COLOR_CYAN}=== Operative Authentication Required ==={COLOR_RESET}")
    print(f"\n{COLOR_YELLOW}Initializing security protocols...{COLOR_RESET}")
    for _ in tqdm(range(20), desc="Verifying", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.1)

    while attempts_left > 0:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{COLOR_PURPLE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{COLOR_RESET}")
        print(f"{COLOR_PURPLE}┃         NCP Secure Access Portal      ┃{COLOR_RESET}")
        print(f"{COLOR_PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{COLOR_RESET}")
        print(f"{COLOR_CYAN}=== Operative Authentication Required ==={COLOR_RESET}")
        print(f"{COLOR_YELLOW}Attempts remaining: {attempts_left}{COLOR_RESET}")

        username = input(f"\n{COLOR_PURPLE}[>>]{COLOR_RESET} Operative ID (username): ").strip()
        if username not in users:
            print(f"{COLOR_RED}Operative ID not found{COLOR_RESET}")
            attempts_left -= 1
            time.sleep(1)
            continue

        password = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Access Code (password): ")
        try:
            ph.verify(users[username], password)
            # Load master key
            global MASTER_KEY
            MASTER_KEY = derive_master_key(password)
            logging.info(f"Operative {username} logged in successfully")
            break
        except VerifyMismatchError:
            print(f"{COLOR_RED}Invalid access code{COLOR_RESET}")
            attempts_left -= 1
            time.sleep(1)

    if attempts_left == 0:
        print(f"\n{COLOR_RED}Too many failed attempts. System lockdown initiated.{COLOR_RESET}")
        print(f"{COLOR_RED}Access denied. Terminating session...{COLOR_RESET}")
        logging.warning("System lockdown: Too many failed login attempts")
        time.sleep(2)
        sys.exit(1)

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{COLOR_GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{COLOR_RESET}")
    print(f"{COLOR_GREEN}┃         System Access Granted         ┃{COLOR_RESET}")
    print(f"{COLOR_GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{COLOR_RESET}")
    print(f"{COLOR_CYAN}Welcome, Operative {username}{COLOR_RESET}")
    print(f"{COLOR_PURPLE}✦ Secure the Void ✦{COLOR_RESET}")
    print(f"\n{COLOR_YELLOW}Loading NCP core systems...{COLOR_RESET}")
    for _ in tqdm(range(20), desc="Initializing", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.1)
    return username

# Utility Functions
def check_file_exists(file_path, file_description="File"):
    """Check if a file exists and is readable."""
    try:
        path = Path(file_path)
        if not path.exists():
            print(f"{COLOR_RED}{file_description} not found: {file_path}{COLOR_RESET}")
            logging.error(f"{file_description} not found: {file_path}")
            return False
        if not path.is_file():
            print(f"{COLOR_RED}{file_description} is not a file: {file_path}{COLOR_RESET}")
            logging.error(f"{file_description} is not a file: {file_path}")
            return False
        return True
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Error accessing {file_description}: {e}{COLOR_RESET}")
        logging.error(f"Error accessing {file_description}: {e}")
        return False

def validate_input(text, input_type="hex"):
    """Validate input based on type (hex or base64)."""
    try:
        if input_type == "hex":
            bytes.fromhex(text)
        elif input_type == "base64":
            base64.b64decode(text)
        return True
    except:
        return False

def validate_file_path(file_path):
    """Validate that a file path is not empty and contains no invalid characters."""
    if not file_path:
        print(f"{COLOR_RED}File path cannot be empty{COLOR_RESET}")
        return False
    invalid_chars = '<>:"/\\|?*' if os.name == 'nt' else '/'
    if any(char in file_path for char in invalid_chars):
        print(f"{COLOR_RED}Invalid file path: {file_path}{COLOR_RESET}")
        return False
    try:
        path = Path(file_path)
        parent = path.parent
        if not parent.exists():
            print(f"{COLOR_RED}Parent directory does not exist: {parent}{COLOR_RESET}")
            return False
        return True
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Invalid file path: {e}{COLOR_RESET}")
        return False

def read_file_with_progress(file_path):
    """Read a file with a progress bar."""
    try:
        file_size = os.path.getsize(file_path)
        data = b""
        with open(file_path, "rb") as f:
            with tqdm(total=file_size, desc="Reading", unit="B", unit_scale=True, disable=not VERBOSE) as pbar:
                while chunk := f.read(1024 * 16):
                    data += chunk
                    pbar.update(len(chunk))
        return data
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Error reading file: {e}{COLOR_RESET}")
        logging.error(f"Error reading file {file_path}: {e}")
        return None

def load_aes_key(use_file, aes_path=None):
    """Load an AES key either from a file or user input."""
    if use_file.lower() == "y":
        aes_path = aes_path or input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} AES key file path [{CONFIG['default_aes_key_path']}]: ") or CONFIG['default_aes_key_path']
        if not check_file_exists(aes_path, "AES key file"):
            return None
        try:
            with open(aes_path, "rb") as f:
                encrypted_key = f.read()
            return decrypt_key(encrypted_key, MASTER_KEY)
        except Exception as e:
            print(f"{COLOR_RED}Error decrypting AES key: {e}{COLOR_RESET}")
            logging.error(f"Error decrypting AES key: {e}")
            return None
    else:
        aes_key_hex = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} AES key (hex): ")
        if not validate_input(aes_key_hex, "hex"):
            print(f"{COLOR_RED}Invalid AES key format (must be hex){COLOR_RESET}")
            return None
        return bytes.fromhex(aes_key_hex)

# Display Functions
def display_ascii(clear=True):
    """Display the text-based header with a splash screen and persistent header."""
    header_text = "NCrypt Protocol"
    header_width = len(header_text) + 16
    top_border = "┏" + "━" * (header_width - 2) + "┓"
    bottom_border = "┗" + "━" * (header_width - 2) + "┛"
    header_line = f"┃{' ' * 7}{header_text}{' ' * 7}┃"
    tagline = "✦ Secure the Void ✦"

    if clear:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{COLOR_PURPLE}{top_border}{COLOR_RESET}")
        print(f"{COLOR_PURPLE}{header_line}{COLOR_RESET}")
        print(f"{COLOR_PURPLE}{bottom_border}{COLOR_RESET}")
        print(f"{COLOR_CYAN}=== NCrypt Protocol: NCP Encryption ==={COLOR_RESET}")
        print(f"{COLOR_YELLOW}Coded by: N0cturn1s | Powered by xAI{COLOR_RESET}")
        print(f"{COLOR_GREEN}github: https://github.com/whois-tet{COLOR_RESET}")
        print(f"Version: 1.0 | CTRL+C: Exit")
        print(f"{COLOR_PURPLE}{tagline}{COLOR_RESET}")
        print(f"\n{COLOR_YELLOW}Initializing...{COLOR_RESET}")
        for _ in tqdm(range(20), desc="Loading", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}", disable=not VERBOSE):
            time.sleep(0.1)
        time.sleep(2)
        os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{COLOR_PURPLE}{top_border}{COLOR_RESET}")
    print(f"{COLOR_PURPLE}{header_line}{COLOR_RESET}")
    print(f"{COLOR_PURPLE}{bottom_border}{COLOR_RESET}")
    print(f"{COLOR_CYAN}=== NCrypt Protocol: NCP Encryption ==={COLOR_RESET}")
    print(f"{COLOR_YELLOW}Coded by: N0cturn1s | Powered by xAI{COLOR_RESET}")
    print(f"{COLOR_GREEN}github: https://github.com/whois-tet{COLOR_RESET}")
    print(f"Version: 1.0 | CTRL+C: Exit")
    print(f"{COLOR_PURPLE}{tagline}{COLOR_RESET}")

def generate_keys(key_type="RSA", size=4096, save_dir=CONFIG["key_dir"]):
    """Generate RSA or X25519+Ed25519 key pairs."""
    print(f"{COLOR_YELLOW}[*] Generating {key_type} keys...{COLOR_RESET}")
    try:
        os.makedirs(save_dir, exist_ok=True)
        algo = ""
        if key_type.upper() == "RSA":
            print(f"{COLOR_YELLOW}This may take a few minutes for {size}-bit keys...{COLOR_RESET}")
            with tqdm(total=100, desc="Generating RSA keys", unit="%", disable=not VERBOSE) as pbar:
                key = RSA.generate(size)
                pbar.update(50)
                priv_path = os.path.join(save_dir, "rsa_private.pem")
                pub_path = os.path.join(save_dir, "rsa_public.pem")
                while True:
                    passphrase = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Enter passphrase for private key (min 8 chars): ")
                    if len(passphrase) < 8:
                        print(f"{COLOR_RED}Passphrase must be at least 8 characters long{COLOR_RESET}")
                        continue
                    break
                priv_export = key.export_key(pkcs=8, protection='scryptAndAES256-CBC', passphrase=passphrase)
                pub_export = key.publickey().export_key()
                with open(priv_path, "wb") as f:
                    f.write(encrypt_key(priv_export, MASTER_KEY))
                with open(pub_path, "wb") as f:
                    f.write(encrypt_key(pub_export, MASTER_KEY))
                pbar.update(50)
                algo = f"RSA-{size}"
        elif key_type.upper() == "X25519":
            priv_key, pub_key = nacl.bindings.crypto_box_keypair()
            signing_key = nacl.signing.SigningKey.generate()
            signed_pub = signing_key.sign(pub_key)
            priv_path = os.path.join(save_dir, "x25519_private.bin")
            pub_path = os.path.join(save_dir, "x25519_public.bin")
            sig_path = os.path.join(save_dir, "x25519_signature.bin")
            with open(priv_path, "wb") as f:
                f.write(encrypt_key(priv_key, MASTER_KEY))
            with open(pub_path, "wb") as f:
                f.write(encrypt_key(pub_key, MASTER_KEY))
            with open(sig_path, "wb") as f:
                f.write(encrypt_key(signed_pub, MASTER_KEY))
            algo = "X25519+Ed25519"
        else:
            raise ValueError("Invalid key type")
        
        msg = f"{algo} key pair generated in '{save_dir}'"
        print(f"{COLOR_GREEN}{msg}{COLOR_RESET}")
        print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
        logging.info(msg)
        return algo
    except Exception as e:
        print(f"{COLOR_RED}Key generation failed: {e}{COLOR_RESET}")
        logging.error(f"Key gen failed: {e}")
        return None

def encrypt_payload(plaintext, aes_key):
    """Encrypt plaintext using AES-256-GCM."""
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext if isinstance(plaintext, bytes) else plaintext.encode('utf-8'))
        return cipher.nonce, ciphertext, tag
    except Exception as e:
        print(f"{COLOR_RED}Encryption failed: {e}{COLOR_RESET}")
        logging.error(f"Encryption failed: {e}")
        return None, None, None

def decrypt_payload(nonce, ciphertext, tag, aes_key):
    """Decrypt ciphertext using AES-256-GCM."""
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext if isinstance(plaintext, bytes) else plaintext.decode('utf-8')
    except Exception as e:
        print(f"{COLOR_RED}Decryption failed: {e}{COLOR_RESET}")
        logging.error(f"Decryption failed: {e}")
        return None

def encrypt_aes_key(aes_key, public_key_path):
    """Encrypt an AES key using RSA-4096."""
    print(f"{COLOR_YELLOW}[*] Encrypting AES key with RSA-4096...{COLOR_RESET}")
    if not check_file_exists(public_key_path, "Public key file"):
        return None
    try:
        with open(public_key_path, "rb") as f:
            encrypted_pub_key = f.read()
        pub_key_data = decrypt_key(encrypted_pub_key, MASTER_KEY)
        pub_key = RSA.import_key(pub_key_data)
        cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA3_512)
        encrypted = cipher.encrypt(aes_key)
        result = base64.b64encode(encrypted).decode()
        print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
        return result
    except Exception as e:
        print(f"{COLOR_RED}Key encryption failed: {e}{COLOR_RESET}")
        logging.error(f"Key encrypt failed: {e}")
        return None

def decrypt_aes_key(encrypted_key_b64, private_key_path):
    """Decrypt an AES key using RSA-4096."""
    print(f"{COLOR_YELLOW}[*] Decrypting AES key with RSA-4096...{COLOR_RESET}")
    if not check_file_exists(private_key_path, "Private key file"):
        return None
    try:
        passphrase = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Enter private key passphrase: ")
        with open(private_key_path, "rb") as f:
            encrypted_priv_key = f.read()
        priv_key_data = decrypt_key(encrypted_priv_key, MASTER_KEY)
        priv_key = RSA.import_key(priv_key_data, passphrase=passphrase)
        cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA3_512)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_key_b64))
        print(f"{COLOR_GREEN}Decrypted AES Key:{COLOR_RESET} {decrypted.hex()}")
        print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
        return decrypted
    except ValueError as ve:
        print(f"{COLOR_RED}Invalid passphrase{COLOR_RESET}")
        logging.error("Invalid private key passphrase")
        return None
    except Exception as e:
        print(f"{COLOR_RED}Key decryption failed: {e}{COLOR_RESET}")
        logging.error(f"Key decrypt failed: {e}")
        return None

def derive_x25519_key(sender_priv_path, receiver_pub_path):
    """Derive an AES key using X25519 key exchange."""
    print(f"{COLOR_YELLOW}[*] Deriving AES key with X25519...{COLOR_RESET}")
    if not check_file_exists(sender_priv_path, "Sender private key file") or \
       not check_file_exists(receiver_pub_path, "Receiver public key file"):
        return None
    try:
        with open(sender_priv_path, "rb") as f:
            encrypted_priv = f.read()
        sender_priv = decrypt_key(encrypted_priv, MASTER_KEY)
        with open(receiver_pub_path, "rb") as f:
            encrypted_pub = f.read()
        receiver_pub = decrypt_key(encrypted_pub, MASTER_KEY)
        aes_key = nacl.bindings.crypto_box_beforenm(receiver_pub, sender_priv)[:32]
        print(f"{COLOR_GREEN}Derived AES Key:{COLOR_RESET} {aes_key.hex()}")
        print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
        return aes_key
    except Exception as e:
        print(f"{COLOR_RED}Key derivation failed: {e}{COLOR_RESET}")
        logging.error(f"Key derive failed: {e}")
        return None

def encrypt_file(input_path, output_path, aes_key, rsa_public_path=None, for_stego=False):
    """Encrypt a file using AES-256-GCM and optionally wrap the AES key with RSA."""
    print(f"{COLOR_YELLOW}[*] Encrypting file with AES-256-GCM...{COLOR_RESET}")
    if not check_file_exists(input_path, "Input file"):
        return None
    if not validate_file_path(output_path):
        return None
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher.nonce
        file_size = os.path.getsize(input_path)
        
        wrapped_key = b""
        if rsa_public_path:
            if not check_file_exists(rsa_public_path, "RSA public key file"):
                return None
            wrapped_key = base64.b64decode(encrypt_aes_key(aes_key, rsa_public_path))
        
        with open(input_path, "rb") as f_in:
            hasher = SHA3_512.new()
            file_data = f_in.read()
            hasher.update(file_data)
            file_hash = hasher.digest()
            
            metadata = NCP_FILE_VERSION + (b"\x01" if rsa_public_path else b"\x00")
            encrypted_data = wrapped_key + nonce
            with tqdm(total=file_size, desc="Encrypting", unit="B", unit_scale=True, disable=not VERBOSE) as pbar:
                ciphertext, tag = cipher.encrypt_and_digest(file_data)
                encrypted_data += ciphertext
                pbar.update(len(file_data))
            encrypted_data += tag + file_hash

        if for_stego:
            return metadata + encrypted_data
        else:
            with open(output_path, "wb") as f_out:
                f_out.write(metadata + encrypted_data)
            print(f"{COLOR_GREEN}File encrypted:{COLOR_RESET} {output_path}")
            print(f"{COLOR_GREEN}File hash (SHA3-512):{COLOR_RESET} {file_hash.hex()}")
            print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
            logging.info(f"File encrypted: {input_path}")
            return None
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Error encrypting file: {e}{COLOR_RESET}")
        logging.error(f"Error encrypting file {input_path}: {e}")
        return None

def decrypt_file(input_path, output_path, aes_key=None, rsa_private_path=None):
    """Decrypt a file using AES-256-GCM and verify its integrity with SHA3-512 hash."""
    print(f"{COLOR_YELLOW}[*] Decrypting file with AES-256-GCM...{COLOR_RESET}")
    if not check_file_exists(input_path, "Input file"):
        return
    if not validate_file_path(output_path):
        return
    try:
        with open(input_path, "rb") as f_in:
            version = f_in.read(7)
            if version != NCP_FILE_VERSION:
                print(f"{COLOR_RED}Unsupported NCP file version: {version.decode()}{COLOR_RESET}")
                return
            rsa_flag = f_in.read(1)
            rsa_size = 512 if rsa_flag == b"\x01" else 0
            
            wrapped_key = f_in.read(rsa_size) if rsa_size else b''
            nonce = f_in.read(16)
            file_size = os.path.getsize(input_path) - 7 - 1 - rsa_size - 16 - 16 - 64
            ciphertext = f_in.read(file_size)
            tag = f_in.read(16)
            stored_hash = f_in.read(64)
            
            if rsa_size:
                if not check_file_exists(rsa_private_path, "RSA private key file"):
                    return
                aes_key = decrypt_aes_key(base64.b64encode(wrapped_key).decode(), rsa_private_path)
                if aes_key is None:
                    return
            
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            with open(output_path, "wb") as f_out, tqdm(total=file_size, desc="Decrypting", unit="B", unit_scale=True, disable=not VERBOSE) as pbar:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                f_out.write(plaintext)
                pbar.update(len(plaintext))
            
            hasher = SHA3_512.new()
            hasher.update(plaintext)
            computed_hash = hasher.digest()
            if computed_hash != stored_hash:
                print(f"{COLOR_RED}File integrity check failed! Hash mismatch.{COLOR_RESET}")
                logging.error(f"File integrity check failed for {input_path}: Hash mismatch")
                os.remove(output_path)
                return
            else:
                print(f"{COLOR_GREEN}File integrity verified!{COLOR_RESET}")
        
        print(f"{COLOR_GREEN}File decrypted:{COLOR_RESET} {output_path}")
        print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
        logging.info(f"File decrypted: {input_path}")
    except (PermissionError, OSError, ValueError) as e:
        print(f"{COLOR_RED}Error decrypting file: {e}{COLOR_RESET}")
        logging.error(f"Error decrypting file {input_path}: {e}")
        return

# Interactive Menu
def interactive_menu(username):
    """Display the interactive menu and handle user choices."""
    global VERBOSE
    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            display_ascii(clear=False)
            print(f"{COLOR_CYAN}╔════════════════════════════════════╗")
            print(f"║           NCP ENCRYPTION           ║")
            print(f"╠════════════════════════════════════╣")
            print(f"║ 1. Generate Keys (RSA/X25519)      ║")
            print(f"║ 2. Encrypt Text (AES+RSA)          ║")
            print(f"║ 3. Decrypt Text (AES+RSA)          ║")
            print(f"║ 4. Encrypt File (AES+RSA)          ║")
            print(f"║ 5. Decrypt File (AES+RSA)          ║")
            print(f"║ 6. Derive X25519 AES Key           ║")
            print(f"║ 7. Generate Random AES Key         ║")
            print(f"║ 8. Toggle Verbosity                ║")
            print(f"║ 9. Embed Steganography (F5)        ║")
            print(f"║ 10. Extract Steganography (F5)     ║")
            print(f"║ 11. Logout                         ║")
            print(f"║ 12. Exit to Hyperspace             ║")
            print(f"╚════════════════════════════════════╝{COLOR_RESET}")
            
            choice = input(f"\n{COLOR_PURPLE}[>>]{COLOR_RESET} Select (1-12): ").strip()
            
            if choice == '1':
                key_type = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Key type (RSA/X25519) [RSA]: ") or "RSA"
                size = None
                if key_type.upper() == "RSA":
                    size = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} RSA Size (2048/4096) [4096]: ") or "4096"
                    size = int(size) if size in ["2048", "4096"] else 4096
                save_dir = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Save dir [{CONFIG['key_dir']}]: ") or CONFIG['key_dir']
                if key_type.upper() == "RSA":
                    generate_keys("RSA", size, save_dir)
                else:
                    generate_keys("X25519", save_dir=save_dir)
                input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")

            elif choice == '2':
                plaintext = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Enter text: ")
                if not plaintext:
                    print(f"{COLOR_RED}Text cannot be empty{COLOR_RESET}")
                    input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")
                    continue
                use_rsa = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Use RSA? (y/n) [y]: ") or "y"
                pub_key = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} RSA public key path [{CONFIG['default_rsa_public']}]: ") or CONFIG['default_rsa_public'] if use_rsa.lower() == "y" else None
                aes_key = get_random_bytes(32)
                nonce, ciphertext, tag = encrypt_payload(plaintext, aes_key)
                if nonce is None:
                    input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")
                    continue
                output = base64.b64encode(nonce + ciphertext + tag).decode()
                if pub_key:
                    enc_key = encrypt_aes_key(aes_key, pub_key)
                    if enc_key is None:
                        input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")
                        continue
                    print(f"{COLOR_GREEN}Encrypted Text:{COLOR_RESET} {output}")
                    print(f"{COLOR_GREEN}Encrypted AES Key:{COLOR_RESET} {enc_key}")
                else:
                    print(f"{COLOR_GREEN}Encrypted Text:{COLOR_RESET} {output}")
                    print(f"{COLOR_YELLOW}AES Key (save this!):{COLOR_RESET} {aes_key.hex()}")
                save_output = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Save to file? (y/n) [n]: ") or "n"
                if save_output.lower() == "y":
                    for_stego = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Export for steganography? (y/n) [n]: ") or "n"
                    save_path = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Save to [{CONFIG['default_output']}]: ") or CONFIG['default_output']
                    if not validate_file_path(save_path):
                        continue
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    if for_stego.lower() == "y":
                        metadata = NCP_FILE_VERSION + (b"\x01" if pub_key else b"\x00")
                        binary_data = metadata + (base64.b64decode(enc_key) if pub_key else b"") + nonce + ciphertext + tag
                        with open(save_path, "wb") as f:
                            f.write(binary_data)
                        print(f"{COLOR_GREEN}Binary data saved for steganography:{COLOR_RESET} {save_path}")
                    else:
                        with open(save_path, "w") as f:
                            f.write(f"Encrypted Text: {output}\n")
                            if pub_key:
                                f.write(f"Encrypted AES Key: {enc_key}\n")
                            else:
                                f.write(f"AES Key (hex): {aes_key.hex()}\n")
                        print(f"{COLOR_GREEN}Saved to:{COLOR_RESET} {save_path}")
                logging.info(f"Operative {username}: Text encrypted with AES-256-GCM")
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '3':
                enc_text = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Encrypted text: ")
                if not validate_input(enc_text, "base64"):
                    print(f"{COLOR_RED}Invalid encrypted text format (must be base64){COLOR_RESET}")
                    input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                    continue
                use_rsa = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Use RSA? (y/n) [y]: ") or "y"
                if use_rsa.lower() == "y":
                    priv_key = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} RSA private key path [{CONFIG['default_rsa_private']}]: ") or CONFIG['default_rsa_private']
                    enc_key = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Encrypted AES key: ")
                    if not validate_input(enc_key, "base64"):
                        print(f"{COLOR_RED}Invalid encrypted AES key format (must be base64){COLOR_RESET}")
                        input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                        continue
                    if not check_file_exists(priv_key, "RSA private key file"):
                        continue
                    aes_key = decrypt_aes_key(enc_key, priv_key)
                    if aes_key is None:
                        input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                        continue
                else:
                    use_file = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Load AES key from file? (y/n) [n]: ") or "n"
                    aes_key = load_aes_key(use_file)
                    if aes_key is None:
                        input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                        continue
                data = base64.b64decode(enc_text)
                nonce, ciphertext, tag = data[:16], data[16:-16], data[-16:]
                plaintext = decrypt_payload(nonce, ciphertext, tag, aes_key)
                if plaintext is None:
                    input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                    continue
                print(f"{COLOR_GREEN}Decrypted Text:{COLOR_RESET} {plaintext}")
                logging.info(f"Operative {username}: Text decrypted with AES-256-GCM")
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '4':
                input_file = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Input file path: ")
                if not check_file_exists(input_file, "Input file"):
                    continue
                output_file = input_file + '.ncp'
                if not validate_file_path(output_file):
                    continue
                use_rsa = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Use RSA? (y/n) [y]: ") or "y"
                pub_key = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} RSA public key path [{CONFIG['default_rsa_public']}]: ") or CONFIG['default_rsa_public'] if use_rsa.lower() == "y" else None
                for_stego = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Export for steganography? (y/n) [n]: ") or "n"
                aes_key = get_random_bytes(32)
                result = encrypt_file(input_file, output_file, aes_key, pub_key, for_stego=for_stego.lower() == "y")
                if for_stego.lower() == "y" and result:
                    save_path = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Save binary data to [ncp_stego.bin]: ") or "ncp_stego.bin"
                    if not validate_file_path(save_path):
                        continue
                    with open(save_path, "wb") as f:
                        f.write(result)
                    print(f"{COLOR_GREEN}Binary data saved for steganography:{COLOR_RESET} {save_path}")
                if not pub_key:
                    print(f"{COLOR_YELLOW}AES Key (save this!):{COLOR_RESET} {aes_key.hex()}")
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '5':
                input_file = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Input file path: ")
                if not check_file_exists(input_file, "Input file"):
                    continue
                output_file = input_file[:-4] if input_file.endswith('.ncp') else input_file + '.dec'
                if not validate_file_path(output_file):
                    continue
                use_rsa = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Use RSA? (y/n) [y]: ") or "y"
                if use_rsa.lower() == "y":
                    priv_key = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} RSA private key path [{CONFIG['default_rsa_private']}]: ") or CONFIG['default_rsa_private']
                    if not check_file_exists(priv_key, "RSA private key file"):
                        continue
                    decrypt_file(input_file, output_file, rsa_private_path=priv_key)
                else:
                    use_file = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Load AES key from file? (y/n) [n]: ") or "n"
                    aes_key = load_aes_key(use_file)
                    if aes_key is None:
                        input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")
                        continue
                    decrypt_file(input_file, output_file, aes_key=aes_key)
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '6':
                sender_priv = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Sender private key path [{CONFIG['default_x25519_private']}]: ") or CONFIG['default_x25519_private']
                receiver_pub = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Receiver public key path [{CONFIG['default_x25519_public']}]: ") or CONFIG['default_x25519_public']
                aes_key = derive_x25519_key(sender_priv, receiver_pub)
                if aes_key is None:
                    input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")
                    continue
                input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")

            elif choice == '7':
                print(f"{COLOR_YELLOW}[*] Generating random AES-256 key...{COLOR_RESET}")
                aes_key = get_random_bytes(32)
                save_path = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Save AES key to [{CONFIG['default_aes_key_path']}]: ") or CONFIG['default_aes_key_path']
                if not validate_file_path(save_path):
                    continue
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                with open(save_path, "wb") as f:
                    f.write(encrypt_key(aes_key, MASTER_KEY))
                print(f"{COLOR_GREEN}AES Key generated and saved:{COLOR_RESET} {save_path}")
                print(f"{COLOR_YELLOW}AES Key (hex):{COLOR_RESET} {aes_key.hex()}")
                print(f"{COLOR_GREEN}Done!{COLOR_RESET}")
                logging.info(f"Operative {username}: Random AES key generated and saved to {save_path}")
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '8':
                VERBOSE = not VERBOSE
                print(f"{COLOR_GREEN}Verbosity {'enabled' if VERBOSE else 'disabled'}{COLOR_RESET}")
                logging.info(f"Operative {username}: Verbosity set to {VERBOSE}")
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '9':
                input_jpeg = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Input JPEG path: ")
                if not check_file_exists(input_jpeg, "JPEG file"):
                    continue
                data_file = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Data file path (from encryption): ")
                if not check_file_exists(data_file, "Data file"):
                    continue
                output_jpeg = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Output JPEG path: ")
                if not validate_file_path(output_jpeg):
                    continue
                password = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Stego password: ")
                run_f5_stego("embed", input_jpeg, data_file, output_jpeg, password)
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '10':
                input_jpeg = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Stego JPEG path: ")
                if not check_file_exists(input_jpeg, "JPEG file"):
                    continue
                output_data = input(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Output data path: ")
                if not validate_file_path(output_data):
                    continue
                password = getpass(f"{COLOR_PURPLE}[>>]{COLOR_RESET} Stego password: ")
                run_f5_stego("extract", input_jpeg, output_data, password)
                input(f"{COLOR_YELLOW}[!] Press Enter to continue...{COLOR_RESET}")

            elif choice == '11':
                print(f"{COLOR_PURPLE}[!] Logging out Operative {username}...{COLOR_RESET}")
                logging.info(f"Operative {username} logged out")
                time.sleep(1)
                return True
            elif choice == '12':
                print(f"{COLOR_PURPLE}[!] Warping out...{COLOR_RESET}")
                logging.info(f"Operative {username} exited the system")
                return False
            else:
                print(f"{COLOR_RED}Invalid choice, fam!{COLOR_RESET}")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{COLOR_PURPLE}[!] Hyperspace jump aborted!{COLOR_RESET}")
            logging.info(f"Operative {username} aborted session with KeyboardInterrupt")
            return False
        except Exception as e:
            print(f"{COLOR_RED}Error: {e}{COLOR_RESET}")
            logging.error(f"Operative {username}: Error - {e}")
            input(f"{COLOR_YELLOW}[!] Enter to continue...{COLOR_RESET}")

if __name__ == "__main__":
    while True:
        username = authenticate_user()
        should_logout = interactive_menu(username)
        if not should_logout:
            break