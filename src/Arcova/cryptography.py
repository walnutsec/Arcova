# src/Arcova/crypto.py

import base64
import logging
from pathlib import Path
from getpass import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Crypto.Random import get_random_bytes
import nacl.bindings
import nacl.signing
from reedsolo import RSCodec
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
import hashlib
from tqdm import tqdm
from . import utils

ARCOVA_FILE_VERSION = b"ARVv1.0"

def apply_ecc(data: bytes, ecc_symbols=8) -> bytes:
    rs = RSCodec(ecc_symbols)
    return rs.encode(data)

def decode_ecc(data: bytes, ecc_symbols=8) -> bytes | None:
    try:
        rs = RSCodec(ecc_symbols)
        return rs.decode(data)[0]
    except Exception as e:
        logging.error(f"ECC decoding failed: {e}")
        return None

def derive_master_key(password: str) -> bytes:
    ph = PasswordHasher()
    hashed = ph.hash(password)
    return hashlib.sha256(hashed.encode()).digest()

def generate_keys(key_type: str, master_key: bytes, save_dir: Path, rsa_size: int = 4096):
    """Generate and save encrypted RSA or X25519 key pairs."""
    print(f"{utils.COLOR_YELLOW}[*] Generating {key_type} keys...{utils.COLOR_RESET}")
    try:
        if key_type.upper() == "RSA":
            print(f"{utils.COLOR_YELLOW}This may take a few minutes for {rsa_size}-bit keys...{utils.COLOR_RESET}")
            priv_path = save_dir / "rsa_private.pem"
            pub_path = save_dir / "rsa_public.pem"

            key = RSA.generate(rsa_size)
            passphrase = getpass(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Create a passphrase for the new private key: ")

            priv_export = key.export_key(pkcs=8, protection='scryptAndAES256-CBC', passphrase=passphrase)
            pub_export = key.publickey().export_key()

            with open(priv_path, "wb") as f:
                f.write(encrypt_key(priv_export, master_key))
            with open(pub_path, "wb") as f:
                f.write(encrypt_key(pub_export, master_key))

            print(f"{utils.COLOR_GREEN}RSA-{rsa_size} key pair generated and encrypted in '{save_dir}'{utils.COLOR_RESET}")

        elif key_type.upper() == "X25519":
            print(f"{utils.COLOR_YELLOW}X25519 key generation not fully implemented yet.{utils.COLOR_RESET}")

        else:
            raise ValueError("Invalid key type specified")
    except Exception as e:
        print(f"{utils.COLOR_RED}Key generation failed: {e}{utils.COLOR_RESET}")
        logging.error(f"Key generation failed: {e}")

def encrypt_key(key_data: bytes, master_key: bytes) -> bytes:
    fernet = Fernet(base64.urlsafe_b64encode(master_key))
    return fernet.encrypt(key_data)

def decrypt_key(encrypted_key: bytes, master_key: bytes) -> bytes:
    fernet = Fernet(base64.urlsafe_b64encode(master_key))
    return fernet.decrypt(encrypted_key)

def encrypt_payload(plaintext: str | bytes, aes_key: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Encrypt plaintext using AES-256-GCM. Returns (nonce, ciphertext, tag) or None."""
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM)
        data_to_encrypt = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
        ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)
        return cipher.nonce, ciphertext, tag
    except Exception as e:
        logging.error(f"Payload encryption failed: {e}")
        return None

def decrypt_payload(nonce: bytes, ciphertext: bytes, tag: bytes, aes_key: bytes) -> str | None:
    """Decrypt ciphertext using AES-256-GCM. Returns plaintext string or None."""
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes.decode('utf-8')
    except (ValueError, KeyError, Exception) as e:
        logging.error(f"Payload decryption failed: {e}")
        return None

def encrypt_aes_key(aes_key: bytes, public_key_path: Path, master_key: bytes) -> str | None:
    """Encrypt an AES key using an RSA public key."""
    logging.info(f"Encrypting AES key with {public_key_path.name}")
    if not utils.check_file_exists(public_key_path, "Public key file"):
        return None
    try:
        with open(public_key_path, "rb") as f:
            encrypted_pub_key = f.read()
        pub_key_data = decrypt_key(encrypted_pub_key, master_key)
        pub_key = RSA.import_key(pub_key_data)
        cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA3_512)
        encrypted = cipher.encrypt(aes_key)
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logging.error(f"AES key encryption failed: {e}")
        return None

def decrypt_aes_key(encrypted_key_b64: str, private_key_path: Path, master_key: bytes) -> bytes | None:
    """Decrypt an AES key using an RSA private key."""
    logging.info(f"Decrypting AES key with {private_key_path.name}")
    if not utils.check_file_exists(private_key_path, "Private key file"):
        return None
    try:
        passphrase = getpass(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter passphrase for {private_key_path.name}: ")
        with open(private_key_path, "rb") as f:
            encrypted_priv_key = f.read()
        priv_key_data = decrypt_key(encrypted_priv_key, master_key)
        priv_key = RSA.import_key(priv_key_data, passphrase=passphrase)
        cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA3_512)
        return cipher.decrypt(base64.b64decode(encrypted_key_b64))
    except (ValueError, TypeError):
        logging.error("Invalid passphrase or corrupted key.")
        print(f"{utils.COLOR_RED}Invalid passphrase.{utils.COLOR_RESET}")
        return None
    except Exception as e:
        logging.error(f"AES key decryption failed: {e}")
        return None

def encrypt_file(input_path: Path, output_path: Path, aes_key: bytes, master_key: bytes, rsa_public_path: Path | None = None, for_stego=False, verbose=True):
    """Encrypt a file and optionally wrap the AES key with RSA."""
    logging.info(f"Encrypting '{input_path}' to '{output_path}'")
    try:
        file_data = utils.read_file_with_progress(input_path, verbose)
        if file_data is None: return None

        cipher = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        
        wrapped_key = b""
        if rsa_public_path:
            encrypted_aes_key_b64 = encrypt_aes_key(aes_key, rsa_public_path, master_key)
            if not encrypted_aes_key_b64: return None
            wrapped_key = base64.b64decode(encrypted_aes_key_b64)

        hasher = SHA3_512.new(file_data)
        file_hash = hasher.digest()
        
        rsa_flag = b"\x01" if rsa_public_path else b"\x00"
        wrapped_key_len = len(wrapped_key).to_bytes(2, 'big')
        
        full_data = ARCOVA_FILE_VERSION + rsa_flag + wrapped_key_len + wrapped_key + nonce + tag + file_hash + ciphertext

        if for_stego:
            return full_data
        else:
            with open(output_path, "wb") as f_out:
                f_out.write(full_data)
            logging.info(f"File encrypted successfully: {output_path}")
            return output_path
            
    except Exception as e:
        logging.error(f"File encryption failed: {e}")
        return None


def decrypt_file(input_path: Path, output_path: Path, master_key: bytes, aes_key: bytes | None = None, rsa_private_path: Path | None = None, verbose=True):
    """Decrypt a file and verify its integrity."""
    logging.info(f"Decrypting '{input_path}' to '{output_path}'")
    try:
        with open(input_path, "rb") as f_in:
            version = f_in.read(len(ARCOVA_FILE_VERSION))
            if version != ARCOVA_FILE_VERSION:
                logging.error(f"Unsupported file version: {version}")
                return None
            
            rsa_flag = f_in.read(1)
            wrapped_key_len = int.from_bytes(f_in.read(2), 'big')
            wrapped_key = f_in.read(wrapped_key_len)
            nonce = f_in.read(16)
            tag = f_in.read(16)
            stored_hash = f_in.read(64)
            ciphertext = f_in.read()

        if rsa_flag == b"\x01":
            if not rsa_private_path:
                logging.error("Decryption requires an RSA private key but none was provided.")
                return None
            aes_key = decrypt_aes_key(base64.b64encode(wrapped_key).decode(), rsa_private_path, master_key)
            if aes_key is None: return None
        
        if aes_key is None:
            logging.error("No AES key available for decryption.")
            return None

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        hasher = SHA3_512.new(plaintext)
        computed_hash = hasher.digest()
        
        if computed_hash != stored_hash:
            logging.error("File integrity check failed! Hash mismatch.")
            print(f"{utils.COLOR_RED}CRITICAL: File integrity check failed! The file may be corrupt or tampered with.{utils.COLOR_RESET}")
            return None
        
        with open(output_path, "wb") as f_out:
            f_out.write(plaintext)
        
        logging.info(f"File decrypted successfully: {output_path}")
        return output_path

    except Exception as e:
        logging.error(f"File decryption failed: {e}")
        return None