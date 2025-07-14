# src/Arcova/config.py

import json
from pathlib import Path

HOME_DIR = Path.home()
APP_DATA_DIR = HOME_DIR / ".Arcova"

CONFIG_FILE = APP_DATA_DIR / "Arcova_config.json"
USER_DB_FILE = APP_DATA_DIR / "Arcova_users.json"
KEY_DIR = APP_DATA_DIR / "keys"

DEFAULT_CONFIG = {
    "key_dir": str(KEY_DIR),
    "default_output": "arcova_encrypted.bin",
    "default_aes_key_path": str(KEY_DIR / "aes_key.bin"),
    "default_rsa_public": str(KEY_DIR / "rsa_public.pem"),
    "default_rsa_private": str(KEY_DIR / "rsa_private.pem"),
    "default_x25519_private": str(KEY_DIR / "x25519_private.bin"),
    "default_x25519_public": str(KEY_DIR / "x25519_public.bin"),
    "master_key_path": str(KEY_DIR / "master_key.bin")
}

def load_config():
    """Load configuration from a JSON file or create a default one."""
    APP_DATA_DIR.mkdir(exist_ok=True)
    KEY_DIR.mkdir(exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

CONFIG = load_config()