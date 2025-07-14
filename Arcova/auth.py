# src/Arcova/auth.py

import json
import time
import logging
from getpass import getpass
from argon2 import PasswordHasher, exceptions

from . import utils
from . import config
from . import cryptography as crypto

def load_users() -> dict:
    """Load user database from the file specified in config."""
    if not config.USER_DB_FILE.exists():
        return {}
    with open(config.USER_DB_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users: dict):
    """Save user database to the file specified in config."""
    with open(config.USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    return True, "Password is valid"

def register_user():
    """Register a new user with a username and password."""
    users = load_users()
    ph = PasswordHasher()

    utils.clear_screen()
    print(f"\n{utils.COLOR_CYAN}=== Arcova: New Operative Registration ==={utils.COLOR_RESET}")
    while True:
        username = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter username: ").strip()
        if not username:
            print(f"{utils.COLOR_RED}Username cannot be empty{utils.COLOR_RESET}")
            continue
        if username in users:
            print(f"{utils.COLOR_RED}Username already exists{utils.COLOR_RESET}")
            continue
        break

    while True:
        password = getpass(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter password: ")
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f"{utils.COLOR_RED}{message}{utils.COLOR_RESET}")
            continue
        confirm_password = getpass(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Confirm password: ")
        if password != confirm_password:
            print(f"{utils.COLOR_RED}Passwords do not match{utils.COLOR_RESET}")
            continue
        break

    hashed_password = ph.hash(password)
    users[username] = hashed_password
    save_users(users)
    
    print(f"{utils.COLOR_GREEN}Operative {username} registered successfully! You can now log in.{utils.COLOR_RESET}")
    logging.info(f"Operative {username} registered")
    time.sleep(2)


def authenticate_user() -> tuple[str | None, bytes | None]:
    """
    Authenticate a user and derive the master key.
    Returns (username, master_key) on success, or (None, None) on failure.
    """
    users = load_users()
    ph = PasswordHasher()
    max_attempts = 3

    if not users:
        print(f"{utils.COLOR_YELLOW}No operatives found. Initiating registration...{utils.COLOR_RESET}")
        time.sleep(1)
        register_user()
        users = load_users()

    for attempts_left in range(max_attempts, 0, -1):
        utils.clear_screen()
        print(f"{utils.COLOR_PURPLE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{utils.COLOR_RESET}")
        print(f"{utils.COLOR_PURPLE}┃        Arcova Secure Access Portal      ┃{utils.COLOR_RESET}")
        print(f"{utils.COLOR_PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{utils.COLOR_RESET}")
        print(f"{utils.COLOR_CYAN}=== Operative Authentication Required ==={utils.COLOR_RESET}")
        print(f"{utils.COLOR_YELLOW}Attempts remaining: {attempts_left}{utils.COLOR_RESET}")

        username = input(f"\n{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Operative ID (username): ").strip()
        if username not in users:
            print(f"{utils.COLOR_RED}Operative ID not found{utils.COLOR_RESET}")
            time.sleep(1)
            continue

        password = getpass(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Access Code (password): ")
        try:
            ph.verify(users[username], password)
            master_key = crypto.derive_master_key(password)
            logging.info(f"Operative {username} logged in successfully")
            return username, master_key
        except exceptions.VerifyMismatchError:
            print(f"{utils.COLOR_RED}Invalid access code{utils.COLOR_RESET}")
            logging.warning(f"Failed login attempt for user: {username}")
            time.sleep(1)

    print(f"\n{utils.COLOR_RED}Too many failed attempts. System lockdown initiated.{utils.COLOR_RESET}")
    logging.warning("System lockdown: Too many failed login attempts")
    time.sleep(2)
    return None, None
