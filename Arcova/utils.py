# src/Arcova/utils.py

import os
import sys
import base64
import logging
from pathlib import Path
from tqdm import tqdm

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_PURPLE = "\033[95m"
COLOR_RESET = "\033[0m"

def setup_logging():
    """Initializes basic logging configuration."""
    from .config import APP_DATA_DIR
    log_file = APP_DATA_DIR / "arcova.log"
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def clear_screen():
    """Clears the console screen, compatible with Windows and Linux/macOS."""
    os.system('cls' if os.name == 'nt' else 'clear')

def check_file_exists(file_path: Path, file_description="File") -> bool:
    """Check if a file exists and is readable using pathlib."""
    try:
        if not file_path.exists():
            print(f"{COLOR_RED}{file_description} not found: {file_path}{COLOR_RESET}")
            logging.error(f"{file_description} not found: {file_path}")
            return False
        if not file_path.is_file():
            print(f"{COLOR_RED}{file_description} is not a file: {file_path}{COLOR_RESET}")
            logging.error(f"{file_description} is not a file: {file_path}")
            return False
        return True
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Error accessing {file_description}: {e}{COLOR_RESET}")
        logging.error(f"Error accessing {file_description}: {e}")
        return False

# FUNGSI YANG HILANG DITAMBAHKAN DI SINI
def validate_file_path(file_path_str: str) -> Path | None:
    """Validate that a file path is not empty and the parent directory exists."""
    if not file_path_str:
        print(f"{COLOR_RED}File path cannot be empty{COLOR_RESET}")
        return None
    try:
        path = Path(file_path_str)
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        return path
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Invalid or inaccessible file path: {e}{COLOR_RESET}")
        return None

def validate_input(text: str, input_type="hex") -> bool:
    """Validate input based on type (hex or base64)."""
    try:
        if input_type == "hex":
            bytes.fromhex(text)
        elif input_type == "base64":
            base64.b64decode(text)
        return True
    except (ValueError, TypeError):
        return False

def read_file_with_progress(file_path: Path, verbose: bool = True):
    """Read a file with a progress bar."""
    try:
        file_size = file_path.stat().st_size
        data = b""
        with open(file_path, "rb") as f:
            with tqdm(total=file_size, desc="Reading", unit="B", unit_scale=True, disable=not verbose) as pbar:
                while chunk := f.read(1024 * 16):
                    data += chunk
                    pbar.update(len(chunk))
        return data
    except (PermissionError, OSError) as e:
        print(f"{COLOR_RED}Error reading file: {e}{COLOR_RESET}")
        logging.error(f"Error reading file {file_path}: {e}")
        return None