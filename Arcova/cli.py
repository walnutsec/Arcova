# src/Arcova/cli.py

import os
import time
import base64
import logging
from getpass import getpass
from pathlib import Path
from Crypto.Random import get_random_bytes

from . import utils
from . import config
from . import cryptography as crypto

def display_ascii():
    """Display the main header for Arcova."""
    header_text = "Arcova"
    header_width = len(header_text) + 16
    top_border = "┏" + "━" * (header_width - 2) + "┓"
    bottom_border = "┗" + "━" * (header_width - 2) + "┛"
    header_line = f"┃{' ' * 7}{header_text}{' ' * 7}┃"
    tagline = "✦ Secure the Void ✦"

    print(f"{utils.COLOR_PURPLE}{top_border}{utils.COLOR_RESET}")
    print(f"{utils.COLOR_PURPLE}{header_line}{utils.COLOR_RESET}")
    print(f"{utils.COLOR_PURPLE}{bottom_border}{utils.COLOR_RESET}")
    print(f"{utils.COLOR_CYAN}=== Arcova Encryption ==={utils.COLOR_RESET}")
    print(f"{utils.COLOR_YELLOW}Coded by: walnutsec | Powered by Walnutsec{utils.COLOR_RESET}")
    print(f"{utils.COLOR_GREEN}github: https://github.com/walnutsec{utils.COLOR_RESET}")
    print(f"Enjoy  | CTRL+C: Exit")
    print(f"{utils.COLOR_PURPLE}{tagline}{utils.COLOR_RESET}")

def embed_f5_cli(user):
    print(f"\n{utils.COLOR_CYAN}--- F5 Embed Steganography ---{utils.COLOR_RESET}")
    print(f"{utils.COLOR_YELLOW}Fitur ini sedang dalam pengembangan!{utils.COLOR_RESET}")
    input(f"{utils.COLOR_YELLOW}[!] Tekan Enter untuk kembali...{utils.COLOR_RESET}")

def extract_f5_cli(user):
    print(f"\n{utils.COLOR_CYAN}--- F5 Extract Steganography ---{utils.COLOR_RESET}")
    print(f"{utils.COLOR_YELLOW}Fitur ini sedang dalam pengembangan!{utils.COLOR_RESET}")
    input(f"{utils.COLOR_YELLOW}[!] Tekan Enter untuk kembali...{utils.COLOR_RESET}")


def interactive_menu(username: str, master_key: bytes) -> bool:
    """
    Display the interactive menu and handle user choices.
    Accepts username and the derived master_key.
    Returns True to logout, False to exit the program.
    """
    VERBOSE = True

    while True:
        try:
            utils.clear_screen()
            display_ascii()
            
            print(f"\n{utils.COLOR_CYAN}Welcome, Operative {username}.{utils.COLOR_RESET}")
            print(f"{utils.COLOR_CYAN}╔════════════════════════════════════╗")
            print(f"║            ARCOVA MENU             ║")
            print(f"╠════════════════════════════════════╣")
            print(f"║ 1. Generate Keys (RSA/X25519)      ║")
            print(f"║ 2. Encrypt Text (AES+RSA)          ║")
            print(f"║ 3. Decrypt Text (AES+RSA)          ║")
            print(f"║ 4. Encrypt File (AES+RSA)          ║")
            print(f"║ 5. Decrypt File (AES+RSA)          ║")
            print(f"║ 6. Generate Random AES Key         ║")
            print(f"║ 7. Embed Steganography (F5)        ║")
            print(f"║ 8. Extract Steganography (F5)      ║")
            print(f"║ 9. Toggle Verbosity                ║")
            print(f"║ 10. Logout                         ║")
            print(f"║ 11. Exit Program                   ║")
            print(f"╚════════════════════════════════════╝{utils.COLOR_RESET}")
            
            choice = input(f"\n{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Select (1-11): ").strip()

            if choice == '1':
                key_type = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Key type (RSA/X25519) [RSA]: ") or "RSA"
                save_dir_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Save dir [{config.KEY_DIR}]: ") or str(config.KEY_DIR)
                save_dir = Path(save_dir_str)
                save_dir.mkdir(exist_ok=True, parents=True)

                if key_type.upper() == "RSA":
                    size_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} RSA Size (2048/4096) [4096]: ") or "4096"
                    size = int(size_str) if size_str in ["2048", "4096"] else 4096
                    crypto.generate_keys("RSA", master_key, save_dir, rsa_size=size)
                else:
                    crypto.generate_keys("X25519", master_key, save_dir)
                input(f"{utils.COLOR_YELLOW}[!] Enter to continue...{utils.COLOR_RESET}")

            elif choice == '2':
                plaintext = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter text: ")
                if not plaintext:
                    print(f"{utils.COLOR_RED}Text cannot be empty{utils.COLOR_RESET}")
                    input(f"{utils.COLOR_YELLOW}[!] Enter to continue...{utils.COLOR_RESET}")
                    continue
                
                aes_key = get_random_bytes(32)
                encrypted_payload = crypto.encrypt_payload(plaintext, aes_key)
                if not encrypted_payload:
                    input(f"{utils.COLOR_YELLOW}[!] Encryption failed. Enter to continue...{utils.COLOR_RESET}")
                    continue
                
                nonce, ciphertext, tag = encrypted_payload
                output_b64 = base64.b64encode(nonce + ciphertext + tag).decode()
                
                use_rsa = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Use RSA to wrap AES key? (y/n) [y]: ").lower() or "y"
                if use_rsa == 'y':
                    pub_key_path_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} RSA public key path [{config.CONFIG['default_rsa_public']}]: ") or config.CONFIG['default_rsa_public']
                    pub_key_path = Path(pub_key_path_str)
                    
                    enc_key = crypto.encrypt_aes_key(aes_key, pub_key_path, master_key)
                    if enc_key:
                        print(f"{utils.COLOR_GREEN}Encrypted Text (Base64):{utils.COLOR_RESET} {output_b64}")
                        print(f"{utils.COLOR_GREEN}Encrypted AES Key (Base64):{utils.COLOR_RESET} {enc_key}")
                    else:
                        print(f"{utils.COLOR_RED}Failed to encrypt AES key.{utils.COLOR_RESET}")
                else:
                    print(f"{utils.COLOR_GREEN}Encrypted Text (Base64):{utils.COLOR_RESET} {output_b64}")
                    print(f"{utils.COLOR_YELLOW}AES Key (SAVE THIS!):{utils.COLOR_RESET} {aes_key.hex()}")
                
                logging.info(f"Operative {username}: Text encrypted with AES-256-GCM")
                input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")

            elif choice == '3':
                enc_text_b64 = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Encrypted text (Base64): ")
                if not utils.validate_input(enc_text_b64, "base64"):
                    print(f"{utils.COLOR_RED}Invalid Base64 format{utils.COLOR_RESET}")
                    continue

                use_rsa = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Was the key wrapped with RSA? (y/n) [y]: ").lower() or "y"
                if use_rsa == 'y':
                    priv_key_path_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} RSA private key path [{config.CONFIG['default_rsa_private']}]: ") or config.CONFIG['default_rsa_private']
                    priv_key_path = Path(priv_key_path_str)
                    enc_key_b64 = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Encrypted AES key (Base64): ")
                    aes_key = crypto.decrypt_aes_key(enc_key_b64, priv_key_path, master_key)
                else:
                    aes_key_hex = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter raw AES key (hex): ")
                    if not utils.validate_input(aes_key_hex, "hex"):
                        print(f"{utils.COLOR_RED}Invalid hex format{utils.COLOR_RESET}")
                        continue
                    aes_key = bytes.fromhex(aes_key_hex)
                
                if not aes_key:
                    print(f"{utils.COLOR_RED}Could not obtain AES key.{utils.COLOR_RESET}")
                    input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")
                    continue

                try:
                    data = base64.b64decode(enc_text_b64)
                    nonce, ciphertext, tag = data[:16], data[16:-16], data[-16:]
                    plaintext = crypto.decrypt_payload(nonce, ciphertext, tag, aes_key)
                    if plaintext:
                        print(f"{utils.COLOR_GREEN}Decrypted Text:{utils.COLOR_RESET} {plaintext}")
                    else:
                        print(f"{utils.COLOR_RED}Decryption failed. Check logs.{utils.COLOR_RESET}")
                except Exception:
                    print(f"{utils.COLOR_RED}Invalid encrypted data format.{utils.COLOR_RESET}")

                input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")

            elif choice == '4':
                input_file_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Input file path: ")
                input_file = Path(input_file_str)
                if not utils.check_file_exists(input_file):
                    continue
                
                output_file_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Output file path [{input_file_str}.arcova]: ") or f"{input_file_str}.arcova"
                output_file = utils.validate_file_path(output_file_str)
                if not output_file:
                    continue

                use_rsa = (input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Use RSA to wrap key? (y/n) [y]: ").lower() or "y") == 'y'
                pub_key_path = None
                if use_rsa:
                    pub_key_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} RSA public key path [{config.CONFIG['default_rsa_public']}]: ") or config.CONFIG['default_rsa_public']
                    pub_key_path = Path(pub_key_str)

                aes_key = get_random_bytes(32)
                result_path = crypto.encrypt_file(input_file, output_file, aes_key, master_key, rsa_public_path=pub_key_path, verbose=VERBOSE)

                if result_path:
                    print(f"{utils.COLOR_GREEN}File encrypted successfully:{utils.COLOR_RESET} {result_path}")
                    if not use_rsa:
                         print(f"{utils.COLOR_YELLOW}AES Key (SAVE THIS!):{utils.COLOR_RESET} {aes_key.hex()}")
                else:
                    print(f"{utils.COLOR_RED}File encryption failed. Check logs for details.{utils.COLOR_RESET}")
                input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")

            elif choice == '5':
                input_file_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Input file path (.arcova): ")
                input_file = Path(input_file_str)
                if not utils.check_file_exists(input_file):
                    continue

                default_output = input_file.with_suffix('') if input_file.suffix == '.arcova' else f"{input_file_str}.dec"
                output_file_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Output file path [{default_output}]: ") or str(default_output)
                output_file = utils.validate_file_path(output_file_str)
                if not output_file:
                    continue
                
                with open(input_file, 'rb') as f:
                    f.seek(len(crypto.ARCOVA_FILE_VERSION))
                    rsa_flag = f.read(1)

                aes_key = None
                priv_key_path = None
                if rsa_flag == b'\x01':
                    print(f"{utils.COLOR_YELLOW}RSA-wrapped key detected.{utils.COLOR_RESET}")
                    priv_key_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} RSA private key path [{config.CONFIG['default_rsa_private']}]: ") or config.CONFIG['default_rsa_private']
                    priv_key_path = Path(priv_key_str)
                else:
                    print(f"{utils.COLOR_YELLOW}Raw AES key required.{utils.COLOR_RESET}")
                    aes_key_hex = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Enter raw AES key (hex): ")
                    if utils.validate_input(aes_key_hex, "hex"):
                        aes_key = bytes.fromhex(aes_key_hex)
                    else:
                        print(f"{utils.COLOR_RED}Invalid hex format.{utils.COLOR_RESET}")
                
                result_path = crypto.decrypt_file(input_file, output_file, master_key, aes_key=aes_key, rsa_private_path=priv_key_path, verbose=VERBOSE)

                if result_path:
                    print(f"{utils.COLOR_GREEN}File decrypted successfully:{utils.COLOR_RESET} {result_path}")
                else:
                    print(f"{utils.COLOR_RED}File decryption failed. Check logs.{utils.COLOR_RESET}")
                input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")

            elif choice == '6':
                aes_key = get_random_bytes(32)
                print(f"{utils.COLOR_YELLOW}[*] Generated random AES-256 key...{utils.COLOR_RESET}")
                print(f"{utils.COLOR_GREEN}AES Key (hex): {aes_key.hex()}{utils.COLOR_RESET}")
                
                save_key = (input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Save encrypted key to file? (y/n) [y]: ").lower() or 'y') == 'y'
                if save_key:
                    save_path_str = input(f"{utils.COLOR_PURPLE}[>>]{utils.COLOR_RESET} Save to [{config.CONFIG['default_aes_key_path']}]: ") or config.CONFIG['default_aes_key_path']
                    save_path = utils.validate_file_path(save_path_str)
                    if save_path:
                        encrypted_key = crypto.encrypt_key(aes_key, master_key)
                        with open(save_path, 'wb') as f:
                            f.write(encrypted_key)
                        print(f"{utils.COLOR_GREEN}AES key encrypted and saved to:{utils.COLOR_RESET} {save_path}")
                input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")

            elif choice == '7':
                 embed_f5_cli(username)
            elif choice == '8':
                 extract_f5_cli(username)

            elif choice == '9':
                print(f"{utils.COLOR_GREEN}Verbosity {'enabled' if VERBOSE else 'disabled'}{utils.COLOR_RESET}")
                time.sleep(1)

            elif choice == '10':
                print(f"{utils.COLOR_PURPLE}[!] Logging out Operative {username}...{utils.COLOR_RESET}")
                time.sleep(1)
                return True

            elif choice == '11':
                return False

            else:
                print(f"{utils.COLOR_RED}Invalid choice, bro!{utils.COLOR_RESET}")
                time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n{utils.COLOR_PURPLE}[!] Operation aborted by user.{utils.COLOR_RESET}")
            return False
        except Exception as e:
            print(f"{utils.COLOR_RED}An unexpected error occurred: {e}{utils.COLOR_RESET}")
            logging.error(f"Operative {username}: Unhandled Exception - {e}", exc_info=True)
            input(f"{utils.COLOR_YELLOW}[!] Press Enter to continue...{utils.COLOR_RESET}")
