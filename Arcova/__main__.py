# src/Arcova/__main__.py

import sys
from . import auth, cli, utils, config

def main():
    """Main function to run the NCP application."""
    utils.setup_logging()
    utils.clear_screen()
    
    username, master_key = auth.authenticate_user()
    if not username:
        sys.exit(1)

    while cli.interactive_menu(username, master_key):
        utils.clear_screen()
        username, master_key = auth.authenticate_user()
        if not username:
            sys.exit(1)
            
    print(f"\n{utils.COLOR_PURPLE}[!] Warping out... Thank you for using Arcova.{utils.COLOR_RESET}")
    sys.exit(0)

if __name__ == "__main__":
    main()