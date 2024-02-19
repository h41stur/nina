import os
from colorama import Fore
from colorama import init as colorama_init

# Color config
if os.name == 'nt':
    colorama_init(autoreset=True, convert=True)
    os.system('cls')
else:
    colorama_init(autoreset=True)

RESET = Fore.RESET
YELLOW = Fore.LIGHTYELLOW_EX
GREEN = Fore.LIGHTGREEN_EX
RED = Fore.LIGHTRED_EX
BLUE = Fore.LIGHTBLUE_EX

def warning_message(message) -> None:
    print(f"\n[{YELLOW}!{RESET}] {message}\n")

def error_message(message) -> None:
    print(f"\n[{RED}-{RESET}] {message}\n")

def running_message(message) -> None:
    print(f"\n{BLUE}[*] {message}{RESET}\n")

def ok_message(message) -> None:
    print(f"\n[{GREEN}+{RESET}] {message}")



