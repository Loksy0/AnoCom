import os
import platform

from .main import *
from .message import *

def log(message, type, next_line=False):
    if next_line is False or next_line == "n":
        prefixes = {1: "[+]", 2: "[-]", 3: "[!]"}
    elif next_line is True or next_line == "y":
        prefixes = {1: "\n[+]", 2: "\n[-]", 3: "\n[!]"}
    print(f"{prefixes.get(type, '[?]')} {message}")

def clear():
    if platformsystem() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def use_them(win, lin):
    current_os = platform.system().strip()
    if current_os == "Windows":
        os.system(f"color {win}")
    else:
        print(lin, end="")
