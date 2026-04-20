import random

COLORS = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
RESET = "\033[0m"


def print_banner():
    lines = [
        "",
        r"    _      _ _          ___       _                       ",
        r"   /_\  __| (_)___ ___ | _ ) __ _| |_  __ _ _ __  __ _ ||_",
        r"  / _ \/ _` | / _ (_-< | _ \/ _` | ' \/ _` | '  \/ _` (_-<",
        r" /_/ \_\__,_|_\___/__/_|___/\__,_|_||_\__,_|_|_|_\__,_/ _/",
        r"                    |___|                              ||.  ",
        "",
        "         Telegram : @mypasswordisadmin",
        "",
    ]
    color = random.choice(COLORS)
    for line in lines:
        print(color + line + RESET)
