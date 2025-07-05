import hashlib
import requests
import csv
import re
from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

def print_banner():
    f = Figlet(font='slant')
    print(f"{Fore.CYAN}{f.renderText('PWNAUDIT')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🔐 Password Audit Tool — Breach + Strength")
   


def check_password_strength(password):
    length = len(password) >= 8
    upper = re.search(r"[A-Z]", password)
    lower = re.search(r"[a-z]", password)
    digit = re.search(r"\d", password)
    symbol = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    score = sum(bool(x) for x in [length, upper, lower, digit, symbol])
    if score == 5: return "Very Strong"
    elif score == 4: return "Strong"
    elif score == 3: return "Moderate"
    elif score == 2: return "Weak"
    else: return "Very Weak"

def get_sha1_hash(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]

def check_password_breach(password):
    prefix, suffix = get_sha1_hash(password)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200: return -1

    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0


def single_password_mode():
    password = input(f"{Fore.GREEN}🔑 Enter the password to check: {Style.RESET_ALL}")
    strength = check_password_strength(password)
    breach_count = check_password_breach(password)

    print(f"\n{Fore.MAGENTA}Password: {Fore.CYAN}{password}")
    print(f"{Fore.YELLOW}Strength: {Fore.CYAN}{strength}")

    if breach_count > 0:
        print(f"{Fore.RED}⚠️ Found in {breach_count} breaches!")
    elif breach_count == 0:
        print(f"{Fore.GREEN}✅ This password was not found in any known breach.")
    else:
        print(f"{Fore.YELLOW}⚠️ API error — try again later.")


def bulk_password_mode():
    input_file = input(f"{Fore.GREEN}📂 Enter path to password file (.txt): {Style.RESET_ALL}").strip()
    output_file = input(f"{Fore.GREEN}💾 Enter name for output CSV: {Style.RESET_ALL}").strip()

    try:
        with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as csvfile:
            reader = infile.readlines()
            writer = csv.writer(csvfile)
            writer.writerow(['Password', 'Strength', 'Breach Count'])

            print(f"\n{Fore.MAGENTA}{'Password':<20} | {'Strength':<12} | {'Breach Status'}")
            print("-" * 55)

            for pwd in reader:
                pwd = pwd.strip()
                if not pwd:
                    continue
                strength = check_password_strength(pwd)
                breach_count = check_password_breach(pwd)

                if breach_count > 0:
                    breach_msg = f"{Fore.RED}{breach_count} breaches"
                elif breach_count == 0:
                    breach_msg = f"{Fore.GREEN}Safe"
                else:
                    breach_msg = f"{Fore.YELLOW}API Error"

                print(f"{Fore.CYAN}{pwd:<20} | {strength:<12} | {breach_msg}")
                writer.writerow([pwd, strength, breach_count])

        print(f"\n{Fore.GREEN}✅ Done! Results saved to {output_file}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}")


def main():
    print_banner()
    print(f"{Fore.BLUE}Select mode:")
    print(f"{Fore.BLUE}1. Single password check")
    print(f"{Fore.BLUE}2. Bulk password check (from file)")

    choice = input(f"{Fore.GREEN}Enter choice (1 or 2): {Style.RESET_ALL}").strip()
    if choice == '1':
        single_password_mode()
    elif choice == '2':
        bulk_password_mode()
    else:
        print(f"{Fore.RED}Invalid option. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
