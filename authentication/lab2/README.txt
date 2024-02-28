
usage: lab2.py -t TARGET -u USER -p PASSWORD

2FA bypassing

options:
  -h, --help            show help message and exit
  -t TARGET, --target TARGET
                        Victim url (Ex: -u https://www.example.com)
  -u USER, --user USER  -> User's victim
  -p PASSWORD, --password PASSWORD -> Password's victim

Example:

  python3 lab2.py -t https://example.com -u carlos -p password
