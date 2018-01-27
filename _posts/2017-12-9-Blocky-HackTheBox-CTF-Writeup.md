---
title:  "Blocky HackTheBox CTF Writeup"
date:   2017-12-09 15:04:23
categories: [CTF]
tags: [HackTheBox, CTF, Hacking, Ethical Hacking, WarGames]
---

![](https://cdn-images-1.medium.com/max/800/1*NfL_pvv2rFuWhFwS7xUJ-g.png)


Welcome to my write up for the Blocky box from [HackTheBox.eu](https://www.hackthebox.eu/) !
Hack The Box is an online platform that allows you to test your penetration testing skills and exchange ideas and methodologies with other members of similar interests. It contains several challenges that are constantly updated.
As an individual, you can complete a simple challenge to prove your skills and then create an account, allowing you to connect to our private network (HTB Labs) where several machines await for you to hack them.
If you want to jack some boxes yourself, try to [hack the invite code](https://www.hackthebox.eu/invite) in order to become a member and get involved. It is a lot of fun!

Without any more talk, lets proceed to the Blocky CTF and my writeup of the penetration tests I ran against it. Please comment with any questions!


Target Machine: `10.10.10.37`


    root@kali:~/Desktop# nmap -sV -sC 10.10.10.37
    Starting Nmap 7.40 ( https://nmap.org ) at 2017–11–16 02:11 EST
    Nmap scan report for 10.10.10.37
    Host is up (0.14s latency).
    Not shown: 996 filtered ports
    PORT STATE SERVICE VERSION
    21/tcp open ftp ProFTPD 1.3.5a
    22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    | 2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
    |_ 256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
    80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
    |_http-generator: WordPress 4.8
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: BlockyCraft &#8211; Under Construction!
    8192/tcp closed sophos
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 24.44 seconds

Used DirBuster and the word list `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` Some interesting files/folders I found were `phpMyAdmin`a `plugins` directory with multiple Java Archive files and the Wordpress login page.


![](https://cdn-images-1.medium.com/max/800/1*c5rFpft213VIdwmZtojWMA.png)

![](https://cdn-images-1.medium.com/max/800/1*6u1ACcGZ3Yh1WtE-v4OC7A.png)


I downloaded the Jar files and decompiled BlockyCore.jar and …

![](https://cdn-images-1.medium.com/max/800/1*A-75IhKB-XSVltYajm_feA.png)


In plain text we can see that the credentials for phpMyAdmin.

![](https://cdn-images-1.medium.com/max/1000/1*nfFODtNW6i_LYxwZ2G0C3Q.png)


Once we log in into phpMyAdmin I started looking through the SQL database tables and the wordpress users were stored in the `wp_users` table.

![](https://cdn-images-1.medium.com/max/1000/1*2q0Cm_4ZgpAAOaMUKgQJyQ.png)


I changed the password to `test123`for the user Notch

![](https://cdn-images-1.medium.com/max/1000/1*XynWcCnmy3EOkYNRqXt-0g.png)


And using the new credentials I logged into the wordpress of dashboard

![](https://cdn-images-1.medium.com/max/1000/1*LLUWyJk9czfuQ7WqkNUNvw.png)

![](https://cdn-images-1.medium.com/max/1000/1*MIPB4HlMhyg6Zx8wXKemGA.png)


Then I uploaded my php reverse shell

![](https://cdn-images-1.medium.com/max/1000/1*Ve_t4jD9VlW1AZQDtAkE-A.png)


I hit a dead end I couldn’t figure out how to elevate my privileges so I went back and grabbed that password from the jar file and tried logging in through ssh with the same password and it worked!

![](https://cdn-images-1.medium.com/max/800/1*_qRPUNkhljzS5ZCbg7cYsA.gif)

![](https://cdn-images-1.medium.com/max/800/1*b8_dQRbVciJkp7vxTAFRKA.png)


Now for the *hardest* part **Privilege Escalation.** I spent a long time enumerating the system but got nothing … How about we try the same password we got for phpMyAdmin for the SSH service as root …

![](https://cdn-images-1.medium.com/max/800/1*0dihYv3rHZPMrYxuM9GaHw.png)

![](https://cdn-images-1.medium.com/max/800/1*IIi1hOP8eJs41HkWJN0ZTg.gif)


Overall this box was easy but very frustrating I was over thinking it way too much. But the point it’s trying to get across is the dangers of password reuse. You should never use the same password on multiple accounts. If you do this, and an attacker is able to figure out your password for one account, he or she will be able to access all of your accounts. Also, I recommend using a different username for sensitive accounts.

So how does one reduce the risk of password reuse attacks. Here are a few actions:

1. Enable Two Factor Authentication (2FA) for all applications that support it
2. Use a password manager to manage logins across applications like
3. - LastPass
4. - Intel True Key
5. - Dashlane
6. - RoboForm
7. - KeePass (Local vault)
8. Use a password generator along with a password manager.
9. Change your password frequently .
![](https://cdn-images-1.medium.com/max/800/1*bJQCbeKE8pEPR_P2jjgIkQ.png)


You can follow me on twitter [@0katz](https://www.twitter.com/0katz)

## #TogetherWeHitHarder
