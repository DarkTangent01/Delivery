### Table of Contents
-	System_scan
-	Enumeration_website
	-	Enumeration: MatterMost
-	Enumeration: HelpDesk
-	Accessing MatterMost
-	Server Enumeration and Privilege Escalation
	-	Cracking the Password with ```hashcat```
		-	Identifying the Hash Type
		-	Hashcat Rules
		-	Putting It All Together
	-	Owning Root
-	Conclusion
-	Reference

Delivery is an "Easy" machine on HackTheBox.

### System Scan
As always, best practice to run nmap against the system.

``` bash
sudo nmap -sS -sV -sC -oN nmap/initial -p- 10.10.10.222
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-27 18:23 IST
Nmap scan report for 10.10.10.222
Host is up (0.048s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
8065/tcp open  unknown

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.96 seconds
```
I suggest you run this ```nmap``` command on your local machine, since I've cleaned up the output a bit for formatting. If you're new to ```nmap``` and are curious about the flags, here's what they all do.

-	```-sS``` for stealth scanning
-	```-sV``` to get versions of services
-	```-sC``` run common scripts
-	```-p-``` on all ports

The scan found three services running:
-	22: SSH; Usually not exploitable, but good to know if credentials are obtained.
-	80: Web Server; Biggest attack vector. Needs further enumeration.
-	8065: Unknown Service; Looks like some form of web service according to the nmap scripts ran against it.

Start with the biggest attack vector, and enumerate the website running on port 80.

### Enumeration: website
![[Pasted image 20210402192024.png]]
Very basic landing page with information about a delivery company. There is not much to go on here. Reading the content and viewing the Contact section, there are few links to other services:
-	http://helpdesk.delivery.htb/
-	http://delivery.htb:8065/

Since ```.htb``` is not a real top level domain, and ```:8065``` was the unknown service that ```nmap``` reported, it's a safe assumption that these are local to this machine. Sad thing is, the links don't work! This can be fixed though ! We can edit the ```/etc/hosts``` file on our kali box to tell the web browser that any DNS resolution of those URLs should point to the IP address of the HTB server.

---------------------------------------------------------------

``` bash 
127.0.0.1 localhost  
127.0.1.1 user  
10.10.10.222 delivery.htb helpdesk.delivery.htb # add this line to the file  
The following lines are desirable for IPv6 capable hosts  
::1 localhost ip6-localhost ip6-loopback  
ff02::1 ip6-allnodes  
ff02::2 ip6-allrouters
```

---------------------------------------------------------------
You can add the host by following command: ``` sudo nano /etc/hosts```

Now we can go to http://delivery.htb/ and it will display the same landing page as before. Going to the other external links, we find two other services running on this box.
-	HelpDesk: osTicket Support Ticket System
-	MatterMost (the unknown service running on 8065)

MatterMost sounds pretty interesting, so let's start with that.

### Enumeration: MatterMost
![[Pasted image 20210402194726.png]]

What is MatterMost ?

---------------------------------------------------------------
> MatterMost is an open-source, self-hostable online chat service with file sharing, search, and intergrations. It is designed as an internal chat for organisations and companies, and mostly markets itself as an open-source alternative to Slack and Microsoft Teams.

---------------------------------------------------------------

This is a fairly new piece of software, written in Go. There's nothing related to MatterMost on ExploitDB (at the time of writing), and the only article I found about exploting MatterMost seems to refernce an older version, and is from a few years back. Not too much to go on here for public exploits.

A quick glance at the service, though, it looks like it has open registration. We can try to register an account and view the channels on the system. Filling out some basic information, we can create a user.
![[Pasted image 20210402195331.png]]
```Email Verification Required```

but wait need to verify our account. This is a default settings in MatterMost. That's a shame. Not much we can do. Without knowing the code, or a valid email, there's no way (that I could find) to bypass the email verification. Machine on HTB won't send emails out (I tried using a throw-away email). Remember, don't pu PII on these publicly available machines.

Looks like we've hit a dead-end. Time to circle-back and investigate the Help Desk service.

### Enumeration: HelpDesk
![[Pasted image 20210402195838.png]]
This looks to be powerd by osTicket's Support Ticket System. A widely-used and trusted open source support ticketing system. Can't determine which version of the software it's currently running. There are a handful of exploits on ExploitDB, but is doesn't look like they are applicable to our situation. Other than trying to log in, the only other interaction is to Open a Ticket.

Rereading the Contact Us Section of the main website, it says to access the MatterMost service, one needs to get in touch with the HelpDesk.

---------------------------------------------------------------
> For unregistered users, please use our HelpDesk to get in touch with our team. Once you have an ```@delivery.htb``` email address, you'll be able to have access to our MatterMost server.

---------------------------------------------------------------
To get the confirmation email, we'll need to access the support ticket created earlier. Going back to the Help Desk, and use the Check Ticket Status option. View the ticket, use the ticket ID and the cutomer email (sme@local.host) to view the data.
![[Pasted image 20210402203434.png]]

Check the page for the confirmation link to MatterMost.
![[Pasted image 20210402203559.png]]
Copy/paste the confirmation URL into the web browser and gain access to the MatterMost instance.
![[Pasted image 20210402203713.png]]
Looking at the thread we see one other user ```root``` and some SSH credentials. There's also a message to stop using a common password variation because of how easily it can be exploited. Let's try accessing the box using the SSH credentials provided in the thread.

### Server Enumeration and Privilege Esclation
The ```maildeliverer``` user is a basic user, with no sudo privileges. There are no obvious services that are running on the box as ```root```. However, there is MySQL database running. Which makes sense. The ticketing system needs a way to store data, and it would't suprise me if mattermost used a DB on the backend as well.
After some failed attempts, the ```maildeliverer``` can't log into the database, and ```root``` account is password protected. We'll need to hunt for the database credentials on the system.
The mattermost configuration file is located in ```/opt/mattermost/config/config.json``` and contains credentials to the MySQL database user ```SqlSettings```. The username and password are in plain-text and can be used to log in to the database.
![[Pasted image 20210404130151.png]]
Command for accessing the database: ``` mysql -u mmuser -D mattermost -p```

Obtain the username and password of the only other user on the mattermost instance.

> SELECT username, password FROM Users WHERE username = 'root';

We can now see the hash of the ```root``` user's password! Save this to a file called ```hash.txt```.

### Cracking the Password with ```hashcat```
The next task is to crack the hash of the ```root``` user's mattermost password. Remember the comment that was made on the mattermost channel?

>Also please create a program to helps us stop re-using the same passwords everywhere... . Especially those that are variant of "PleaseSubscribe!"
>
>PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases.

We're going to use ```PleaseSubscribe!``` as our wordlist. Create a new file called ```wordlist.txt``` and add ```PleaseSubscribe!``` to it. We'll have ```hashcat``` do a rule based attack to try and find the password.

### Identifying the Hash Type
Before we can attempt to crack the password, we need to figure out what type of hash this is. We'll need to provide the mode for ```hashcat```, but more on that later.

To identify the hash, I am a fan of using ```hashid```.

``` bash
hashid
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
Analyzing '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
```

We know that we need to user the ```bcrypt``` hash mode in hashcat. Flipping through the ```man``` page, we can see that is mode 3200.

### Hashcat Rules

Stole from the hashcat Wiki page:
> The rule-based attack is one of the most complicated of all the attack modes. The reason for this is very simple. The rule-based attack is like a programming language designed for password candidate generation.

### Putting It Alll Together
Here is the output of ```hashcat```
```bash
hashcat -a 0 -m 3200 hash wordliststxt -r Hob0Rules/d3adhob0.rule -o racked.txt -w 3 -O
Session..........: hashcat 
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v...JwgjjO
Time.Started.....: Wed Jan 27 12:47:22 2021 (42 mins, 34 secs)
Time.Estimated...: Wed Jan 27 13:29:56 2021 (0 secs)
Guess.Base.......: File (wordlist.txt)
Guess.Mod........: Rules (Hob0Rules/d3adhob0.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       16 H/s (3.88ms) @ Accel:16 Loops:64 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 39796/57540 (69.16%)
Rejected.........: 0/39796 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:39795-39796 Iteration:960-1024
Candidates.#1....: PleaseSubscribe!toMyBlog -> PleaseSubscribe!toMyBlog

Started: Wed Jan 27 12:46:51 2021
Stopped: Wed Jan 27 13:29:57 2021
```
If you're new to ```hashcat``` or want to understand how the flags on this operate, here's the breakdown:
-	```-a 0``` specifies an attack mode, with zero being the straight mode. This saying to use all words in a list.
-	```-m 3200``` specifies the hash type. As we researched earlier, this is a bcrypt hash which is number 3200 for hashcat.
-	```hash``` the file containing the hashes to be cracked.
-	```wordlists.txt``` is the "dictionary" we're using for our straight mode attack.
-	```-r Hob0Rules/d3adhob0.rule``` is the rule we want to use, manipulating the words in the dictionary according to the rules in the file.
-	```-o cracked.txt``` tells hashcat to write the cracked hashes to a file called ```cracked.txt```.
-	```-w 3``` set the workload profile. Setting this to ```3``` gives a more tuned experice on your desktop, but it can also be slowe. To utilize more of your GPU, use a workload settings of ```1```, but your desktop will probably lag. The default settings is ```2```.
-	```-O``` is shorthand for ```--optimized-kernal-enable```, this limits the password length.

### Owning Root
Remember, this is the password for the MatterMost account named root. However, I'm going to try and hope that there is some password reuse here, and try to switch to the ```root``` user on the server using this new password.
> su root

![[Pasted image 20210404151640.png]]

### Conclusion
This box really opened up my eyes to one thing when enumerating a target: read, READ, REad. One thing I find myself doing is overlooking the content on website, chat messages, emails, etc. This really reminded me that I don't need to speed-run these challenges. Take my time, read the content, really enumerate. Delivery was really an exciting machine for me. Every step forward brought a grin to my fcae and really pushed my drive to get root on the machine.

### Reference
- Basic Port Scanning with nmap
- Using an /etc/hosts/ file for custome domains during development
- MatterMost
- osTicket
- hashcat | Rules Based Attacks
- Hob0Rules Source code