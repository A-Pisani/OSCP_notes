# How to Get a Fully Interactive Shell with zsh
1. Spawn a TTY shell:
    ```sh
    locate python       #choose the correct one 
    python -c "import pty; pty.spawn('/bin/bash')"
    python3 -c "import pty; pty.spawn('/bin/bash')"
    ```
2. Background the process using <kbd>CTRL</kbd> + <kbd>Z</kbd>.
3. On Kali, get the number of rows and columns and the terminal:
    ```sh
    kali@kali:~$ stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'
    rows 35
    columns 157
    kali@kali:~$ echo $TERM
    screen-256color
    ```
4. On Kali, to return to your reverse shell:
    ```sh
    kali@kali:~$ stty raw -echo; fg
    # Note: For zsh users it is important to enter this in one line!
    ```
5. Configure your rows and columns and export term (match point 3):
    ```sh
    stty rows 35 cols 157
    export TERM=screen-256color
    ```
6. All you need to do now, is reload your shell:
    ```sh
    exec /bin/bash
    ```

- Notes:
  - Since normal <kbd>CTRL</kbd> + <kbd>C</kbd> won’t close this shell, you have to kill its process .
  - If your shell prompt is messed up after exiting, type `stty sane`.
- References:
  - https://gabb4r.gitbook.io/oscp-notes/shell/upgrading-shell
  - [Upgrade a Dumb Shell to a Fully Interactive Shell for More Flexibility](https://null-byte.wonderhowto.com/how-to/upgrade-dumb-shell-fully-interactive-shell-for-more-flexibility-0197224/)
  
# Escape Restricted Shells
If Bash is started with the name rbash, or the --restricted or -r option is supplied at invocation, the shell becomes restricted. A restricted shell is used to set up an environment more controlled than the standard shell.
- References:
    - [Escape from Restricted Shells](https://0xffsec.com/handbook/shells/restricted-shells/)
    - [The Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
