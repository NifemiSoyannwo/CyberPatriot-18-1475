# Forensics Questions

## Forensics Question 1

Q: what is the welcome message when connecting to ftp

6 pts

W: `ftp localhost`

A: `220 Welcome to AFA`

## Forensics Question 2

Q: what users are locked out of ftp

6 pts

W: `sudo find / -name ftpusers`, find the file named `ftpusers`

A: `rzane` and `shuntley

# Checklist

## Disable guest accounts

`sudo nano /etc/lightdm/lightdm.conf`, `allow-guest=false`

# Remove unauthorized users

- tgianopolous
- jquelling

3 pts each

# Remove non-admins

- dscott

3 pts

## Change insecure password (FAILED)

- edarby

? pts

# Create users & make them an admin

- edarby

3 pts

## Require all users to change passwords at next login

- edarby

6 pts

## Set a default minimum password length (FAILED)

? pts

## Enable IPv4 TCP SYN Cookies (FAILED)

? pts

## Enable UFW

5 pts

## Fix insecure permissions on FTP root directory (FAILED)

? pts

## Disable OpenSSH (FAILED)

? pts

## Refresh the list of Updates Automatically

4 pts

## Install Update Automatically (FAILED)

? pts

## Install Updates from Important Security Updates

? pts

## Update Software

- Systemd
- Chromium
- Vsftpd

4 pts


## Prohibited MP3 files are removed

4 pts


## Remove Prohibited Software

- Wireshark
- Zangband
- aMule

4 pts each

## FTP users may log in with SSL



# Points Unaccounted for
Software Sources > Official Repos > Source code repositories (turn on) > save - 4 points
sudo apt install libpam-cracklib - 4 points

# My Done List


- Update manager > install updates (only gave points for updating chromium) - 4 points
- uninstall Zangband - 4 points
- removed wireshark packet in Synaptic Package Manager and then uninstall wireshark - 4 points
- cd /srv/afa and then rm *.mp3 - 4 points
- sudo apt update && sudo apt upgrade -y didn't do anything
- sudo nano /etc/ssh/sshd_config and then set PermitRootLogin to no didn’t do anything
- removed dscott from admins - 3 points
- removed jquelling - 3 points
- removed tgianopolus - 3 points
- created edarby - 3 points
- sudo nano /etc/login.defs and set pass max days to 90 and min days to 30
- sudo nano /etc/pam.d/common-password and add sha512 remember=5 to unix.so line
- Update manager > Edit > Preferences > Refresh List of Updates Automatically - 4 points
- Software Sources > Official Repos > Source code repositories (turn on) > save - 4 points
- Update manager > install updates  > update everything
  - 4 points for updating Systemd
  - 4 points for updating Vsftpd
- Reboot
- sudo passwd -S -a and check all users are P
- `sudo nano /etc/security/pquality.conf`
- sudo apt install libpam-cracklib - 4 points
  - seems you have to install lib-pam-cracklib to get the password minlen points
- Firewall Configuration > Enable - 5 points
- Upgrade to mint 21.3 Virginia
- Install Language Packs
- Install Multimedia Codecs
- deleted aMule - 4 points


