#!/bin/bash

#functions
#------------------------------------------------------------------------------------------
function space(){
    echo " "
    echo " "
}
function red(){
  printf "\033[31m$1\033[0m"
}
function green(){
  printf "\033[32m$1\033[0m"
}
function yellow(){
  printf "\033[33m$1\033[0m"
}
function blue(){
  printf "\033[34m$1\033[0m"
}
function purple(){
  printf "\033[35m$1\033[0m"
}
function dblue(){
  printf "\033[36m$1\033[0m"
}
#------------------------------------------------------------------------------------------

#LEGAL NOTICE
#------------------------------------------------------------------------------------------
space
echo "Script made by Puru Jain for CyberPatriot. If this script is found, it is not to be used for anyone's use in the CyberPatriot competitions"
space
#------------------------------------------------------------------------------------------


#Get rid of all aliases + update sources
#------------------------------------------------------------------------------------------
alias
space
red "REMEMBER ATTRIBUTES SUCH AS IMMUTABLE EXIST"
space
red "Change any unwanted alias by manual inspection, use unalias (aliasname) to get rid of alias"
read alias
space
red "Check for poisoned files by using debsums -c and fix it (research/replace it with correct file)"
read ao
#------------------------------------------------------------------------------------------

#prompts user for current user
#------------------------------------------------------------------------------------------
space
yellow "Current working directory is" ; pwd
space
blue "What is the name of the user you are currently using?"
read CUSER
#------------------------------------------------------------------------------------------

#Updates
#------------------------------------------------------------------------------------------
dnf config-manager --set-disabled fedora-cisco-openh264
dnf config-manager --set-disabled updates-testing-modular
dnf config-manager --set-enabled fedora
dnf config-manager --set-enabled updates
dnf config-manager --set-enabled updates-testing
dnf config-manager --set-enabled fedora-modular
dnf config-manager --set-enabled updates-modular
space
red "Make sure your update settings are up to date"
space
red "Make sure updates are displayed immediatly, script takes cares of the rest"
space
read ANSWER
sudo dnf update
sudo dnf install dnf-automatic
sudo dnf install dnf
sudo dnf install firewalld
space
#------------------------------------------------------------------------------------------

#Clamav Full Scan
#------------------------------------------------------------------------------------------
sudo dnf install clamav
#ClamAV
printf "\033[1;31mStarting CLAMAV scan...\033[0m\n"
systemctl stop clamav-freshclam
freshclam --stdout
systemctl start clamav-freshclam
mkdir /home/$CUSER/Desktop/malware
echo "Put this in another terminal:"
space
echo "clamscan --move=/home/$CUSER/Desktop/malware --alert-encrypted=yes --scan-archive=yes --scan-html=yes --scan-elf=yes --scan-pdf=yes --follow-file-symlinks=0 --follow-dir-symlinks=0 --exclude-dir=sys --exclude-dir=snap --exclude-dir=/usr/lib --exclude-dir=proc -ro /"
space
space
red "Press enter when you're done pasting that in. "
space
read y
#------------------------------------------------------------------------------------------

#Add new users 
#----------------------------------------------------------------------------------------
space
echo "Adding new users..."
space

for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/newusers.txt` ; do sudo useradd $i > /dev/null 2>&1 ; echo $i >> /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt; echo "Added new user " $i ; done

for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/newusers.txt` ; do echo "Changing password for " $i ; sudo passwd $i ; done

space
echo "Done adding new users"
space
#----------------------------------------------------------------------------------------
#Changing Passwords by asking user to place users in passwords.txt
#------------------------------------------------------------------------------------------
space
red "Starting by changing passwords..."
space
yellow "Enter names of all authorized users (Not yourself)(separated by lines): " /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt
space

for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt` ; do echo $i:"dq*eb5,69~n)_-JU<&V8" | sudo chpasswd ;  echo "Done changing password for: " $i " ...";  done
echo "root:dq*eb5,69~n)_-JU<&V8" | sudo chpasswd; echo "Done changing password for: root..."
space
space
echo "Done changing passwords..."
#------------------------------------------------------------------------------------------

#fix shell
#------------------------------------------------------------------------------------------
for line in $(cat /etc/passwd | cut -d ":" -f 1)
	do
		if [ $(id -u $line) -lt 1000 ]
		then
			sudo usermod -s /bin/false $line
		fi
		
		if [ $(id -u $line) -eq 0 ] || [ $(id -u $line) -gt 999 ]
		then
			sudo usermod -s /bin/bash $line
		fi
	done
#-----------------------------------------------------------------------------------------

#Remove unauthorized admins
#------------------------------------------------------------------------------------------
space
echo "Add the authorized admins in " /home/$CUSER/Desktop/Scripting-main/Scripting-main/admins.txt
space
echo "Changing admins..."
space

#for loop to read all usernames
for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt` ; do sudo gpasswd -d $i wheel > /dev/null 2>&1 ; sudo gpasswd -d $i adm  > /dev/null 2>&1 ; echo "Removed " $i " as an admin"; done


for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/admins.txt` ; do sudo gpasswd -a $i wheel > /dev/null 2>&1 ; sudo gpasswd -a $i adm > /dev/null 2>&1; echo "Added " $i " as an admin"; done

space
echo "Done changing admins "


#------------------------------------------------------------------------------------------

#chage stuff
#----------------------------------------------------------------------------------------
for line in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt` ; do chage -M 15 -m 6 -W 7 -I 5 $line; done
#----------------------------------------------------------------------------------------

#Delete unauthorized users
#----------------------------------------------------------------------------------------

echo $CUSER >> users.txt

#list of all non-system users
grep -E 1[0-9]{3}  /etc/passwd | sed s/:/\ / | awk '{print $1}' > /home/$CUSER/Desktop/Scripting-main/Scripting-main/allusers.txt

#list of all bad users
grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt /home/$CUSER/Desktop/Scripting-main/Scripting-main/allusers.txt > /home/$CUSER/Desktop/Scripting-main/Scripting-main/badusers.txt

#delete all bad users
for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/badusers.txt` ; do sudo userdel $i > /dev/null 2>&1 ; echo "Deleted user " $i;  done

#Check and Change UID's of 0 not Owned by Root
printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users! I'm fixing it now!"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... "
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "WARNING: UID CHANGE UNSUCCESSFUL!"
		else
			echo "Successfully Changed Zero UIDs!"
		fi
	else
		echo "No Zero UID Users"
	fi

#------------------------------------------------------------------------------------------

#manual passwd + group inspection

space 
red "MAKE SURE TO CHECK FOR HIDDEN USERS - COMPARE COMPARE COMPAREEEEEEE (urgot was a hidden user with an id < 1000 which made it hide as a system user), y to continue"
read a
echo "Press y to check /etc/passwd"
read ha
nano /etc/passwd
space
echo "Press y to check /etc/group"
read h
nano /etc/group
space
#------------------------------------------------------------------------------------------

#unlock users
#------------------------------------------------------------------------------------------
for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt` ; do sudo usermod -U $i; sudo passwd -u $i; echo "Unlocked user " $i; done 
#-----------------------------------------------------------------------------------------



#enable firewall
#------------------------------------------------------------------------------------------
sudo systemctl enable firewalld
sudo systemctl start firewalld
sudo firewall-cmd --set-default-zone=public
space

red "MAKE SURE YOU OPEN PORTS FOR CRITICALS!!!!!! For example do: sudo firewall-cmd --add-port=22/tcp for SSH"
space
#------------------------------------------------------------------------------------------

#installs critical stuff
#------------------------------------------------------------------------------------------
echo "Make sure to install critical services before continuing!!!!"
echo "Press y when you are done installing them (in another terminal)"
read y

#------------------------------------------------------------------------------------------

#deletes commonly known bad packages

if `grep -Fxq "httpd" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove httpd -y > /dev/null 2>&1
fi

if `grep -Fxq "mysql" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove mysql-server -y > /dev/null 2>&1
fi

if `grep -Fxq "ssh" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove openssh-server -y > /dev/null 2>&1
fi

if `grep -Fxq "samba" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove samba -y > /dev/null 2>&1
fi

if `grep -Fxq "vsftpd" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove vsftpd -y > /dev/null 2>&1
fi

if `grep -Fxq "proftpd" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove proftpd -y > /dev/null 2>&1
fi

if `grep -Fxq "ncftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove ncftp -y > /dev/null 2>&1
fi

if `grep -Fxq "tnftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    :
else
    sudo dnf remove tnftp -y > /dev/null 2>&1
fi

if `grep -Fxq "tftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo dnf remove tftp -y > /dev/null 2>&1
fi

#------------------------------------------------------------------------------------------

#update important packages
#------------------------------------------------------------------------------------------
sudo dnf install firefox -y
sudo dnf install nautilus -y
sudo dnf install kernel-core -y
space
red "Now go update firefox settings and then press y"
space
read as
#------------------------------------------------------------------------------------------

#Delete unwanted files
#------------------------------------------------------------------------------------------
printf "\033[1;31mDeleting dangerous files...\033[0m\n"

#--------- Delete Dangerous Files ----------------
cd /
sudo find / -name '.mp3' -type f -delete > /dev/null 2>&1
echo "Done deleting mp3 files"
sudo find / -name '.tgz' -type f -delete > /dev/null 2>&1
echo "Done deleting tgz files"
sudo find / -name '.mov' -type f -delete > /dev/null 2>&1
echo "Done deleting mov files"
sudo find / -name '.mp4' -type f -delete > /dev/null 2>&1
echo "Done deleting mp4 files"
sudo find / -name '.avi' -type f -delete > /dev/null 2>&1
echo "Done deleting avi files"
sudo find / -name '.mpg' -type f -delete > /dev/null 2>&1
echo "Done deleting mpg files"
sudo find / -name '.mpeg' -type f -delete > /dev/null 2>&1
echo "Done deleting mpeg files"
sudo find / -name '.flac' -type f -delete > /dev/null 2>&1
echo "Done deleting flac files"
sudo find / -name '.m4a' -type f -delete > /dev/null 2>&1
echo "Done deleting m4a files"
sudo find / -name '.flv' -type f -delete > /dev/null 2>&1
echo "Done deleting flv files"
sudo find / -name '.ogg' -type f -delete > /dev/null 2>&1
echo "Done deleting ogg files"
sudo find /home -name '.gif' -type f -delete > /dev/null 2>&1
sudo find /root -name '.gif' -type f -delete > /dev/null 2>&1
echo "Done deleting gif files"
sudo find /home -name '.png' -type f -delete > /dev/null 2>&1
sudo find /root -name '.png' -type f -delete > /dev/null 2>&1
echo "Done deleting png files"
sudo find /home -name '.jpg' -type f -delete > /dev/null 2>&1
sudo find /root -name '.jpg' -type f -delete > /dev/null 2>&1
echo "Done deleting jpg files"
sudo find /home -name '.jpeg' -type f -delete > /dev/null 2>&1
sudo find /root -name '*.jpeg' -type f -delete > /dev/null 2>&1
echo "Done deleting jpeg files"
space
red "Delete the Suspicious PDF files that shouldn't be there AND check for other file types that are like tgz and stuff idk"
space
find /home -type f -name *.pdf
space
echo "Press y when done"
read y
space
red "Delete the Suspicious txt files that shouldn't be there"
space
find / -type f -name *.pdf | grep -v lib | grep -v usr | grep -v firefox | grep -v snap | grep -v Input
space
red "Delete the Suspicious tar gz files that shouldn't be there"
space
find / -name '*.gz' -type f | grep -v snap | grep -v /usr/share | grep -v /var/lib
space
red "Delete the Suspicious zip files that shouldn't be there"
space
find / -name '*.zip' -type f | grep -v snap
space
space
red "Make sure that there aren't any weird, OR bad files (jpg, mp3, etc.) in /usr/share YOUR SCRIPT DOESNT DO THIS ANYMORE (REMOVED ALL ICONS SO YOU REMOVED IT)"
space
echo "Press y when done"
read y
space
space
cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
echo " " | cat /tmp/777s
space
space
  
echo "After changing permissions, press any key"
read yea
#------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------
space
space
red "INSTALLING PAM RN SOOOOOOO PRAY IG? press y lol"
space
read hi
sudo dnf install pam
cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/system-auth > /etc/pam.d/system-auth
cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/password-auth > /etc/pam.d/password-auth
space
#------------------------------------------------------------------------------------------


# manual
#------------------------------------------------------------------------------------------
space
echo "GO RUN THROUGH EVERY USER'S DIRECTORY and then press y"
space
read x
#------------------------------------------------------------------------------------------

# Configuring Configs
#------------------------------------------------------------------------------------------

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/fsudoers > /etc/sudoers

nano /etc/sudoers

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/gdm3/fcustom.conf > /etc/gdm/custom.conf

nano /etc/gdm/custom.conf

gsettings set org.gnome.login-screen disable-user-list true

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/login.defs > /etc/login.defs

nano /etc/login.defs

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/httpd.conf > /etc/httpd/conf/httpd.conf

nano /etc/httpd/conf/httpd.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/sysctl.conf > /usr/lib/sysctl.d/50-default
nano /usr/lib/sysctl.d/50-default

space

red "CHECK /etc/sysctl.d/99-sysctl.conf FOR THAT"
read h

space

sysctl -ep

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/hosts > /etc/hosts

nano /etc/hosts

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/firewalld.conf > /etc/firewalld/firewalld.conf

nano /etc/firewalld/firewalld.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/logrotate.conf > /etc/logrotate.conf

nano /etc/logrotate/logrotate.conf
cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/host.conf > /etc/host.conf

nano /etc/host.conf

for i in `ls -a /home | grep -v lost`;do cd /home/$i; cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/.bashrc > /home/$i/.bashrc; chmod 644 .bashrc; cd /; done
for i in `ls -a /root | grep -v lost`;do cd /home/$i; cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/.bashrc > /home/$i/.bashrc; chmod 644 .bashrc; cd /; done

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/my.cnf > /etc/my.cnf

nano /etc/my.cnf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/sshd_config > /etc/ssh/sshd_config

nano /etc/ssh/sshd_config

space
red " For PHP, type the version down below. i.e. '7.2' "
read VERSION
space

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/php.ini > /etc/php/$VERSION/apache2/php.ini

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/vsftpd.conf > /etc/vsftpd.conf

nano /etc/vsftpd.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/smb.conf > /etc/samba/smb.conf

nano /etc/samba/smb.conf

rm -rf /etc/sudoers.d

mkdir /etc/sudoers.d

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/README > /etc/sudoers.d/README

#------------------------------------------------------------------------------------------

#Packages
#------------------------------------------------------------------------------------------
red "Check these packages and the files created on your Desktop for malicious files (read description):"
space

dnf list installed| cut -d " " -f1 > /home/$CUSER/Desktop/listofallpackages.txt
grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/fedorabasepackages.txt /home/$CUSER/Desktop/listofallpackages.txt > /home/$CUSER/Desktop/differentsystempackages.txt

cat /home/$CUSER/Desktop/differentsystempackages.txt > /home/$CUSER/Desktop/differentsystempackagese.txt

for i in `cat /home/$CUSER/Desktop/differentsystempackagese.txt`; do dnf list installed| cut -d " " -f1 | grep -wF $i >> /home/$CUSER/Desktop/Differentsystempackages.txt; done

cat /home/$CUSER/Desktop/Differentsystempackages.txt | grep -v lib > /home/$CUSER/Desktop/removeduplicates.txt; sleep 3s; awk '!a[$0]++' /home/$CUSER/Desktop/removeduplicates.txt > /home/$CUSER/Desktop/finallist

cat /home/$CUSER/Desktop/finallist

space
yellow "Type yes once you are done with MANUALLY INSPECTING packages"
space
read e

#symlinks

#------------------------------------------------------------------------------------------

space
echo "Look at all the symlinks"
space
cd /;ls -laR | grep -w /bin | grep -w '\->' | grep -v systemctl | grep -v kmod | grep -vF "ld." | grep -v less | grep -v touch | grep -v which | grep -vw ip | grep -w '\->' > /tmp/sym; clear; cat /tmp/sym
space
echo "Press enter when you're done checking out the symlinks"
space

#------------------------------------------------------------------------------------------


#Services
#------------------------------------------------------------------------------------------
sudo systemctl restart sshd
sudo systemctl restart httpd
sudo systemctl restart mariadb
sudo systemctl restart samba-client
sudo systemctl restart samba-server
sudo systemctl restart vsftpd
sudo systemctl restart proftpd
sudo systemctl restart ncftp
sudo systemctl restart tnftp
sudo systemctl restart tftp
space
red "IF YOU HAVE A SERVICE THAT ISNT AUTHORIZED, YOU PROBABLY LOST POINTS BY RESTARTING, SO DISABLE STUFF LIKE APACHE, SSH, SAMBA, SMBD, SMTP, AND PROFTP TYPE STUFF (y to continue)"
read f
space
red "Check for suspicious services and disable them: "
space
echo "Possibly Malicious Services"
echo "########################"
space
red `systemctl list-units --type service --all --no-legend --plain --no-pager --quiet | cut -d " " -f1 > /tmp/currentservices.txt; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/fedoraservices.txt /tmp/currentservices.txt > /tmp/differentServices; cat /tmp/differentServices`
space
echo "########################"
space
echo "Press enter when you're ready to enter manual inspection"
space
read k
sudo systemctl --all
space
echo "when ready to proceed, press y"
read s
#------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------
space
yellow "SSH KeyGen"
space
sudo dnf -y install expect
cd /
space
mkdir /home/$CUSER/.ssh
space
expect -c "
spawn ssh-keygen
expect \"Enter file in which to save the key\"
send \"/home/$CUSER/.ssh/id_rsa\r\"
expect \"Enter passphrase\"
send \"j@Hn\r\"
expect \"Enter same passphrase again\"
send \"j@Hn\r\"
expect eof
"
space
space

chmod 600 /home/$CUSER/.ssh/id_rsa
chmod 640 /home/$CUSER/.ssh/id_rsa.pub
space

#Binary Files
#------------------------------------------------------------------------------------------
space
echo "Bad Binaries"
space
echo "###################################################"
space
cd /bin; ls -a > /tmp/binaries; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/safebinfiles.txt /tmp/binaries
space
echo "###################################################"
space

space
echo "Bad SudoBinaries"
space
echo "###################################################"
space
cd /sbin; ls -a > /tmp/sudobinaries; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/safesbin.txt /tmp/sudobinaries
space
echo "###################################################"
space

red "Figure out whats going on what the above files MAKE SURE THE FILES MENTIONED IN ISSUES DONT HAVE SUID BITS, fix accordingly + manually look at /bin + /sbin with hidden files listed. Then press y"
space
read y
#------------------------------------------------------------------------------------------

#resolv.conf
#------------------------------------------------------------------------------------------
space
red "Check /etc/resolv.conf for anything that doesn't look like the following and press enter when you're ready to continue: "
space
echo 'nameserver 127.0.0.53
options edns0 trust-ad
search localdomain'
space
read sd
nano /etc/resolv.conf
space
space
#------------------------------------------------------------------------------------------

#/var/www/html inspection
#-----------------------------------------------------------------------------
red "Check /var/www/html for suspicious files and press enter when finished"
space
ls -a /var/www/html
space
space
read easd
space
space
#-----------------------------------------------------------------------------

#Backdoors
#-----------------------------------------------------------------------------
sudo dnf install net-tools
for i in `sudo netstat -tulpen | grep -v 631 | grep LISTEN | grep -v systemd-resolv | grep -v dnsmasq | grep -v ftp | grep -v ssh | grep -v apache2 | awk '{print $9F}' | awk '!a[$0]++' | cut -d "/" -f1`; do lsof 2>&1 | grep -w $i | grep -w txt | awk '{print $NF}'; done
space
space
red "FEDORA DOESNT HAVE CRON IT HAS SYSTEMD TIMERS, This will print the timers that are RUNNING~, press y."
space
read h
space
systemctl list-timers --all
space
space
red "TAKE A LOOK AT THOSEE, THE NEXT ONE WILL LIST ALLLLLLL, even if they're not running.
space
systemctl list-units --type=timer
space
red "Done. press y to continue after inspecting the above."
read y
#-----------------------------------------------------------------------------


#/etc/fstab stuff
#-----------------------------------------------------------------------------
echo 'tmpfs /dev/shm tmpfs defaults,nodev,noexec,nosuid 0 0
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0' >> /etc/fstab
space
printf "\033[31mPut the following into /etc/fstab for the disk partition:\033[0m \n\ndefaults,nodev,noexec,nosuid"
space
red "Press y when ready"
space
read y
nano /etc/fstab
space
space
red "Now go check your partition notes (grubmkpasswd) and press enter when done"
space
read y
#-----------------------------------------------------------------------------

#/etc sus file permissions
#-----------------------------------------------------------------------------
space
yellow "Check the following files for any wrong permissions in /etc: "
space
cd /etc; ls -la -Issl -Irc*.d -Ialternatives -Ifonts -Ialsa -R | grep -v .service | grep -v .target | grep -v .path| grep -v .want | grep -v .socket | grep -v .mount | grep -v .timer | grep .....w..w.
space
red "Change the permissions to 600 and then press y"
space
read y
#-----------------------------------------------------------------------------

#------------------------------------------------------------------------------
space
red "Delete suspicious suid bit files"
space
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; | awk -F " " '{print $NF}' > /tmp/suidbits; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/oksuid /tmp/suidbits
space
space
echo "Done?"
read asdasd
#-----------------------------------------------------------------------------

#plaintext password file
#-----------------------------------------------------------------------------
space
yellow "What is the password of a user?"
read passwd
space
cd /home; grep -rRwF --exclude /etc --exclude *.config "$passwd" | grep -v '\.' > /home/$CUSER/Desktop/weirdfiles.txt; grep -rRwF --exclude /etc --exclude *.config "$passwd" |  grep txt >> /home/$CUSER/Desktop/weirdfiles.txt ; cd /root;  grep -rRwF --exclude /etc --exclude *.config "$passwd" | grep -v '\.' >> /home/$CUSER/Desktop/weirdfiles.txt; grep -rRwF --exclude /etc --exclude *.config "$passwd" |  grep txt; cd /sbin; grep -rRwF --exclude /etc --exclude *.config "$passwd" | grep -v '\.' >> /home/$CUSER/Desktop/weirdfiles.txt; grep -rRwF --exclude /etc --exclude *.config "$passwd" |  grep txt >> /home/$CUSER/Desktop/weirdfiles.txt; cat /home/$CUSER/Desktop/weirdfiles.txt | cut -d: -f1
space
red "HOLD ON CHECKING /ETC. Press Y ONCE DONE CHECKING ABOVE"
read asdss
cd /etc; grep -rRwF "$passwd"
space
red "REMOVE ANY SUSPICIOUS FILES THAT CONTAIN THAT AND THEN PRESS Y"
space
space
read asd
#-----------------------------------------------------------------------------

#Antivirus and stuff
#-----------------------------------------------------------------------------
printf "\033[1;31mScanning for Viruses...\033[0m\n"

printf "\033[1;31mSay (y/n) depending on if you want to do this (say no for earlier rounds tbh)...\033[0m\n" 
space
read $virus

if [$virus == "y"]
then
	sudo dnf install -y chkrootkit rkhunter apparmor apparmor-profiles lynis

	#This will download lynis 2.4.0, which may be out of date

	#chkrootkit
	printf "\033[1;31mStarting CHKROOTKIT scan...\033[0m\n"
	chkrootkit -q
	space
	red "Ready for the next scan?"
	space
	read y

	#Rkhunter
	printf "\033[1;31mStarting RKHUNTER scan...\033[0m\n"
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	space
	red "Ready for the next scan?"
	space
	read y

	#Lynis
	printf "\033[1;31mStarting LYNIS scan...\033[0m\n"
	lynis update info
	lynis audit system
	space
	red "Ready for the next scan?"
	space
	read y
fi
#-------------------------------------------------------------------------

#----------------
space
sudo systemctl enable firewalld
sudo systemctl start firewalld
space
red "MAKE SURE YOU OPEN CRITICAL SERVICE PORTS FOR FIREWALL (open 22 for ssh (make sure if you made it 100, make it 100))"
space
space
space
red "nmap ALL ports not just the usual 1000, ALL 65535. MAKE SURE THE CORRECT SERVICES ARE RUNNING ON THOSE PORTS AND ITS NOT JUST A SCAM. press y to continue"
space
space
space
read y

#----------------

#Locks Root
#------------------------------------------------------------------------------------------
usermod -L root
passwd -l root
#------------------------------------------------------------------------------------------
