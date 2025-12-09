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
echo "Script made by Puru Jain for CyberPatriot."
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
red "Check for poisoned files by using debsums -ca and fix it (research/replace it with correct file)"
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

clear
sudo chattr -iaR /etc
sudo chattr -iaR /bin
sudo chattr -iaR /home
sudo chattr -iaR /sbin
sudo chattr -iaR /usr
sudo chattr -iaR /var
sudo chown -R root:root /bin
sudo chown -R root:root /sbin
sudo chown -R root:root /usr/bin
sudo chown -R root:root /usr/sbin
clear

#Updates
#------------------------------------------------------------------------------------------
#cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/apt/sources.list > /etc/apt/sources.list
#cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/apt/sources.list.save > /etc/apt/sources.list.save
#cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/apt/apt.conf.d/10periodic > /etc/apt/apt.conf.d/10periodic
#cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/apt/apt.conf.d/20auto-upgrades > /etc/apt/apt.conf.d/20auto-upgrades
space
red "Make sure your update settings are up to date"
space
red "Make sure updates are displayed immediatly, script takes cares of the rest"
space
read ANSWER
sudo apt update
sudo apt install unattended-upgrades
sudo apt install apt
sudo apt install ufw
space
#------------------------------------------------------------------------------------------

#Clamav Full Scan
#------------------------------------------------------------------------------------------
sudo apt install clamav
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

for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/newusers.txt` ; do echo $i:"dq*eb5,69~n)_-JU<&V8" | sudo chpasswd ;  done

echo "Done adding users "
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
for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/users.txt` ; do sudo gpasswd -d $i sudo > /dev/null 2>&1 ; sudo gpasswd -d $i adm  > /dev/null 2>&1 ; echo "Removed " $i " as an admin"; done


for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/admins.txt` ; do sudo gpasswd -a $i sudo > /dev/null 2>&1 ; sudo gpasswd -a $i adm > /dev/null 2>&1; echo "Added " $i " as an admin"; done

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
for i in `cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/badusers.txt` ; do sudo deluser $i > /dev/null 2>&1 ; echo "Deleted user " $i;  done

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
sudo ufw reset
sudo ufw enable
#enable fire-wall outgoing + incoming connections
space

echo "Allow outgoing connections? (y/n)"
read outConn
if [ $outConn = "n" ]
then
	sudo ufw default deny outgoing
else
	sudo ufw default allow outgoing
fi

echo "Allow incoming connections? (y/n)"
read inConn
if [ $inConn = "y" ]
then
	sudo ufw default allow incoming
else
	sudo ufw default deny incoming
fi

space
space

red "MAKE SURE YOU OPEN PORTS FOR CRITICAL SERVICES!!!!!! For example do: sudo ufw allow 22 for SSH"
space
#------------------------------------------------------------------------------------------

#installs critical stuff
#------------------------------------------------------------------------------------------
space
red "MAKE SURE TO INSTALL CRITICAL SERVICES BEFORE CONTINUING!!!!!!"
space
echo "Press y when you are done installing them (in another terminal)"
read y

#------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------
#deletes commonly known bad packages

if `grep -Fxq "apache2" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove apache2 -y > /dev/null 2>&1
fi

if `grep -Fxq "mysql" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove mysql-server-5.5 -y > /dev/null 2>&1
  sudo apt-get --purge autoremove mysql-server-5.6 -y > /dev/null 2>&1
fi

if `grep -Fxq "ssh" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove openssh-client -y > /dev/null 2>&1
  sudo apt-get --purge autoremove openssh-server -y > /dev/null 2>&1
fi

if `grep -Fxq "samba" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove samba -y > /dev/null 2>&1
fi

if `grep -Fxq "vsftpd" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove vsftpd -y > /dev/null 2>&1
fi

if `grep -Fxq "proftpd" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove proftpd -y > /dev/null 2>&1
fi

if `grep -Fxq "ncftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove ncftp -y > /dev/null 2>&1
fi

if `grep -Fxq "tnftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove tnftp -y > /dev/null 2>&1
fi

if `grep -Fxq "tftp" /home/$CUSER/Desktop/Scripting-main/Scripting-main/critical_services.txt`
then
    # code if found
  :
else
    # code if not found
  sudo apt-get --purge autoremove tftp -y > /dev/null 2>&1
fi

#------------------------------------------------------------------------------------------

#update important packages
#------------------------------------------------------------------------------------------
sudo apt install gufw -y
sudo apt-mark unhold firefox
sudo apt install firefox -y
sudo apt install nautilus -y
sudo apt install linux-generic -y
space
red "Now go update firefox settings and then press y"
space
read as
#------------------------------------------------------------------------------------------

#Delete unwanted users
#------------------------------------------------------------------------------------------
printf "\033[1;31mDeleting dangerous files...\033[0m\n"
	#--------- Delete Dangerous Files ----------------
cd /
find / -name '*.mp3' -type f -delete > /dev/null 2>&1
echo "Done deleting mp3 files"
find / -name '*.tgz' -type f -delete > /dev/null 2>&1
echo "Done deleting tgz files"
find / -name '*.mov' -type f -delete > /dev/null 2>&1
echo "Done deleting mov files"
find / -name '*.mp4' -type f -delete > /dev/null 2>&1
echo "Done deleting mp4 files"
find / -name '*.avi' -type f -delete > /dev/null 2>&1
echo "Done deleting avi files"
find / -name '*.mpg' -type f -delete > /dev/null 2>&1
echo "Done deleting mpg files"
find / -name '*.mpeg' -type f -delete > /dev/null 2>&1
echo "Done deleting mpeg files"
find / -name '*.flac' -type f -delete > /dev/null 2>&1
echo "Done deleting flac files"
find / -name '*.m4a' -type f -delete > /dev/null 2>&1
echo "Done deleting m4a files"
find / -name '*.flv' -type f -delete > /dev/null 2>&1
echo "Done deleting flv files"
find / -name '*.ogg' -type f -delete > /dev/null 2>&1
echo "Done deleting ogg files"
find /home -name '*.gif' -type f -delete > /dev/null 2>&1
find /root -name '*.gif' -type f -delete > /dev/null 2>&1
echo "Done deleting gif files"
find /home -name '*.png' -type f -delete > /dev/null 2>&1
find /root -name '*.png' -type f -delete > /dev/null 2>&1
echo "Done deleting png files"
find /home -name '*.jpg' -type f -delete > /dev/null 2>&1
find /root -name '*.jpg' -type f -delete > /dev/null 2>&1
echo "Done deleting jpg files"
find /home -name '*.jpeg' -type f -delete > /dev/null 2>&1
find /root -name '*.jpeg' -type f -delete > /dev/null 2>&1
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
sudo apt install libpam-pwquality
space
#------------------------------------------------------------------------------------------


#manual
#------------------------------------------------------------------------------------------
space
echo "GO RUN THROUGH EVERY USER'S DIRECTORY and CHECK /etc/rc.d/init.d then press y"
space
read x
#------------------------------------------------------------------------------------------

#Configuring Configs
#------------------------------------------------------------------------------------------
cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/sudoers > /etc/sudoers

nano /etc/sudoers

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/lightdm.conf > /etc/lightdm/lightdm.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/lightdm.conf > /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf > /dev/null 2>&1

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/login.defs > /etc/login.defs

nano /etc/login.defs

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/apache2.conf > /etc/apache2/apache2.conf

nano /etc/apache2/apache2.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/rc.local > /etc/rc.local

nano /etc/rc.local

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/sysctl.conf > /etc/sysctl.conf

nano /etc/sysctl.conf

sysctl -ep

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/hosts > /etc/hosts

nano /etc/hosts

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/ufw.conf > /etc/ufw.conf

nano /etc/ufw.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/logrotate.conf > /etc/logrotate.conf

nano /etc/logrotate.conf

space
space
red "Check common-account after pressing y, you removed it just in case it broke but it could be like vulnerable so DO IT MANUALLY"
read hissss
space
space

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/pam.d/common-auth > /etc/pam.d/common-auth
cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/pam.d/common-password > /etc/pam.d/common-password



cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/gdm3/custom.conf > /etc/gdm3/custom.conf

nano /etc/gdm3/custom.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/gdm3/greeter.dconf-defaults > /etc/gdm3/greeter.dconf-defaults

nano /etc/gdm3/greeter.dconf-defaults

rm -rf /etc/sysctl.d; cp -r /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/sysctl.d /etc

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/host.conf > /etc/host.conf

nano /etc/host.conf

for i in `ls -a /home | grep -v lost`;do cd /home/$i; cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/.bashrc > /home/$i/.bashrc; chmod 644 .bashrc; cd /; done
cd /root; cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/.bashrc > /root/.bashrc; chmod 644 .bashrc; cd /

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/my.cnf > /etc/mysql/my.cnf

nano /etc/mysql/my.cnf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/users.conf > /etc/lightdm/users.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/adduser.conf > /etc/adduser.conf

nano /etc/adduser.conf

cat /home/$CUSER/Desktop/Scripting-main/Scripting-main/Configs/deluser.conf > /etc/deluser.conf

nano /etc/deluser.conf

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
#dpkg -l | grep -i wireless >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i http >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i capture >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i packet >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep TCP >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep IP >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i RDP >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i remote >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i torrent >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i unathorized >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i  vulnera >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i game >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i crack >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i password >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i Windows >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i bypass >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i gain >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i access >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i backdoor >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i exploit >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i scan >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i brute >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i sniff >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i intercept >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i force >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i malware >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i map >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i network >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i phish >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i hack >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i request >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i domain >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i dns >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i breach >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i DoS >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i DDoS >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i web >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i clickjack >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i social >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i "social engineer" >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i rootkit >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i malicious >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i ware >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i game >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i server >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i telnet >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i SQL >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i injection >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i passive >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i active >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i fingerprint >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i chat >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i call >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i connect >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i talk >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i vino >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i database >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i daemon >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i pop3 >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i IMAP >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i reverse >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i engineer >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i snmp >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i snmp >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i manipulate >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i snmp >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i media >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i audacious >> /home/$CUSER/Desktop/badfiles.txt
#dpkg -l | grep -i trap >> /home/$CUSER/Desktop/badfiles.txt


#grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/basefiles.txt /home/$CUSER/Desktop/badfiles.txt | grep -v lib | grep -v gir | grep -v unity| grep -v gnome | grep -vF "linux-" | grep -v "ubuntu-">  /home/$CUSER/Desktop/CHECKTHISfixedlistofpossiblebadstuff.txt

dpkg-query -l | tail -n+4 | awk '{print $2}' > /home/$CUSER/Desktop/listofallpackages.txt
grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/basefiles.txt /home/$CUSER/Desktop/listofallpackages.txt > /home/$CUSER/Desktop/differentsystempackages.txt

cat /home/$CUSER/Desktop/differentsystempackages.txt | grep -v lib | grep -v python | grep -v gir |grep -v unity | grep -v fonts | grep -v gnome | grep -vF "linux-"| grep -v indicator | grep -v qml | grep -v signon | grep -v qt | grep -vF "ubuntu-" | grep -vF "account-" | grep -v conf | grep -v openssh | grep -v apache2 | grep -v samba | grep -v imagemagick | grep -v GNU | grep -v OpenGl > /home/$CUSER/Desktop/differentsystempackagese.txt

for i in `cat /home/$CUSER/Desktop/differentsystempackagese.txt`; do dpkg -l | grep -wF $i >> /home/$CUSER/Desktop/Differentsystempackages.txt; done

cat /home/$CUSER/Desktop/Differentsystempackages.txt | grep -v lib > /home/$CUSER/Desktop/removeduplicates.txt; sleep 3s; awk '!a[$0]++' /home/$CUSER/Desktop/removeduplicates.txt > /home/$CUSER/Desktop/finallist

cat /home/$CUSER/Desktop/finallist

space
yellow "Type yes once you are done with MANUALLY INSPECTING packages"
space
read e

#------------------------------------------------------------------------------------------

#symlinks

#------------------------------------------------------------------------------------------

space
echo "Look at all the symlinks"
space
cd /; ls -laR | grep ^- | awk -F ' ' '$2 > 1' | grep ^- > /tmp/ha.txt;clear; cat /tmp/ha.txt | grep ^- | awk -F " " '{print $NF}' > /tmp/heh.txt; for i in ` grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/safehlinks.txt /tmp/heh.txt`; do find | grep -w $i > /tmp/listofhardlinks; done; cat /tmp/listofhardlinks
cd /;ls -laR | grep -w /bin | grep -w '\->' | grep -v systemctl | grep -v kmod | grep -vF "ld." | grep -v less | grep -v touch | grep -v which | grep -vw ip | grep -w '\->' > /tmp/sym; clear; cat /tmp/sym
space
echo "Press enter when you're done checking out the symlinks"
space

#------------------------------------------------------------------------------------------


#Services
#------------------------------------------------------------------------------------------
sudo service ssh restart
sudo service apache2 restart
sudo service mysql restart
sudo service samba restart
sudo service smbd restart
sudo service vsftpd restart
sudo service proftpd restart
sudo service ncftp restart
sudo service tnftp restart
sudo service tftp restart
space
printf "\033[1;31mIF YOU HAVE A SERVICE THAT ISNT AUTHORIZED, YOU PROBABLY LOST POINTS BY RESTARTING, SO DISABLE STUFF LIKE APACHE, SSH, SAMBA, SMBD, SMTP, AND PROFTP TYPE STUFF (y to continue) \033[0m\n"
read $f
space
printf "\033[1;31mCheck for suspicious services and disable them: \033[0m\n"
space
echo "Possibly Malicious Services"
echo "########################"
space
red `service --status-all | awk -F " " '{print $NF}' > /tmp/currentservices.txt; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/allservices.txt /tmp/currentservices.txt > /tmp/differentServices; cat /tmp/differentServices`
space
echo "########################"
space
echo "Press enter when you're ready to enter manual inspection"
space
read k
sudo service --status-all
space
echo "when ready to proceed, press y"
read s
#------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------
space
yellow "SSH KeyGen"
space
sudo apt -y install expect
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
#------------------------------------------------------------------------------------------

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

red "Figure out whats going on what the above files, fix accordingly + manually look at /bin + /sbin with hidden files listed. Then press y"
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

#backdoors
#-----------------------------------------------------------------------------
sudo apt install net-tools
for i in `sudo netstat -tulpen | grep -v 631 | grep LISTEN | grep -v systemd-resolv | grep -v dnsmasq | grep -v ftp | grep -v ssh | grep -v apache2 | awk '{print $9F}' | awk '!a[$0]++' | cut -d "/" -f1`; do lsof 2>&1 | grep -w $i | grep -w txt | awk '{print $NF}'; done
space
for i in `ls -la /var/spool/cron/crontabs | awk '{print $(NF)}'`; do if cat /var/spool/cron/crontabs/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /var/spool/cron/crontabs/$i; echo " "; echo "#####################################"; echo " "; fi; cat /var/spool/cron/crontabs/$i | grep -v '#' | grep '*'; echo " "; done
for i in `ls -la /etc/cron.d | awk '{print $(NF)}'`; do if cat /etc/cron.d/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /etc/cron.d/$i; echo " "; echo "#####################################"; echo " "; fi; cat /etc/cron.d/$i | grep -v '#' | grep '*'; echo " "; done
for i in `ls -la /etc/cron.hourly | awk '{print $(NF)}' `; do if cat /etc/cron.hourly/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /etc/cron.hourly/$i; echo " "; echo "#####################################"; echo " "; fi; cat /etc/cron.hourly/$i | grep -v '#' | grep '*'; echo " "; done
for i in `ls -la /etc/cron.daily | awk '{print $(NF)}' `; do if cat /etc/cron.daily/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /etc/cron.daily/$i; echo " "; echo "#####################################"; echo " "; fi; cat /etc/cron.daily/$i | grep -v '#' | grep '*'; echo " "; done
for i in `ls -la /etc/cron.weekly | awk '{print $(NF)}'`; do if cat /etc/cron.weekly/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /etc/cron.weekly/$i; echo " "; echo "#####################################"; echo " "; fi; cat /etc/cron.weekly/$i | grep -v '#' | grep '*'; echo " "; done
for i in `ls -la /etc/cron.monthly | awk '{print $(NF)}'`; do if cat /etc/cron.monthly/$i | grep -v '#' | grep '*' > /dev/null ; then echo " "; echo "#####################################"; echo " ";echo /etc/cron.monthly/$i; echo " "; echo "#####################################"; echo " "; fi; cat /etc/cron.monthly/$i | grep -v '#' | grep '*'; echo " "; done
space
red "MANUALLY CHECK FOR BACKDOORS ESPECIALLY IN HIDDEN FILES (.urgot) (Also check Attributes, immutable) AND DONT FORGET TO KILL THEIR PID then press ok"
red "/etc/cron.monthly, /etc/cron.weekly, /etc/cron.daily, /etc/cron.hourly, /etc/cron.d, /var/spool/cron/crontabs CHECK WITH ls -la (LOOK FOR .urgot TYPE OF FILES)"
space
read ok
space
red "Manual /etc/crontab inspection on Enter"
read enter
space
nano /etc/crontab
space
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
find / -perm /4000 > /tmp/test1; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/suid /tmp/test1 > /tmp/suidfinal
find / -perm /2000 > /tmp/test2; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/sgid /tmp/test2 > /tmp/sgidfinal
find / -perm /6000 > /tmp/test3; grep -Fxvf /home/$CUSER/Desktop/Scripting-main/Scripting-main/bothsuidsgid /tmp/test3 > /tmp/bothfinal
clear
red "##########################################"
red "                 BAD SUID                 "
red "##########################################"
space
cat /tmp/suidfinal
space
space
echo "Done?"
read boooooooo
red "##########################################"
red "                 BAD SGID                 "
red "##########################################"
space
cat /tmp/sgidfinal
space
space
echo "Done?"
read booooooo
red "##########################################"
red "                 BAD SUID                 "
red "##########################################"
space
cat /tmp/bothfinal
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
	sudo apt-get install -y chkrootkit rkhunter apparmor apparmor-profiles lynis

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
sudo ufw enable
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
