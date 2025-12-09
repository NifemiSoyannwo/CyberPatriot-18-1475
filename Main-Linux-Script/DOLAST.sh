function space () {
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

echo "User?"
read CUSER

space
space
red "Make sure to change all critical service configs to 600 (file perms)"
space
cd /etc; sudo chmod 644 -R /*/*.conf
chmod 777 /etc/grub.d
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/shadow
chmod 0600 /etc/securetty
chmod 700 /root
chmod 600 /boot/grub/grub.cfg
chmod 600 /etc/cron.allow
chmod 750 /etc/apache2/conf* >/dev/null 2>&1
chmod 511 /usr/sbin/apache2 >/dev/null 2>&1
chmod 750 /var/log/apache2/ >/dev/null 2>&1
chmod 640 /etc/apache2/conf-available/* >/dev/null 2>&1
chmod 640 /etc/apache2/conf-enabled/* >/dev/null 2>&1
chmod 640 /etc/apache2/apache2.conf >/dev/null 2>&1
chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/group
chmod 644 /etc/group
chown root:shadow /etc/gshadow
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
chown root:root /etc/group-
chmod 600 /etc/group-
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
#RESTART SERVICES SUCH AS SSH AND OTHERS
#CHECK cron.allow/cron.deny /etc/cron.atallow or something stuff

#crontab change access to root
crontab -r
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 644 cron.allow at.allow

#Install and enable auditing
echo "Installing auditing daemon"
apt-get install auditd -y
echo "enabling auditing"
auditctl -e 1 > /var/local/audit.log

#Permissions
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinted.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
chown root:root /etc/shadow
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 644 /etc/gshadow
chown root:root /etc/gshadow
chmod 700 /boot
chown root:root /etc/anacrontab
chmod 600 /etc/anacrontab
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown root:root /etc/cron.hourly
chmod 600 /etc/cron.hourly
chown root:root /etc/cron.daily
chmod 600 /etc/cron.daily
chown root:root /etc/cron.weekly
chmod 600 /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod 600 /etc/cron.monthly
chown root:root /etc/cron.d
chmod 600 /etc/cron.d

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t



sudo apt-get update 
sudo apt upgrade
pam-auth-update --force

sudo ufw enable
space
red "MAKE SURE TO OPEN PORTS TO CRITICAL SERVICES (open port 22 for ssh (make sure its the port that YOU changed it to)) ALSO CHECK IF PAM CONFIGS REVERTED"
read apple
space
red "Done."
sleep 10

sleep 10
