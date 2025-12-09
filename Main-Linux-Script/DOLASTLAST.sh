# means may cause problems
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

#world-writeable --> suidbit
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

#no automount
systemctl disable autofs

###########################
echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf
rmmod usb-storage
###########################

#gpg keys
space
red "configure/verify GPG keys, press y"
space
read a

#grub conf
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

space

#grubpasswd
red "go to your script and look at image_2022-11-05_235653351.png for GRUB PASSWORD"
read a
space

space
space

red "if this returns a yes, go to /etc/sysconfig/boot and CHANGE TO NO"
space
space
grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot
space
space
read i
space

#motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net


####################################
echo "[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized uses only. All activity may be monitored and
reported.'" >> /etc/gdm3/greeter.dconf-defaults
####################################


