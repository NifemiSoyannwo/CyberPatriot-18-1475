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

red "User?"
read CUSER

cd /
find > /home/$CUSER/Desktop/currentfind
grep -Fxvf /home/$CUSER/Desktop/debianbasefind.txt /home/$CUSER/Desktop/currentfind > /home/$CUSER/Desktop/oop; cat /home/$CUSER/Desktop/oop | grep -v home | grep -v sys | grep -v run | grep -v proc | grep -v /dev | grep -v /usr/include | grep -v /tmp | grep -v /opt | grep -v usr/share | grep -v lib | grep -v log | grep -v /var/www | grep -v alternatives | grep -v /usr/bin | grep -v cache | grep -v /etc/ufw/after | grep -v /etc/ufw/before | grep -v /etc/ufw/user | grep -v backups | grep -v boot/grub | grep -v vmware | grep -v etc/ssl/ > /home/$CUSER/Desktop/differentinfind
clear
cat /home/$CUSER/Desktop/differentinfind
space
red "Check for any outwardly bad files"

sudo for i in `cat /home/debian/dir`; do cd $i; echo $i; echo "---------------------------------------------------------------------------"; find $i/ -maxdepth 1 -type f -print0 | while IFS= read -r -d '' file; do permissions=$(stat -c "%A" "$file"); sha256=$(sha256sum "$file" | awk '{print $1}'); echo "$permissions $file $sha256"; done; echo "---------------------------------------------------------------------------"; done
