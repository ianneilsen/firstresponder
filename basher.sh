#!/bin/sh
##########################################################################
#
# Cursive checks on a suspected linux box.
# Collect some info and start your hunting.
# 
# DESCRIPTION
# The script runs some basic checks on a linux system looking for signs of compromise, mis-configuration and 
# collecting information on the system and performing some rudimentary malware checks.
#
# Great place to start when you suspect a your system is playing up. Every sysadmin should have these bags of tricks in their pockets
#Author: Ian Neilsen 7functions http://twitter.com/ianneilsen
#Props to http://blog.sevagas.com/ - http://twitter.com/EmericNasi Some ideas and scripts taken from his old blog. cmds ref where possible

###########################################################################

SUCCESS=0
# colors
GREEN="$(tput setaf 2)"
RED="$(tput setaf 1)"
REDB="$(tput bold; tput setaf 1)"
YELLOW="$(tput setaf 3)"
NC="$(tput sgr0)"
EXPLOIT_DIR=""
#TODO - change out ww_scan_dir with below
ians_scan_dir="/tmp /var/tmp /dev /dev/shm /bin /sbin /usr/bin /usr/sbin /lib /usr/lib /etc /var /var/log /var/spool/cron /var/www"

# usage and help - Got to love flags and switches, swing those dials.
usage()
{
  echo "usage:"
  echo ""
  echo "  ian-check-bash.sh -f <arg> | -s <arg> | <misc>"
  echo ""
  echo "options:"
  echo ""
  echo "  -s <str>  - exploit to search using <str> in ${EXPLOIT_DIR}"
  echo "              (default: http://dl.packetstormsecurity.com/)"
  echo "  -c        - do not delete downloaded archive files"
  echo "  -v        - verbose mode (default: on)"
  echo "  -d        - check this directory"
  echo ""
  echo "misc:"
  echo ""
  echo "  -V        - print version of sploitctl and exit"
  echo "  -H        - print this help and exit"

  exit $SUCCESS
}

# leet banner, important stuff ;-)
banner()
{
	echo "${YELLOW}--==[ check-bash.sh by ianneilsen ]==--${NC}"
	echo

	return $SUCCESS
}

# script must run as root, doh!
check_uid()
{
  if [[ $EUID -ne 0 ]]; then
  	echo "${GREEN}This script must be run as root. Later hater."
  	exit 1
  elif [[ $EUID = 0 ]]; then
  	echo "==++== Hey buddy ==++== You ready to rock?${NC}"
  	echo
  fi
}
# Print a pretty message - Unicorns are ????
msg1()
{
  echo "${GREEN}[+]${NC} ${@}"

  return $SUCCESS
}
# eddie murphy
main()
{
	banner
	check_uid
	#check_files
	#check_network
	#check_full

	msg1 "Game start - Fight"
	echo
	return $SUCCESS
}

main "${0}"

#######################################################
## System Info
#######################################################

echo "cat spool and cron"
echo '=========================================='
cat /var/spool/cron/*
cat cat /var/spool/cron/crontabs/*

echo "Hostname and kernel"
echo '=========================================='
hostnamectl

echo "ipconfig"
echo '=========================================='
ipconfig

echo "systemctl status"
echo '=========================================='
systemctl status

echo "Show me iptables -L"
echo '=========================================='
iptables -L -n --line-numbers



## Kicking off the tests - wahoo lets go!!
#########################################################
## NETWORKING
#########################################################
echo
echo "Lets start with network"
echo "${GREEN} NETWORKING ${NC}"
echo
#########################################################

echo "3 - Network all ports/socket capture"
echo '=========================================='
netstat -anp

echo "Network all tcp/udp"
echo '=========================================='
netstat -antu

echo "4 -lsof all super verbose"
echo '=========================================='
#lsof -V
## Uncomment if you want everything - long output

echo "5 - lsof show me listening ports"
echo '=========================================='
#lsof -Pni
## Uncomment if you want everything - long output

echo "lsof all sockets "
echo '=========================================='
lsof -Pwln

echo " network routing"
echo '=========================================='
netstat -rn

echo " show me listening networks"
echo '=========================================='
ss -tlpa

echo " show me connected now just ip addresses and process"
echo '=========================================='
netstat -plantu

echo " show me tcp/udp nip address resolved not just number"
echo '=========================================='
netstat -platu

echo "Network all ports/socket capture"
echo '=========================================='
netstat -na

echo " show me listening"
echo '=========================================='
netstat -tulpn

echo "show me all sockets using lsof"
echo '=========================================='
#That command will list all IPv4 and IPv6 opened connections and \
#display the corresponding command, pid, user, the connexion type, the transport layer protocol used and \
#the connection description (IP address and port). The column and sed part is just for nice formatting"
lsof | grep -E "IPv4|IPv6|COMMAND.*USER" |  sed -r  "s/ +/ /g" | cut -d " " -f 1,2,3,5,8,9 | column -t | sed "s/.*/ &/"

echo " show me all unique ips"
echo '=========================================='
ss -tp | grep -v Recv-Q | sed -e 's/.*users:(("//' -e 's/".*$//' | sort | uniq

echo "show me lsof of activie listening connections "
echo '=========================================='
lsof -Pni

echo " lsof on http logs"
echo '=========================================='
#lsof +d /var/log/apache

echo " lsof socket collection"
echo '=========================================='
#lsof -Pwln

echo " show me all deleted processes"
echo '=========================================='
lsof -n | grep -i deleted

echo " ss socket connections "
echo '=========================================='
ss -nap



#########################################################
# PROCESSES - Check yo process yo
#########################################################
echo
echo "${GREEN} Start jamming on processes ${NC}"
echo
#########################################################

echo " Show me all of ps tree with file paths"
echo '=========================================='
ps -auxwf

echo " Standard ps "
echo '=========================================='
ps -ef

echo " pstree if available"
echo '=========================================='
pstree -Aup

echo " deleted proc exe's - now prob in memory"
echo '=========================================='
ls -alR /proc/*/exe 2> /dev/null | grep deleted

echo " proc list all cwd"
echo '=========================================='
ls -alR /proc/*/cwd

echo " check proc for anything in tmp dir"
echo '=========================================='
ls -alR /proc/*/cwd 2> /dev/null | grep tmp

echo " check proc for anything in dev dir"
echo '=========================================='
ls -alR /proc/*/cwd 2> /dev/null | grep dev

echo " Kernel show me all lsmod all"
echo '=========================================='
lsmod

echo " show all process file struc and cmds -- verbose"
echo '=========================================='
ps auxwef

echo " show all process file struc and cmds -- good"
echo '=========================================='
ps auxwe

echo
echo "Show all cron jobs for users"
echo '=========================================='
for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l; done

echo
echo "Apapche top if installed"
apachetop
echo

echo
#########################################################
## FILES DIRECTORIES -- Check files, files file and dirs
#########################################################
echo
echo "${GREEN} FILES ${NC}"
echo
#########################################################

echo
echo "find all dirs set to 777 in web directories"
echo '=========================================='
find /var -type d -perm 777

echo
echo "find all files set to 777 in web directories"
echo '=========================================='
find /var -type f -perm 777

echo
echo "broken sym links"
echo '=========================================='
find -L  /usr -type l -maxdepth 8 2>/dev/null

echo
echo "Show me all sticky bit files"
# should always be set on world writable folders to prevent a user from removing a file he doesn’t own
echo '=========================================='
find /  -perm -1000 2>/dev/null

echo
echo "Find world writable files"
echo '=========================================='
find / -type f -perm -o+w -exec ls -l {} \;

echo
echo "Find world writable dirs - Type 1"
echo '=========================================='
find / -type d -perm -o+w -exec ls -l {} \;

echo
echo "Find world directories - Type2 - important"
echo '==========================================='
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;

echo
echo "the directories /bin, /sbin, /boot, /etc, /lib, /root, /usr should never be world writable"
echo '=========================================='
echo
ww_scan_dirs="/bin /sbin /boot /etc /lib /root /usr "
for ww_scan_dir in $ww_scan_dirs
do
  for file in `find $ww_scan_dir  ! -type l  -perm -002 `
  do
    echo " DANGER : $file is world writable, files in $ww_scan_dir shouldn't be."
  done | sort
done
unset ww_scan_dir
unset ww_scan_dirs

echo
echo "Looking for bin files"
echo '=========================================='
find / -name \*.bin

echo
echo "1 - checking permissions setgid and guid"
echo '=========================================='
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;

echo
echo " immmutable files/dris"
echo '=========================================='
lsattr / -R 2> /dev/null | grep "\----i"

echo
echo " Missing setgid and guid"
echo '=========================================='
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;

echo
echo " no user or group on all files/dirs"
echo '=========================================='
find / \( -nouser -o -nogroup \) -exec ls -lg {} \;

echo
echo " find executables"
echo '=========================================='
#find / -type f -exec file -p '{}' \; | grep ELF

echo
echo " dev null history file"
echo '=========================================='
ls -alR / 2> /dev/null | grep .*history | grep null

echo
echo " World writable files are bad mckay - especially ones owned by root"
echo '=========================================='
find / ! -type l -perm -002  2>/dev/null

echo
echo "show me all setuid files"
echo '=========================================='
find / -perm -4000 2>/dev/null

echo
echo "show me all setuid owned by root"
echo '=========================================='
find / -perm -4000 -user root 2>/dev/null

echo
echo "ex insind /var or /tmp) they must have the sticky bit on to prevent unauthorized file deletion"
echo '=========================================='
for file in `find /   -type d -perm -002 ! -perm -1000   2>/dev/null`
do
  echo " DANGER : $file is a world writable directory, it should have the sticky bit on."
done | sor

echo
echo "Are all system files owned by root"
echo '=========================================='
for file in `find /root $find_options ! -user root  2>/dev/null`
do
  echo " DANGER : $file doesn't belong to root. It should be changed or moved from the \/root folder."
done | sort

echo
echo "Are all files owned by someone"
echo '=========================================='
for file in `find / $find_options -nouser  2>/dev/null`
do
  echo " DANGER : No user corresponds to $file  numeric user ID."
done | sort
for file in `find / $find_options  -nogroup  2>/dev/null`
do
  echo " DANGER : No group corresponds to $file  numeric group ID."
done | sort


## Are devices only stored in specific directories
echo
echo "Devices stored in correct dirs"
device_scan_dirs="/bin /sbin /lib /boot /etc /home /root /sys /usr /var /tmp /mnt /media /proc"
for device_scan_dir in $device_scan_dirs
do
  for file in `find $device_scan_dir $find_options -type b -o -type c  2>/dev/null`
  do
    [[ "$file" =~ ^/lib/udev/devices/ ]] || echo " DANGER : $file looks like a device. Move it to /dev (or /lib/udev/devices)."
  done | sort
done
unset device_scan_dir
unset device_scan_dirs

## dirs
echo
echo "symlink in tmp dir = bad maybe - you should check this"
echo
for file in `find  /tmp $find_options  -type l  `
  do
    echo " RISKy : $file is a symbolic link inside the /tmp folder"
  done | sort

### really bad confs
echo
echo "Very bad - if found possibly compromised - Items will list below"
#Check if there are any files with SetUID bit on in the /tmp folder
echo '========================================='
for file in `find /tmp $find_options -perm -4000`
do
  echo " EXTREME DANGER : $file is setuid and shouldn't be in /tmp folder."
done | sort


echo
echo "VEry Very Bad - File is setuid and world writable"
echo '========================================='
for file in `find / $find_options -perm -4002 2>/dev/null`
do
  echo " EXTREME Bad : $file is setuid and world writable."
done | sort

echo
echo "Looking at non-readable files on important files"
echo '========================================='
nonReadableFiles="/etc/master.passwd /etc/shadow /etc/shadow- /etc/gshadow /etc/sudoers /var/log/messages "
for nonReadableFile in $nonReadableFiles
do
  [ -f "$nonReadableFile" ] && [[ $(ls -gn "$nonReadableFile") =~ ^.......r..\ .*$ ]]  &&  echo "EXTREME DANGER : $nonReadableFile should not be readeable by others."
done
unset nonReadableFile
unset nonReadableFiles

echo
echo "blacklistFiles"
echo '=========================================='
blacklistFiles="/dev/tcp /dev/udp"
for blacklistFile in $blacklistFiles
do
  [ -f "$blacklistFile" ] && [[ $(ls -trap "$blacklistFile") ]] && echo " DANGER : $blacklistFile is a security hole, remove if you can."
done
unset blacklistFile
unset blacklistFiles

echo "look for src includes"
echo '=========================================='
zgrep -ic "script src=" /var/* |grep -v :0

echo " Find all files modified in the last 30days which end in .php"
echo '=========================================='
find /var/* -type f -name "*.php" -ctime -30

echo "Find all files modified in last x days which end in .php in home dir"
echo '=========================================='
find /home/* -type f -name "*.php" -ctime -30

echo " Look for encoded files in home"
echo '=========================================='
#find /home/* -type f -mtime -7 -maxdepth 4 -exec egrep -q “eval\(|exec\(|gzinflate\(|base64_decode\(|str_rot13\(|gzuncompress\(|rawurldecode\(|strrev\(|ini_set\(chr|chr\(rand\(|shell_exec\(|fopen\(|curl_exec\(|popen\(|x..x..” {} \; -print

echo " Look for endcoded files in var"
echo '=========================================='
#find /var/* -type f -mtime -7 -maxdepth 4 -exec egrep -q “eval\(|exec\(|gzinflate\(|base64_decode\(|str_rot13\(|gzuncompress\(|rawurldecode\(|strrev\(|ini_set\(chr|chr\(rand\(|shell_exec\(|fopen\(|curl_exec\(|popen\(|x..x..” {} \; -print

#find /tmp/* -type f -mtime -7 -maxdepth 4 -exec egrep -q “eval\(|exec\(|gzinflate\(|base64_decode\(|str_rot13\(|gzuncompress\(|rawurldecode\(|strrev\(|ini_set\(chr|chr\(rand\(|shell_exec\(|fopen\(|curl_exec\(|popen\(|x..x..” {} \; -print

echo "Find all writable folders and files => "
echo '=========================================='
find / -perm -2 -ls

# find all suid files
echo "find all suid files"
echo '=========================================='
find / -type f -perm -04000 -ls


echo "Find all sgid files"
echo '=========================================='
find / -type f -perm -02000 -ls


echo "Find setgid on user root all dirs"
echo '=========================================='
find / -xdev -user root  -perm -4000 -o -perm -2000
echo 

#TODO sort these file checks out and remove any dups or useless

#########################################################
## Users
#########################################################

echo
echo " whos is online now"
echo '=========================================='
who -la

echo
echo " show me no user all"
echo '=========================================='
find / -nouser

echo
echo " show me no group all"
echo '=========================================='
find / -nogroup

echo
echo " show me current logins"
echo '=========================================='
utmpdump < /var/run/utmp

echo
echo " show me all bad logins"
echo '=========================================='
utmpdump < /var/log/btmp*

echo
echo " show me valid past logins"
echo '=========================================='
utmpdump < /var/log/wtmp*

echo
echo " search for all no user files types"
#find / -xdev -fstype xfs -nouser

echo
echo " show me all no group file types"
#find / -xdev -fstype xfs -nogroup

echo
echo " diff no use search all file system"
echo '=========================================='
find / -nogroup -nouse

echo
echo "Empty passwords"
echo '=========================================='
awk -F':' '{ if ( $2 == ""  ) print $1 }' /etc/shadow

echo
echo "Is there more than one UID 0"
echo '=========================================='
awk -F':' '{ if ( $3 == "0"  ) print $1 }' /etc/passwd

echo
echo "uid on logins"
echo '=========================================='
cat /etc/login.defs | grep -E ^UID_MIN | sed -r 's/ +/ /g' | cut -d " " -f 2


#########################################################
# Package checks
#########################################################

echo
echo "Show my rpm packages modified"
echo '=========================================='
rpm -Va | grep ^..5

echo
echo "Show my deb packages modified"
echo '=========================================='
debsums -c
debsums -C

echo

#########################################################
# Audit log and selinux checks
#########################################################
echo
## ausearch

echo
echo "Run auditctl -l"
auditctl -l

echo
echo "ausearch user login -m USER_LOGIN -sv no"
ausearch -m USER_LOGIN -sv no

echo
echo "ausearch user login - au root"
ausearch -ua root

echo
echo "ausearch -m user stuff -i"
ausearch -m ADD_USER,DEL_USER,USER_CHAUTHTOK,ADD_GROUP,DEL_GROUP,CHGRP_ID,ROLE_ASSIGN,ROLE_REMOVE  -i


#########################################################
# Malware scans - simple regexs
#########################################################

## Malware scans using remote gtihub repo and regex patterns
echo
echo "${YELLOW}--== Malware checks using simple regex patterns ==--${NC}"
echo echo "${GREEN}--===================================================--${NC}"
echo

echo
echo "scan malware patterns in usr"
echo '=========================================='
#cd /usr && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo
echo "scan malware patterns in www"
echo '=========================================='
#cd /var/www
#python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo
echo "scan malware patterns in home"
echo '=========================================='
#cd /home && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo
echo "scan malware patterns in root"
echo '=========================================='
#cd /root && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo "scan malware patterns in dev"
echo '=========================================='
#cd /dev && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo "scan malware in tmp"
echo '=========================================='
#cd /tmp && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)

echo "scan malware in var spool cron"
echo '=========================================='
#cd /var/spool/cron && python <(curl -ks https://raw.githubusercontent.com/ianneilsen/Pyscan/master/pyscan.py)


#########################################################
# Look for configs
#########################################################
# find config.inc.php files" => "
echo "# find all sgid files"
find / -type f -name config.inc.php

echo "# find config* files => "
find / -type f -name \"config*\"

echo "# find all service.pwd files => "
find / -type f -name service.pwd

echo "# find all .htpasswd files => "
find / -type f -name .htpasswd

echo "# find all .bash_history files => "
find / -type f -name .bash_history

echo "# find all .fetchmailrc files => "
find / -type f -name .fetchmailrc

#locate httpd.conf
#locate vhosts.conf
#locate proftpd.conf
#locate psybnc.conf
#locate my.conf
#locate admin.php
#locate cfg.php
#locate conf.php
#locate config.dat
#locate config.php
#locate config.inc
#locate config.inc.php
#locate config.default.php
#locate config
#locate '.conf'
#locate '.pwd'
#locate '.sql'

echo
echo " Look for htaccess file/s"
echo '=========================================='
find / -name .htaccess


echo
echo "# The following command searches for all .htaccess files in all subdirectories that contains ‘http’. This will list all redirect rules that may include malicious redirect"
echo '=========================================='
find . -type f -name '\.htaccess' | xargs grep -i http;
echo

locate '.htpasswd'
echo "htpass"

locate '.bash_history'
locate '.mysql_history'
locate '.pgpass'
locate '.my.cnf'
locate '.passwd'
locate '.htpass'
#locate '.fetchmailrc'
#locate backup
locate dump
#locate priv


#########################################################
# Grep dodgy stuff in files
#########################################################

# Grep dodgy php files

echo
echo "php files with dodgy encodings"

find / -type f -name "*.php" | xargs grep -l "eval *(" --color
find / -type f -name "*.php" | xargs grep -l "base64_decode *(" --color
find / -type f -name "*.php" | xargs grep -l "gzinflate *(" --color

## grepping for simple terms
echo "${YELLOW}--== webshell string checks - simple ==--${NC}"
echo echo "${GREEN}--===================================================--${NC}"
echo

echo
echo "Check for common shells & strings in files"
echo '=========================================='
echo

echo
echo "grep for webshell in var 1 of 17"
echo '=========================================='
grep --exclude-dir=run -Rilw webshell /var 

echo
echo "grep for webshell in root 2 of 19"
echo '=========================================='
grep -Rilw webshell /root

echo
echo "grep for webshell in tmp 3 of 19"
echo '=========================================='
grep -Rilw webshell /tmp 


#echo "win 2 of 17"
#grep --exclude-dir=proc -Rilw win / 

# echo "shells 3 of 17"
# grep --exclude-dir=proc -Rilw shells /

# echo "c0ded 4 of 17"
# grep --exclude-dir=proc -Rilw c0ded /

# echo "shadow 5 of 17"
# grep --exclude-dir=proc -Rilw shadow /

# echo "gmail 6 of 17"
# grep --exclude-dir=proc -Rilw gmail /

# echo "yahoo 7 of 17"
# grep --exclude-dir=proc -Rilw yahoo /

echo
echo "grep base64 10 of 19"
grep --exclude-dir=run -Rilw base64 /var

echo
echo "grep base64 11 of 19"
grep -Rilw base64 /tmp


# echo "gzinflate 9 of 17"
# grep --exclude-dir=proc -Rilw gzinflate /

# echo "rot13 10 of 17"
# grep --exclude-dir=proc -Rilw rot13 /

# echo "getgid 11 of 17"
# grep --exclude-dir=proc -Rilw getegid /

# echo "uid 12 of 17"
# grep --exclude-dir=proc -Rilw uid /

# echo "phpversion 13 of 17"
# grep --exclude-dir=proc -Rilw phpversion /

# echo "pastebin 14 of 17"
# grep --exclude-dir=proc -Rilw pastebin /

# echo "chmod 15 of 17"
# grep --exclude-dir=proc -Rilw chmod /

# echo "xploit 16 of 17"
# grep --exclude-dir=proc -Rilw xploit /

# echo "base64_decode 17 of 17"
# grep --exclude-dir=proc -Rilw base64_decode /


#########################################################
# Quick log checks
#########################################################

## Quick check on logs
echo "${YELLOW}--== LOG checks ==--${NC}"
echo echo "${GREEN}--===================================================--${NC}"
echo


echo "Check logs quickly for signs of intrusion"
echo '=========================================='
echo

echo
echo "grep sql injection in httpd logs"
echo '=========================================='
grep -iP "UNION" /var/log/apache2/access* 

echo
echo "grep sql injection in httpd logs"
echo '=========================================='
grep -ic "failed" /var/log/apache2/error* |grep -v :0

#TODO add in my common log greps for malicious hits

#########################################################
# Check swap space
#########################################################
#check swap space
echo "${YELLOW}--== SWAP s[ace checks ==--${NC}"
echo echo "${GREEN}--===================================================--${NC}"
echo

echo "grep swap space for email string"
strings /dev/dm-1 | grep -i 'email=' | grep @ | uniq

echo
echo "grep swap space for password string"
strings <swap_device> | grep "&password="

echo
echo "grep swap space for creditcard string"
strings <swap_device> | grep "&credit="

echo
echo "grep swap space for card string"
strings <swap_device> | grep "&card="



echo 
# Print a pretty message - Unicorns are ????
msg2()
{
  echo "${GREEN}[+]${NC} ${@}"

  return $SUCCESS
}

echo
echo
msg2 "Game End - Finish him PROFIT"
echo

#########################################################
# Extra checks
#########################################################

# maldet
# pyscan
# 


# set system accounts shell to no
# for account in `awk -F':' '{ if (( $7 == "/bin/bash" || $7 == "/bin/sh" )&& ($3>0 && $3<'$UID_MIN' ) ) print $1 }' /etc/passwd`
# do
#   usermod -s /bin/false "$account"
# done

#EOF

# TODO
#add in10. DNS Request Anomalies
#Mismatched Port-Application Traffic
#7. Large Numbers Of Requests For The Same File
#6. HTML Response Sizes
#5. Swells In Database Read Volume 
#3. Geographical Irregularities
#2. Anomalies In Privileged User Account Activity
#1. Unusual Outbound Network Traffic
#file creation
# add in zgrep on logs - sql, xss and file uploads and file extracts.
# diff bin files expecially netstat, ls, cp, mv, w, top, htop, chsh, slice, syslogd, socklist, ss, lsof, ps, chmod, useradd
