#!/bin/bash
#
# Copyright 2014, Timothy Marcinowski (marshyski@gmail.com), USA
# Web site: https://github.com/marshyski/quick-secure
#
# Quick NIX Secure Script comes with ABSOLUTELY NO WARRANTY. This is free
# software, and you are welcome to redistribute it under the terms of the
# GNU General Public License. See LICENSE file for usage of this software.
#
################################################################################
#
# Quick NIX Secure Script is meant to quickly secure UNIX/Linux systems
# GNU GENERAL PUBLIC LICENSE Version 3
#
################################################################################
#
# Review script's comments "#" if you want to apply any other best practices
# to your system, uncomment.  Want to better this or recommend fixes? Submit
# a pull request or email PoC above.
#
#################################################################################

#Check if script is running with root permissions
if [[ $UID != "0" ]]; then
  echo "Sorry, must sudo or be root to run this."
  exit
fi


#Display commented out items and variables for review
if [[ $1 = "-c" ]]; then
  echo ""
  echo "==VARIABLES OF QUICK NIX SECURE SCRIPT=="
  cat $0 | grep ^[A-Z]
  echo ""
  echo "==COMMENTED OUT SECTION OF SCRIPT=="
  grep ^#[Aa-Zz] $0
  exit
fi

if [[ $1 = "-u" ]]; then
  echo ""
  cat $0 | sed 's/^[ \t]*//;s/[ \t]*$//' | grep '.' | grep -v ^#
  exit
fi


#Set variables of script
PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/local/bin:/opt/local/sbin"
PASS_EXP="60" #used to set password expire in days
PASS_WARN="14" #used to set password warning in days
PASS_CHANG="1" #used to set how often you can change password in days
SELINUX=`grep ^SELINUX= /etc/selinux/config 2>/dev/null | awk -F'=' '{ print $2 }'`


#Disclaimer
cat << 'DISC'
Quick NIX Secure Script Copyright (C) 2014 Timothy Marcinowski

# QUICK NIX SECURE SCRIPT HAS NO WARRANTY OF ANY KIND       #
# PLEASE REVIEW SCRIPT BEFORE SECURING YOUR SYSTEM(S)       #
# PLEASE USE WITH CAUTION AND DILIGENCE!!!                  #

  quick-secure -c | Review what's commented out in script
  quick-secure -u | Review what's being applied to system
  quick-secure -f | Force settings, never prompt question

# THIS WILL BREAK RHEL/CENTOS 6 GNOME GUI!!!                #
DISC

#Verify admin wants to harden system
if [[ $1 != "-f" ]]; then
  echo -n "Are you sure you want to quick secure `hostname` (y/N)? "
  read ANSWER
  if [[ $ANSWER != "y" ]]; then
    echo ""
    exit
  fi

  if [[ $ANSWER = "n" ]] || [[ $ANSWER = "" ]]; then
    echo ""
    exit
  fi

  echo ""
fi


#Set audit group variable
if [[ `grep -i ^audit /etc/group` != "" ]]; then
  AUDIT=`grep -i ^audit /etc/group | awk -F":" '{ print $1 }' | head -n 1`
else
  AUDIT="root"
fi

echo "Audit group is set to '$AUDIT'"
echo ""


#Turn off selinux before setting configurations
if [[ `getenforce 2>/dev/null` = "Enforcing" ]]; then
  setenforce 0
fi

if [[ -f /etc/sysconfig/selinux ]]; then
  sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
  echo "SELINUX=disabled" > /etc/sysconfig/selinux
  echo "SELINUXTYPE=targeted" >> /etc/sysconfig/selinux
  chmod -f 0640 /etc/sysconfig/selinux
fi


#Setup /etc/motd and /etc/issues
echo "" > /etc/motd
echo "" > /etc/issue.net
#rm -f /etc/issue /etc/issue.net
#ln -s /etc/motd /etc/issue
#ln -s /etc/motd /etc/issue.net
chown -f root:root /etc/motd /etc/issue*
chmod -f 0444 /etc/motd /etc/issue*


#Cron setup
if [[ -f /etc/cron.allow ]]; then
  if [[ `grep root /etc/cron.allow 2>/dev/null` != "root" ]]; then
    echo "root" > /etc/cron.allow
    rm -f /etc/at.deny
  else
    echo "root is already in /etc/cron.allow"
    echo ""
  fi
fi

if [[ -f /etc/cron.allow ]]; then
  if [[ ! -f /etc/at.allow ]]; then
    touch /etc/at.allow
  fi
fi

if [[ `grep root /etc/at.allow 2>/dev/null` != "root" ]]; then
  echo "root" > /etc/at.allow
  rm -f /etc/at.deny
else
  echo "root is already in /etc/at.allow"
  echo ""
fi

if [[ `cat /etc/at.deny 2>/dev/null` = "" ]]; then
  rm -f /etc/at.deny
fi

if [[ `cat /etc/cron.deny 2>/dev/null` = "" ]]; then
  rm -f /etc/cron.deny
fi


chmod -f 0700 /etc/cron.monthly/*
chmod -f 0700 /etc/cron.weekly/*
chmod -f 0700 /etc/cron.daily/*
chmod -f 0700 /etc/cron.hourly/*
chmod -f 0700 /etc/cron.d/*
chmod -f 0400 /etc/cron.allow
chmod -f 0400 /etc/cron.deny
chmod -f 0400 /etc/crontab
chmod -f 0400 /etc/at.allow
chmod -f 0400 /etc/at.deny
chmod -f 0700 /etc/cron.daily
chmod -f 0700 /etc/cron.weekly
chmod -f 0700 /etc/cron.monthly
chmod -f 0700 /etc/cron.hourly
chmod -f 0700 /var/spool/cron
chmod -f 0600 /var/spool/cron/*
chmod -f 0700 /var/spool/at
chmod -f 0600 /var/spool/at/*
chmod -f 0400 /etc/anacrontab


#File permissions and ownerships
chmod -f 1777 /tmp
chown -f root:root /var/crash
chown -f root:root /var/cache/mod_proxy
chown -f root:root /var/lib/dav
chown -f root:root /usr/bin/lockfile
chown -f rpcuser:rpcuser /var/lib/nfs/statd
chown -f adm:adm /var/adm
chmod -f 0600 /var/crash
chown -f root:root /bin/mail
chmod -f 0700 /sbin/reboot
chmod -f 0700 /sbin/shutdown
chmod -f 0600 /etc/ssh/ssh*config
chown -f root:root /root
chmod -f 0700 /root
chmod -f 0500 /usr/bin/ypcat
chmod -f 0700 /usr/sbin/usernetctl
chmod -f 0700 /usr/bin/rlogin
chmod -f 0700 /usr/bin/rcp
chmod -f 0640 /etc/pam.d/system-auth*
chmod -f 0640 /etc/login.defs
chmod -f 0750 /etc/security
chmod -f 0600 /etc/audit/audit.rules
chown -f root:root /etc/audit/audit.rules
chmod -f 0600 /etc/audit/auditd.conf
chown -f root:root /etc/audit/auditd.conf
chmod -f 0600 /etc/auditd.conf
chmod -f 0744 /etc/rc.d/init.d/auditd
chown -f root /sbin/auditctl
chmod -f 0750 /sbin/auditctl
chown -f root /sbin/auditd
chmod -f 0750 /sbin/auditd
chmod -f 0750 /sbin/ausearch
chown -f root /sbin/ausearch
chown -f root /sbin/aureport
chmod -f 0750 /sbin/aureport
chown -f root /sbin/autrace
chmod -f 0750 /sbin/autrace
chown -f root /sbin/audispd
chmod -f 0750 /sbin/audispd
chmod -f 0444 /etc/bashrc
chmod -f 0444 /etc/csh.cshrc
chmod -f 0444 /etc/csh.login
chmod -f 0600 /etc/cups/client.conf
chmod -f 0600 /etc/cups/cupsd.conf
chown -f root:sys /etc/cups/client.conf
chown -f root:sys /etc/cups/cupsd.conf
chmod -f 0600 /etc/grub.conf
chown -f root:root /etc/grub.conf
chmod -f 0600 /boot/grub2/grub.cfg
chown -f root:root /boot/grub2/grub.cfg
chmod -f 0600 /boot/grub/grub.cfg
chown -f root:root /boot/grub/grub.cfg
chmod -f 0444 /etc/hosts
chown -f root:root /etc/hosts
chmod -f 0600 /etc/inittab
chown -f root:root /etc/inittab
chmod -f 0444 /etc/mail/sendmail.cf
chown -f root:bin /etc/mail/sendmail.cf
chmod -f 0600 /etc/ntp.conf
chmod -f 0640 /etc/security/access.conf
chmod -f 0600 /etc/security/console.perms
chmod -f 0600 /etc/security/console.perms.d/50-default.perms
chmod -f 0600 /etc/security/limits
chmod -f 0444 /etc/services
chmod -f 0444 /etc/shells
chmod -f 0644 /etc/skel/.*
chmod -f 0600 /etc/skel/.bashrc
chmod -f 0600 /etc/skel/.bash_profile
chmod -f 0600 /etc/skel/.bash_logout
chmod -f 0440 /etc/sudoers
chown -f root:root /etc/sudoers
chmod -f 0600 /etc/sysctl.conf
chown -f root:root /etc/sysctl.conf
chown -f root:root /etc/sysctl.d/*
chmod -f 0700 /etc/sysctl.d
chmod -f 0600 /etc/sysctl.d/*
chmod -f 0600 /etc/syslog.conf
chmod -f 0600 /var/yp/binding
chown -f root:$AUDIT /var/log
chown -Rf root:$AUDIT /var/log/*
chmod -Rf 0640 /var/log/*
chmod -Rf 0640 /var/log/audit/*
chmod -f 0755 /var/log
chmod -f 0750 /var/log/syslog /var/log/audit
chmod -f 0600 /var/log/lastlog*
chmod -f 0600 /var/log/cron*
chmod -f 0600 /var/log/btmp
chmod -f 0660 /var/log/wtmp
chmod -f 0444 /etc/profile
chmod -f 0700 /etc/rc.d/rc.local
chmod -f 0400 /etc/securetty
chmod -f 0700 /etc/rc.local
chmod -f 0750 /usr/bin/wall
chown -f root:tty /usr/bin/wall
chown -f root:users /mnt
chown -f root:users /media
chmod -f 0644 /etc/.login
chmod -f 0644 /etc/profile.d/*
chown -f root /etc/security/environ
chown -f root /etc/xinetd.d
chown -f root /etc/xinetd.d/*
chmod -f 0750 /etc/xinetd.d
chmod -f 0640 /etc/xinetd.d/*
chmod -f 0640 /etc/selinux/config
chmod -f 0750 /usr/bin/chfn
chmod -f 0750 /usr/bin/chsh
chmod -f 0750 /usr/bin/write
chmod -f 0750 /sbin/mount.nfs
chmod -f 0750 /sbin/mount.nfs4
chmod -f 0700 /usr/bin/ldd #0400 FOR SOME SYSTEMS
chmod -f 0700 /bin/traceroute
chown -f root:root /bin/traceroute
chmod -f 0700 /usr/bin/traceroute6*
chown -f root:root /usr/bin/traceroute6
chmod -f 0700 /bin/tcptraceroute
chmod -f 0700 /sbin/iptunnel
chmod -f 0700 /usr/bin/tracpath*
chmod -f 0644 /dev/audio
chown -f root:root /dev/audio
chmod -f 0644 /etc/environment
chown -f root:root /etc/environment
chmod -f 0600 /etc/modprobe.conf
chown -f root:root /etc/modprobe.conf
chown -f root:root /etc/modprobe.d
chown -f root:root /etc/modprobe.d/*
chmod -f 0700 /etc/modprobe.d
chmod -f 0600 /etc/modprobe.d/*
chmod -f o-w /selinux/*
#umask 077 /etc/*
chmod -f 0755 /etc
chmod -f 0644 /usr/share/man/man1/*
chmod -Rf 0644 /usr/share/man/man5
chmod -Rf 0644 /usr/share/man/man1
chmod -f 0600 /etc/yum.repos.d/*
chmod -f 0640 /etc/fstab
chmod -f 0755 /var/cache/man
chmod -f 0755 /etc/init.d/atd
chmod -f 0750 /etc/ppp/peers
chmod -f 0755 /bin/ntfs-3g
chmod -f 0750 /usr/sbin/pppd
chmod -f 0750 /etc/chatscripts
chmod -f 0750 /usr/local/share/ca-certificates


#ClamAV permissions and ownership
if [[ -d /usr/local/share/clamav ]]; then
  passwd -l clamav 2>/dev/null
  usermod -s /sbin/nologin clamav 2>/dev/null
  chmod -f 0755 /usr/local/share/clamav
  chown -f root:clamav /usr/local/share/clamav
  chown -f root:clamav /usr/local/share/clamav/*.cvd
  chmod -f 0664 /usr/local/share/clamav/*.cvd
  mkdir -p /var/log/clamav
  chown -f root:$AUDIT /var/log/clamav
  chmod -f 0640 /var/log/clamav
fi
if [[ -d /var/clamav ]]; then
  passwd -l clamav 2>/dev/null
  usermod -s /sbin/nologin clamav 2>/dev/null
  chmod -f 0755 /var/clamav
  chown -f root:clamav /var/clamav
  chown -f root:clamav /var/clamav/*.cvd
  chmod -f 0664 /var/clamav/*.cvd
  mkdir -p /var/log/clamav
  chown -f root:$AUDIT /var/log/clamav
  chmod -f 0640 /var/log/clamav
fi


#DISA STIG file ownsership
chmod -f 0755 /bin/csh
chmod -f 0755 /bin/jsh
chmod -f 0755 /bin/ksh
chmod -f 0755 /bin/rsh
chmod -f 0755 /bin/sh
chmod -f 0640 /dev/kmem
chown -f root:sys /dev/kmem
chmod -f 0640 /dev/mem
chown -f root:sys /dev/mem
chmod -f 0666 /dev/null
chown -f root:sys /dev/null
chmod -f 0755 /etc/csh
chmod -f 0755 /etc/jsh
chmod -f 0755 /etc/ksh
chmod -f 0755 /etc/rsh
chmod -f 0755 /etc/sh
chmod -f 0644 /etc/aliases
chown -f root:root /etc/aliases
chmod -f 0640 /etc/exports
chown -f root:root /etc/exports
chmod -f 0640 /etc/ftpusers
chown -f root:root /etc/ftpusers
chmod -f 0664 /etc/host.lpd
chmod -f 0440 /etc/inetd.conf
chown -f root:root /etc/inetd.conf
chmod -f 0644 /etc/mail/aliases
chown -f root:root /etc/mail/aliases
chmod -f 0644 /etc/passwd
chown -f root:root /etc/passwd
chmod -f 0400 /etc/shadow
chown -f root:root /etc/shadow
chmod -f 0600 /etc/uucp/L.cmds
chown -f uucp:uucp /etc/uucp/L.cmds
chmod -f 0600 /etc/uucp/L.sys
chown -f uucp:uucp /etc/uucp/L.sys
chmod -f 0600 /etc/uucp/Permissions
chown -f uucp:uucp /etc/uucp/Permissions
chmod -f 0600 /etc/uucp/remote.unknown
chown -f root:root /etc/uucp/remote.unknown
chmod -f 0600 /etc/uucp/remote.systems
chmod -f 0600 /etc/uccp/Systems
chown -f uucp:uucp /etc/uccp/Systems
chmod -f 0755 /sbin/csh
chmod -f 0755 /sbin/jsh
chmod -f 0755 /sbin/ksh
chmod -f 0755 /sbin/rsh
chmod -f 0755 /sbin/sh
chmod -f 0755 /usr/bin/csh
chmod -f 0755 /usr/bin/jsh
chmod -f 0755 /usr/bin/ksh
chmod -f 0755 /usr/bin/rsh
chmod -f 0755 /usr/bin/sh
chmod -f 1777 /var/mail
chmod -f 1777 /var/spool/uucppublic


#Set all files in ``.ssh`` to ``600``
chmod 700 ~/.ssh && chmod 600 ~/.ssh/*


#Disable ctrl-alt-delete RHEL 6+
if [[ -f /etc/init/control-alt-delete.conf ]]; then
  if [[ `grep ^exec /etc/init/control-alt-delete.conf` != "" ]]; then
    sed -i 's/^exec/#exec/g' /etc/init/control-alt-delete.conf
  fi
fi


#Disable ctrl-alt-delete RHEL 5+
if [[ -f /etc/inittab ]]; then
  if [[ `grep ^ca:: /etc/inittab` != "" ]]; then
    sed -i 's/^ca::/#ca::/g' /etc/inittab
  fi
fi


#Remove security related packages
if [[ -f /bin/rpm ]]; then
  rpm -ev nc 2>/dev/null
  rpm -ev vsftpd 2>/dev/null
  rpm -ev nmap 2>/dev/null
  rpm -ev telnet-server 2>/dev/null
  rpm -ev rdate 2>/dev/null
  rpm -ev tcpdump 2>/dev/null
  rpm -ev vnc-server 2>/dev/null
  rpm -ev tigervnc-server 2>/dev/null
  rpm -ev wireshark 2>/dev/null
  rpm -ev --allmatches --nodeps wireless-tools 2>/dev/null
fi

if [[ `which apt-get 2>/dev/null` != "" ]]; then
  apt-get autoremove -y vsftpd 2>/dev/null
  apt-get autoremove -y nmap 2>/dev/null
  apt-get autoremove -y telnetd 2>/dev/null
  apt-get autoremove -y rdate 2>/dev/null
  apt-get autoremove -y tcpdump 2>/dev/null
  apt-get autoremove -y vnc4server 2>/dev/null
  apt-get autoremove -y vino 2>/dev/null
  apt-get autoremove -y wireshark 2>/dev/null
  apt-get autoremove -y bind9-host 2>/dev/null
  apt-get autoremove -y libbind9-90 2>/dev/null
fi


#Account management and cleanup
if [[ `which userdel 2>/dev/null` != "" ]]; then
  userdel -f games 2>/dev/null
  userdel -f news 2>/dev/null
  userdel -f gopher 2>/dev/null
  userdel -f tcpdump 2>/dev/null
  userdel -f shutdown 2>/dev/null
  userdel -f halt 2>/dev/null
  userdel -f sync 2>/dev/null
  userdel -f ftp 2>/dev/null
  userdel -f operator 2>/dev/null
  userdel -f lp 2>/dev/null
  userdel -f uucp 2>/dev/null
  userdel -f irc 2>/dev/null
  userdel -f gnats 2>/dev/null
  userdel -f pcap 2>/dev/null
  userdel -f netdump 2>/dev/null
fi


#GDM user RHEL 5 is unlocked out-of-the-box
passwd -l gdm 2>/dev/null


#Set password settings for all accounts in shadow
#sed -i 's/0:99999:7/'"$PASS_CHANG:$PASS_EXP:$PASS_WARN"'/' /etc/shadow


#Disable fingerprint in PAM and authconfig
if [[ `which authconfig 2>/dev/null` != "" ]]; then
  authconfig --disablefingerprint --update
fi


#Start-up chkconfig levels set
if [[ -f /sbin/chkconfig ]]; then
  /sbin/chkconfig --level 12345 auditd on 2>/dev/null
  #  /sbin/chkconfig yum-updatesd off 2>/dev/null
  /sbin/chkconfig isdn off 2>/dev/null
  /sbin/chkconfig bluetooth off 2>/dev/null
  /sbin/chkconfig haldaemon off 2>/dev/null #NEEDED ON FOR RHEL6 GUI
fi


#Change mount point security to nodev, noexec, nosuid (only tested on RHEL)
#/boot
#sed -i "s/\( \/boot.*`grep " \/boot " /etc/fstab | awk '{print $4}'`\)/\1,nodev,noexec,nosuid/" /etc/fstab

#/dev/shm
#sed -i "s/\( \/dev\/shm.*`grep " \/dev\/shm " /etc/fstab | awk '{print $4}'`\)/\1,nodev,noexec,nosuid/" /etc/fstab

#/var
#sed -i "s/\( \/var\/log.*`grep " \/var " /etc/fstab | awk '{print $4}'`\)/\1,nodev,noexec,nosuid/" /etc/fstab

#/var/log
#sed -i "s/\( \/var\/log.*`grep " \/var\/log " /etc/fstab | awk '{print $4}'`\)/\1,nodev,noexec,nosuid/" /etc/fstab

#/tmp
#sed -i "s/\( \/tmp.*`grep " \/tmp " /etc/fstab | awk '{print $4}'`\)/\1,nodev,noexec,nosuid/" /etc/fstab

#/home
#sed -i "s/\( \/home.*`grep " \/home " /etc/fstab | awk '{print $4}'`\)/\1,nodev,nosuid/" /etc/fstab


#Misc settings and permissions
chmod -Rf o-w /usr/local/src/*
rm -f /etc/security/console.perms


#Remove rpmnew and rpmsave files
if [[ `which rpm 2>/dev/null` != "" ]]; then
  find / -noleaf 2>/dev/null | grep -v '/net\|/proc' | grep '\.rpmsave'
  find / -noleaf 2>/dev/null | grep -v '/net\|/proc' | grep '\.rpmnew'
fi


#Set background image permissions
if [[ -d /usr/share/backgrounds ]]; then
  chmod -f 0444 /usr/share/backgrounds/default*
  chmod -f 0444 /usr/share/backgrounds/images/default*
fi

if [[ $SELINUX = enforcing || $SELINUX = permissive ]]; then
  setenforce 1
fi

#Permit ssh login from root
rootLogin='PermitRootLogin'
sshConfig='/etc/ssh/ssh_config'

if [[ -f ${sshConfig?} ]]; then
  if grep -q ${rootLogin?} ${sshConfig?}; then
    sed -i 's/.*PermitRootLogin.*/\tPermitRootLogin no/g' ${sshConfig?}
  else
    echo -e '\tPermitRootLogin no' >> ${sshConfig?}
  fi
fi

#Set home directories to 0700 permissions
if [[ -d /home ]]; then
  for x in `find /home -maxdepth 1 -mindepth 1 -type d`; do chmod -f 0700 $x; done
fi

if [[ -d /export/home ]]; then
  for x in `find /export/home -maxdepth 1 -mindepth 1 -type d`; do chmod -f 0700 $x; done
fi

#Set basic kernel parameters
if [[ `which sysctl 2>/dev/null` != "" ]]; then
  #Turn on Exec Shield for RHEL systems
  sysctl -w kernel.exec-shield=1
  #Turn on ASLR Conservative Randomization
  sysctl -w kernel.randomize_va_space=1
  #Hide Kernel Pointers
  sysctl -w kernel.kptr_restrict=1
  #Allow reboot/poweroff, remount read-only, sync command
  sysctl -w kernel.sysrq=176
  #Restrict PTRACE for debugging
  sysctl -w kernel.yama.ptrace_scope=1
  #Hard and Soft Link Protection
  sysctl -w fs.protected_hardlinks=1
  sysctl -w fs.protected_symlinks=1
  #Enable TCP SYN Cookie Protection
  sysctl -w net.ipv4.tcp_syncookies=1
  #Disable IP Source Routing
  sysctl -w net.ipv4.conf.all.accept_source_route=0
  #Disable ICMP Redirect Acceptance
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv6.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv6.conf.all.send_redirects=0
  #Enable IP Spoofing Protection
  sysctl -w net.ipv4.conf.all.rp_filter=1
  sysctl -w net.ipv4.conf.default.rp_filter=1
  #Enable Ignoring to ICMP Requests
  sysctl -w net.ipv4.icmp_echo_ignore_all=1
  #Enable Ignoring Broadcasts Request
  sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
  #Enable Bad Error Message Protection
  sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
  #Enable Logging of Spoofed Packets, Source Routed Packets, Redirect Packets
  sysctl -w net.ipv4.conf.all.log_martians=1
  sysctl -w net.ipv4.conf.default.log_martians=1
  #Perfer Privacy Addresses
  net.ipv6.conf.all.use_tempaddr = 2
  net.ipv6.conf.default.use_tempaddr = 2
  sysctl -p
fi

echo ""
echo "WARNING!WARNING!WARNING!"
echo "CHANGE ROOT'S PASSWORD AFTER RUNNING QUICK NIX SECURE SCRIPT, JUST IN CASE."
echo "WARNING!WARNING!WARNING!"
