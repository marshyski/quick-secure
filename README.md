Quick NIX Secure Script
==============

Quick NIX Secure Script is used to **harden** and **secure** basic permissions and ownership **on the fly**.  This script can be used during boot up, cron, bootstrapping, kickstart, jumpstart and during other system deployments.  I recommend using CM tools like Puppet or Ansible, but this is still nice.

Why use this?
--------------
Many times in (**prod**)uction world prior admins harden without **automation** or towards an industry **baseline**. This is to help get to a point of standardization and quickly set or reset basic system security.

Use before or after app deploymentz.  I don't set umasks, so everything should work regardless ^_^

Industry Compliance
------------
This is influenced from DISA STIGs, ODAA, NSA and NIST/FIPs.  This does not enforce towards those baselines, but helps minimize CAT I-III findings.

Requirements
------------
  * RHEL 5-6, Fedora 17-20, Ubuntu 10-13, Solaris 9-10 and OpenSolaris
  * root or equivalent
  * basic /bin /sbin /usr/bin executables

Installation
------------
(Easiest method to get going)

    curl -sfO https://raw.githubusercontent.com/marshyski/quick-secure/master/quick-secure && bash quick-secure

    
(Alternative)  

    git clone https://github.com/marshyski/quick-secure.git
	chmod 0700 ./quick-secure/quick-secure

Securing Docker Containers
------------
(Easiest method)

    RUN cd / && curl -sfO https://raw.githubusercontent.com/marshyski/quick-secure/master/quick-secure && bash /quick-secure -f

(Alternative method) 

    ADD quick-secure /quick-secure
    RUN bash /quick-secure -f

Usage
-----
  * **-c** argument reviews what's commented out in quick-secure.
  ``./quick-secure/quick-secure -c``
  * **-u** argument reviews what's being applied to your current system.
  ``./quick-secure/quick-secure -u``
  * **-f** argument forces settings without being prompt with "are you sure"
    question.
  ``./quick-secure/quick-secure -f``
  * Run quick-secure for the first time: ``./quick-secure/quick-secure`` in CLI.
  * Setup quick-secure to run every sunday at 11PM via root's cron: 
    ``00 23 * * 0 /root/quick-secure/quick-secure -f``


Help & Feedback
---------------
You can email (timski@linux.com) me directly if you need help, submit an issue or pull request.  Fork it.

**Looking for better hardening for Ubuntu so pull request quick-secure.**
