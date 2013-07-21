Quick NIX Secure Script
==============
Quick NIX Secure Script is used to **harden** and **secure** basic permissions and ownership **on the fly**.  This script can be used during boot up, cron,
bootstrapping, kickstart, jumpstart and during other system deployments.

Why use this?
--------------
Many times in (prod)uction world prior system admins harden without 
automation or towards an industry baseline. This is to help get to a point
of standardization and quickly set or reset basic system security.

Requirements
------------
  * RHEL 5-6, Fedora 17-19, Ubuntu 10-13, Solaris 9-10 and OpenSolaris
  * root or equivalent
  * basic /bin /sbin /usr/bin executables

Installation
------------
    git clone https://github.com/marshyski/quick_secure.git
    chmod 0700 ./quick_secure/quick_secure.sh

Usage
-----
  * **-c** argument reviews what's commented out in quick_secure.sh
  ``./quick_secure/quick_secure.sh -c``
  * **-u** argument reviews what's being applied to your current system.
  ``./quick_secure/quick_secure.sh -u``
  * **-f** argument forces settings without being prompt with "are you sure"
    question.
  ``./quick_secure/quick_secure.sh -f``

  * Run quick_secure.sh for the first time: ``./quick_secure/quick_secure.sh`` in CLI
  * Setup quick_secure.sh to run every sunday at 11PM via root's cron: ``00 23 * * 0 /root/quick_secure/quick_secure.sh -f``

Help & Feedback
---------------
You can email (timski@linux.com) me directly if you need help, submit an issue or pull request.  Fork it.