<h1 align="center">
  <br>
  <a href="https://github.com/CrystalX127/Shield.git"><img src="https://image.freepik.com/free-vector/golden-shield-retro-design_12454-5380.jpg" alt="Logo" width="500"></a>
  <br>
  Shield:
  <br>
</h1>

<p align="center">
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Liscence-MIT-informational?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Language-Python and Bash-9cf?style=flat-square&logo=appveyor" >
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
    <img src="https://img.shields.io/badge/Repository Status-Active-success?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Contributions-Welcome-yellow?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Build-Passing-orange?style=flat-square&logo=appveyor">
  </a>
</p>

Photo Source: https://image.freepik.com/free-vector/golden-shield-retro-design_12454-5380.jpg

Shield is a zero configuration, single file python script made to be run to harden and secure your Debian or Debian based OS.
The python script is used to create a UI and automate bash hardening scripts.

- Zero installation 
- Zero configuration
- Single file python script

## Usage:
Clone the script and follow these instruction below, and then run it as root and select which sections to run when prompted.
```
   1. git clone https://github.com/CrystalX127/Shield.git
   2. cd Shield
   3. sudo su
   4. python Shield.py
```
## Warning:
This shell script reverts the ssh port to `652`, and it restricts the ssh key to the admin user.
## Supported OS types:
- Debian 10
- Debian 8
- Debian based OS's

## What does this python script do?
- Adds a legal banner to /etc/motd, /etc/issue and /etc/issue.net
- Adds an automatic updater
- Adds a daily cronjob to update system packages on the server
- Configures the iptables
- Configures the kernel
- Disables core dumps
- Disables firewire and usb storage
- Disables uncommon filesystems
- Disables uncommon network protocols
- Enables process accounting
- Installs and configures auditd with reasonable rules
- Installs and sets up aide
- Installs fail2ban
- Installs packages recommended by lynis
- Moves /tmp to /tmpfs
- Purges old and removed packages
- Remounts /tmp, /proc, /dev, /run to be more restrictive
- Restricts access to compilers
- Restricts access to /root 
- Restricts firewall to only allow ssh on port `652`
- Restricts logins
- Restricts ssh, and enables ssh only for the admin user
- Updates system packages

## Contributing:
Please open issues and pull requests on anything you come across.

## Dependencies:
Python must be installed on you computer and you must have a python version of 3.5 or higher.
