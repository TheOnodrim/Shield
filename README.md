<h1 align="center">
  <br>
  <a href="https://github.com/CrystalX127/Shield.git"><img src="https://image.freepik.com/free-vector/golden-shield-retro-design_12454-5380.jpg" alt="Logo" width="500"></a>
  <br>
  Shield:
  <br>
</h1>

<p align="center">
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Liscence-GNU GPL v.3.0-informational?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Language-Bash-9cf?style=flat-square&logo=appveyor" >
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
    <img src="https://img.shields.io/badge/Repository Status-Inactive-red?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Contributions-Welcome-yellow?style=flat-square&logo=appveyor">
  </a>
  <a href="https://github.com/CrystalX127/Shield.git">
      <img src="https://img.shields.io/badge/Build-Passing-success?style=flat-square&logo=appveyor">
  </a>
</p>

Photo Source: https://image.freepik.com/free-vector/golden-shield-retro-design_12454-5380.jpg

Shield is a single file bash script, made to be harden and secure your Debian or Debian based OS.
This project has been thoroughly tested and checked for errors.

# If you liked it:
Feel free to star my project, I have worked very hard on this repository.

## Usage:
Clone the script and follow these instruction below, and then run it as root and select which sections to run when prompted.
```
   1. git clone https://github.com/CrystalX127/Shield.git
   2. cd Shield
   3. chmod +x Shield.sh
   4. ./Shield.sh
```
## Warning:
This shell script restricts the ssh key to the admin user.

## Supported OS types:
- Debian 10
- Debian 8
- Debian based OS's

## What does the hardening script do?
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
- Remounts  /dev, /tmp, /run and /proc to be more restrictive
- Restricts access to compilers
- Restricts access to /root 
- Restrics ssh key to admin user
- Restricts logins
- Restricts ssh, and enables ssh only for the admin user
- Updates system packages and the package list
- Sets up rkhunter and chkrootkit
- Disables thunderbolt
- Sets up psad
- Protects physical console access
- Sets up shorewall
- Installs logwatch
- Enables disk quotas
- Enables process accounting
- Restricts core file access
- Creates a daily cronjob that runs certain security based applications and opens security related log files.
- Installs and sets up SElinux
- Sets up Two-Factor Authentication
- Sets up email notifications when sudo is run
- Installs and sets up Open VPN

## Contributing:
Please open issues and pull requests on anything you come across.

## Reaching out to me:
If you have anything you would like to tell me, simply create an issue with the title To Repository Owner.

## Screenshots:
![alt text](https://user-images.githubusercontent.com/65303868/86959004-10554680-c12b-11ea-83aa-e75b9c0257f2.png)


![alt text](https://user-images.githubusercontent.com/65303868/86959587-113aa800-c12c-11ea-995f-a0227ced20a4.png)
