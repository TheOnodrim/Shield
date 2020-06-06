#!/bin/bash

disable_uncommon_filesystems() {
  # Disables uncommon filesystems
  echo "install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true" >> /etc/modprobe.d/filesystems.conf
}
