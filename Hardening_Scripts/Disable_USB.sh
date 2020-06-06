#!/bin/bash

disable_usb() {
  # Disables usb
  echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}
disable_usb
