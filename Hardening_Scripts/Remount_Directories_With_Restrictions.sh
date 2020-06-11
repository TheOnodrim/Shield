#!/bin/bash

remount_directories_with_restrictions() {
  # Mounts /proc with hidepid=2
  mount -o remount,rw,hidepid=2 /proc
  
  # Mounts /tmp with noexec
  mount -o remount,noexec /tmp

  # Mount /dev with noexec
  mount -o remount,noexec /dev

  # Mounts /run as nodev
  mount -o remount,nodev /run
}
remount_directories_with_restrictions
