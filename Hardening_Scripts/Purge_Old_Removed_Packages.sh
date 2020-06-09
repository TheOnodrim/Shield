#!/bin/bash

purge_old_removed_packages() {
  # Purges old and removed packages
  apt autoremove 
  apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')" 
}
purge_old_removed_packages
