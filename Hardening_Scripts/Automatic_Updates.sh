#!/bin/bash

automatic_updates() {
  # Enables automatic updates
  apt-get install unattended-upgrades 
  dpkg-reconfigure -plow unattended-upgrades
}
automatic_updates
