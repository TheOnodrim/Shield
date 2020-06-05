#!/bin/bash

automatic_updates() {
  # Enables automatic updates
  apt install unattended-upgrades 
  dpkg-reconfigure -plow unattended-upgrades
}
automatic_update
