#!/bin/bash
restrict_logins() {
  # Restrics logins by configuring login.defs
  sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
  sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
  echo "SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000" >> /etc/login.defs
}
restrict_logins
