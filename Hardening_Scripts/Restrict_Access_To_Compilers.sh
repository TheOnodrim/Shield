#!/bin/bash 
restrict_access_to_compilers() {
  # Restricts access to compilers
  if [ -d "/usr/bin/as" ]
  then
  chmod o-x /usr/bin/as /usr/bin/g++ /usr/bin/gcc
  chmod o-r /usr/bin/as /usr/bin/g++ /usr/bin/gcc
  chmod o-w /usr/bin/as
  fi
  
  if [ -d "/usr/bin/g++" ]
  then
  chmod o-x /usr/bin/g++ 
  chmod o-r /usr/bin/g++ 
  chmod o-w /usr/bin/g++
  
  if [ -d "/usr/bin/gcc" ]
  chmod o-x /usr/bin/gcc
  chmod o-r /usr/bin/gcc
  chmod o-w /usr/bin/gcc
}
restrict_access_to_compilers
