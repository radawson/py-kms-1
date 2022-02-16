#!/bin/sh
# Installs py-kms as a service on OpenWRT devices
# v 1.0.1
# Run as root
# (c) Richard Dawson 2020, 2021

MESSAGE="\npy-kms installed as a process that starts on boot\n"

setup_ubuntu(){
  sudo cp ./resources/kms-server-ubuntu /lib/systemd/system/kms-server.service
  sudo systemctl daemon-reload
  sudo systemctl enable kms-server.service
  printf "${MESSAGE}"
  sudo systemctl start kms-server.service
}

setup_openwrt(){
  cp ./resources/kms-server-owrt /etc/init.d/kms-server
  chmod 755 /etc/init.d/kms-server
  /etc/init.d/kms-server enable
  MESSAGE="${MESSAGE}""py-kms will autodetect the LAN bridge IP address on reboot or restart"
  MESSAGE="${MESSAGE}""If you change the IP in the GUI, you must still manually restart\n"
  MESSAGE="${MESSAGE}""\nTo start the server manually, type '/etc/init.d/kms-server start'"
  MESSAGE="${MESSAGE}""\nTo stop the server, type '/etc/init.d/kms-server stop'"
  printf "${MESSAGE}"
  /etc/init.d/kms-server start
}

# TODO: modify the message for each OS use case
MESSAGE="${MESSAGE}""\n\nProblems? https://github.com/radawson/py-kms-1/issues"
MESSAGE="${MESSAGE}""\n\nStarting KMS server now\n"

# TODO: detect operating system and run appropriate script

#------------------------
# Main Logic
#------------------------

setup_openwrt
printf "\n\nProblems? https://github.com/radawson/py-kms-1/issues"
printf "\n\nStarting KMS server now\n"
