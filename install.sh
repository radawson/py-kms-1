#!/bin/sh
# Installs py-kms as a service on OpenWRT devices
# v2.0.0

# (c) Richard Dawson 2020, 2021

# Default variables
# Change these if you need to
BRANCH="master"
MESSAGE="\npy-kms installed as a process that starts on boot\n"
# TODO: modify the message for each OS use case

# Functions
check_root() {
  # Check to ensure script is not run as root
  if [[ "${UID}" -eq 0 ]]; then
    UNAME=$(id -un)
    printf "\nThis script must not be run as root.\n\n" >&2
    usage
  fi
}

echo_out() {
  local MESSAGE="${@}"
  if [[ "${VERBOSE}" = 'true' ]]; then
    printf "${MESSAGE}\n"
  fi
}

setup_ubuntu(){
  sudo cp ./resources/kms-server-ubuntu /lib/systemd/system/kms-server.service
  sudo systemctl daemon-reload
  sudo systemctl enable kms-server.service
  sudo systemctl start kms-server.service
}

setup_openwrt(){
  cp ./resources/kms-server-owrt /etc/init.d/kms-server
  chmod 755 /etc/init.d/kms-server
  /etc/init.d/kms-server enable
  MESSAGE="${MESSAGE}""py-kms will autodetect the LAN bridge IP address on reboot or restart\n"
  MESSAGE="${MESSAGE}""If you change the IP in the GUI, you must still manually restart\n"
  MESSAGE="${MESSAGE}""\nTo start the server manually, type '/etc/init.d/kms-server start'\n"
  MESSAGE="${MESSAGE}""\nTo stop the server, type '/etc/init.d/kms-server stop'\n"
  /etc/init.d/kms-server start
}

usage() {
  echo "Usage: ${0} [-ouv]" >&2
  echo "Sets up and starts KMS server."
  echo "Do not run as root."
  echo "-o		Install for OpenWRT."
  echo "-u		Install for Ubuntu."
  echo "-v 		Verbose mode. Displays the server name before executing COMMAND."
  exit 1
}


#------------------------
# Main Logic
#------------------------

# TODO: detect operating system and run appropriate script automatically

# Provide usage statement if no parameters
while getopts vdou OPTION; do
  case ${OPTION} in
    v)
      # Verbose is first so any other elements will echo as well
      VERBOSE='true'
      echo_out "Verbose mode on."
      ;;
	d)
	# Set installation to dev branch
	  BRANCH="dev"
	  echo_out "Branch set to dev branch"
	  ;;
    o)
	# OpenWRT
      echo_out "Setting up for OpenWRT."
	  setup_openwrt
      ;;
	u)
	# Ubuntu
	  echo_out "Setting up for Ubuntu."
	  setup_ubuntu
	  ;;
    ?)
      echo "invalid option" >&2
      usage
      ;;
  esac
done

# Clear the options from the arguments
shift "$(( OPTIND - 1 ))"

# TODO: Shift messages to individual OS installations

MESSAGE="${MESSAGE}""\n\nProblems? https://github.com/radawson/py-kms-1/issues"

printf "\n\n${MESSAGE}\n"
printf "\nStarting KMS server now\n"
