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
  # Create pykms group if it doesn't exist
  if ! getent group pykms > /dev/null; then
    sudo groupadd -r pykms
    echo_out "Created pykms group."
  else
    echo_out "pykms group already exists."
  fi

  # Create pykms user if it doesn't exist
  if ! id "pykms" &>/dev/null; then
    sudo useradd -r -g pykms -d /opt/py-kms -s /sbin/nologin pykms
    echo_out "Created pykms system user."
  else
    echo_out "pykms user already exists."
  fi

  # Create installation directory
  echo_out "Creating installation directory /opt/py-kms..."
  sudo mkdir -p /opt/py-kms

  # Copy application files (including requirements.txt)
  echo_out "Copying application files to /opt/py-kms..."
  sudo cp -r ./py-kms/* /opt/py-kms/
  sudo cp ./requirements.txt /opt/py-kms/

  # Set ownership
  echo_out "Setting ownership for /opt/py-kms..."
  sudo chown -R pykms:pykms /opt/py-kms

  # Ensure database file exists and has correct permissions
  echo_out "Setting up database file permissions..."
  sudo -u pykms touch /opt/py-kms/pykms_database.db
  sudo chown pykms:pykms /opt/py-kms/pykms_database.db

  # Create virtual environment
  echo_out "Creating Python virtual environment in /opt/py-kms/venv..."
  # Run as pykms user to ensure correct ownership
  sudo -u pykms python3 -m venv /opt/py-kms/venv 

  # Install requirements
  echo_out "Installing dependencies from requirements.txt into virtual environment..."
  # Run pip install as pykms user
  sudo -u pykms /opt/py-kms/venv/bin/pip install -r /opt/py-kms/requirements.txt

  # Copy config file
  echo_out "Copying config file to /etc/py-kms/config.yaml..."
  sudo mkdir -p /etc/py-kms
  sudo cp ./resources/config.yaml /etc/py-kms/config.yaml
  sudo chown pykms:pykms /etc/py-kms/config.yaml

  # Copy and enable systemd service
  echo_out "Setting up systemd service..."
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
