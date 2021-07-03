#!/bin/sh
# Installs py-kms as a service on OpenWRT devices
# Run as root

sudo cp ./resources/kms-server /etc/init.d/kms-server
sudo chmod 755 /etc/init.d/kms-server
sudo /etc/init.d/kms-server enable

echo "py-kms installed as a process that starts on boot"
echo "py-kms will autodetect the LAN bridge IP address on reboot or restart"
echo -e "If you change the IP in the GUI, you must still manually restart\nthe kms-server."
echo -e "\nTo start the server manually, type '/etc/init.d/kms-server start'"
echo -e "\nTo stop the server, type '/etc/init.d/kms-server stop'"
echo -e "\nTo restart the server, type '/etc/init.d/kms-server restart'"
echo -e "\n\nProblems? https://github.com/radawson/py-kms/issues"
echo -e "\n\nStarting KMS server now"

sudo /etc/init.d/kms-server start
