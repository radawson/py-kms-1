#!/bin/sh
# Installs py-kms as a service on OpenWRT devices
# Run as root
message=""

setup_ubuntu(){
	sudo cp ./resources/kms-server-ubuntu /lib/systemd/system/kms-server.service
	sudo systemctl daemon-reload
	sudo systemctl enable kms-server.service
	printf "$message"
	sudo systemctl start kms-server.service
}

setup_openwrt(){
	cp ./resources/kms-server-owrt /etc/init.d/kms-server
	chmod 755 /etc/init.d/kms-server
	/etc/init.d/kms-server enable

	message+="py-kms will autodetect the LAN bridge IP address on reboot or restart"
	message+="If you change the IP in the GUI, you must still manually restart\n"
	message+="\nTo start the server manually, type '/etc/init.d/kms-server start'"
	message+="\nTo stop the server, type '/etc/init.d/kms-server stop'"
	printf "$message"
	/etc/init.d/kms-server start
}

# TODO: modify the message for each OS use case
message="\npy-kms installed as a process that starts on boot\n"
message+="\n\nProblems? https://github.com/radawson/py-kms/issues"
message+="\n\nStarting KMS server now\n"

# TODO: detect operating system and run appropriate script

setup_openwrt
printf "\n\nProblems? https://github.com/radawson/py-kms/issues"
printf "\n\nStarting KMS server now\n"
