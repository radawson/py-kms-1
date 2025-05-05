#!/bin/bash
echo "Updating OS"
sudo apt update
sudo apt -y full-upgrade
sudo apt -y autoremove
sudo apt -y clean

echo "Updating KMS"

cd py-kms-1
git pull
git checkout master

sudo systemctl stop kms-server

sudo cp -r py-kms/* /opt/py-kms
sudo chown -R pykms:pykms /opt/py-kms

echo "Updating Python dependencies"
# Activate virtual environment and update dependencies
sudo -u pykms /opt/py-kms/venv/bin/pip install -U pip pip-tools
sudo -u pykms /opt/py-kms/venv/bin/pip-compile --upgrade /opt/py-kms/requirements.in
sudo -u pykms /opt/py-kms/venv/bin/pip-sync /opt/py-kms/requirements.txt

sudo systemctl start kms-server 