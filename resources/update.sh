#!/bin/bash
set -e  # Exit on any error

echo "Updating OS"
sudo apt update
sudo apt -y full-upgrade
sudo apt -y autoremove
sudo apt -y clean

echo "Updating KMS"

cd py-kms-1

# Ensure we're on master branch and clean
if ! git diff-index --quiet HEAD --; then
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "Switching to master branch from $CURRENT_BRANCH"
    git checkout master
fi

# Pull latest changes
git pull

echo "Stopping KMS service"
sudo systemctl stop kms-server

echo "Copying files"
sudo cp -r py-kms/* /opt/py-kms
sudo cp requirements* /opt/py-kms
sudo chown -R pykms:pykms /opt/py-kms

echo "Installing Python dependencies"
# Install dependencies from requirements.txt
sudo -u pykms /opt/py-kms/venv/bin/pip install -r /opt/py-kms/requirements.txt

echo "Starting KMS service"
sudo systemctl start kms-server

# Verify service is running
if ! systemctl is-active --quiet kms-server; then
    echo "Error: KMS service failed to start"
    exit 1
fi

echo "Update completed successfully" 