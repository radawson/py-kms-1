#!/bin/bash

echo "Updating Python dependencies"
# Activate virtual environment and update dependencies
sudo -u pykms /opt/py-kms/venv/bin/pip install -U pip pip-tools
sudo -u pykms /opt/py-kms/venv/bin/pip-compile --upgrade /opt/py-kms/requirements.in
sudo -u pykms /opt/py-kms/venv/bin/pip-sync /opt/py-kms/requirements.txt