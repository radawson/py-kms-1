# Readme
![repo-size](https://img.shields.io/github/repo-size/SystemRage/py-kms)
![open-issues](https://img.shields.io/github/issues/SystemRage/py-kms)
![last-commit](https://img.shields.io/github/last-commit/SystemRage/py-kms/master)
![docker-status](https://img.shields.io/docker/cloud/build/pykmsorg/py-kms)
![docker-pulls](https://img.shields.io/docker/pulls/pykmsorg/py-kms)
![read-the-docs](https://img.shields.io/readthedocs/py-kms)
***

## History
_py-kms_ is a port of node-kms created by [cyrozap](http://forums.mydigitallife.info/members/183074-markedsword), which is a port of either the C#, C++, or .NET implementations of KMS Emulator. The original version was written by [CODYQX4](http://forums.mydigitallife.info/members/89933-CODYQX4) and is derived from the reverse-engineered code of Microsoft's official KMS.

## Features
- Responds to `v4`, `v5`, and `v6` KMS requests.
- Supports activating:
    - Windows Vista 
    - Windows 7 
    - Windows 8
    - Windows 8.1
    - Windows 10 ( 1511 / 1607 / 1703 / 1709 / 1803 / 1809 )
    - Windows 10 ( 1903 / 1909 / 20H1 )
    - Windows Server 2008
    - Windows Server 2008 R2
    - Windows Server 2012
    - Windows Server 2012 R2
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022
    - Windows Server 2025
    - Microsoft Office 2010 ( Volume License )
    - Microsoft Office 2013 ( Volume License )
    - Microsoft Office 2016 ( Volume License )
    - Microsoft Office 2019 ( Volume License )
    - Microsoft Office 2021 ( Volume License )
    - Microsoft Office LTSC 2021 ( Volume License )
    - Microsoft Office LTSC 2024 ( Volume License )
- Written in Python (tested with Python 3.6.9+)
- Supports execution by `Docker`, `systemd`, `Upstart` and many more...
- Modern web-based GUI for easy management
- Multiple database backend support:
    - SQLite (default)
    - MySQL/MariaDB
    - PostgreSQL
- Real-time logging and monitoring
- Client activation tracking and statistics

## Documentation
The wiki has been completely reworked and is now available on [readthedocs.com](https://py-kms.readthedocs.io/en/latest/). It provides all necessary information on how to setup and use _py-kms_, without cluttering this readme. The documentation also houses more details about activation with _py-kms_ and how to get GVLK keys.
       
## Quick Start

### Basic Server
To start the server with default settings:
```bash
python3 pykms_Server.py
```
This will start the server on all interfaces (0.0.0.0) on port 1688.

### Web GUI
To enable the web-based management interface:
```bash
python3 pykms_Server.py -wg --web-port 8080
```
Access the web interface at `http://localhost:8080`

### Database Configuration
The server supports multiple database backends:

#### SQLite (Default)
```bash
python3 pykms_Server.py -s database.db
```

#### MySQL/MariaDB
```bash
python3 pykms_Server.py --db-type mysql --db-host localhost --db-name pykms --db-user user --db-password pass
```

#### PostgreSQL
```bash
python3 pykms_Server.py --db-type postgresql --db-host localhost --db-name pykms --db-user user --db-password pass
```

### Docker
Start with default settings:
```bash
docker run -d --name py-kms --restart always -p 1688:1688 pykmsorg/py-kms
```

Start with web GUI and MySQL:
```bash
docker run -d --name py-kms \
  -p 1688:1688 -p 8080:8080 \
  -e WEB_GUI=true \
  -e DB_TYPE=mysql \
  -e DB_HOST=mysql-server \
  -e DB_NAME=pykms \
  -e DB_USER=user \
  -e DB_PASSWORD=pass \
  pykmsorg/py-kms
```

### Help
For full command line options:
```bash
python3 pykms_Server.py -h
python3 pykms_Client.py -h
```

## License
- _py-kms_ is [![Unlicense](https://img.shields.io/badge/license-unlicense-lightgray.svg)](https://github.com/SystemRage/py-kms/blob/master/LICENSE)
- _py-kms GUI_ is [![MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/SystemRage/py-kms/blob/master/LICENSE.gui.md) © Matteo ℱan
