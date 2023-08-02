[![Tests](https://github.com/m-erhardt/check-synology-plugins/actions/workflows/tests.yml/badge.svg)](https://github.com/m-erhardt/check-synology-plugins/actions/workflows/tests.yml) [![Release](https://img.shields.io/github/release/m-erhardt/check-synology-plugins.svg)](https://github.com/m-erhardt/check-synology-plugins/releases)
# check-synology-plugins

## About
* this repository contains a collection of Icinga / Nagios plugins to monitor Synology NAS devices via SNMPv3
* Written for python3 (CI tests are run with python 3.6, 3.8, 3.9 and 3.10)
* Uses SNMPv3 in AuthPriv or authNoPriv mode

### Compatibility
these plugins should work with all Synology devices running Synology DSM (DiskStation Manager)

## Documentation
* [check_synology_cpu.py](docs/check_synology_cpu.md)
* [check_synology_disks.py](docs/check_synology_disks.md)
* [check_synology_ram.py](docs/check_synology_ram.md)
* [check_synology_ups.py](docs/check_synology_ups.md)
* [check_synology_volumes.py](docs/check_synology_volumes.md)

### Installing dependencies
* `pip3 install -r requirements.txt`

## Contributing
* You're welcome to open pull requests
* When contributing code please make sure if follows the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
* Test your code with pycodestyle and pylint to avoid obvious issues
  * `pycodestyle ./*.py`
  * `pylint ./*.py`

