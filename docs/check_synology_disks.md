# check_synology_disks.py
this Icinga/Nagios plugin checks the status of all individual hard drives connected to a Synology NAS device.

![Output of check_synology_disks.py](img/check_synology_disks-small.png?raw=true "Output of check_synology_disks.py")

## Usage

```
./check_synology_disks.py --help
usage: check_synology_disks.py [-h] -H HOST [-p PORT] [-t TIMEOUT] -u USER
                               [-l {authPriv,authNoPriv}] -A AUTHKEY
                               [-X PRIVKEY]
                               [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                               [-x {DES,3DES,AES,AES192,AES256}]

Icinga/Nagios plugin which checks the state of all individual disks on a
Synology NAS

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  hostname or IP address
  -p PORT, --port PORT  SNMP port
  -t TIMEOUT, --timeout TIMEOUT
                        SNMP timeout
  -u USER, --user USER  SNMPv3 user name
  -l {authPriv,authNoPriv}, --seclevel {authPriv,authNoPriv}
                        SNMPv3 security level
  -A AUTHKEY, --authkey AUTHKEY
                        SNMPv3 auth key
  -X PRIVKEY, --privkey PRIVKEY
                        SNMPv3 priv key
  -a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}, --authmode {MD5,SHA,SHA224,SHA256,SHA384,SHA512}
                        SNMPv3 auth mode
  -x {DES,3DES,AES,AES192,AES256}, --privmode {DES,3DES,AES,AES192,AES256}
                        SNMPv3 privacy mode
```

### Usage example
```
./check_synology_disks.py --host 1.2.3.4 \
                         --user monitoring \
                         --authmode SHA \
                         --authkey 'ABCDEF' \
                         --privmode AES \
                         --privkey '123456'

OK - Drive 1: Normal, Drive 2: Normal, Drive 3: Normal, Drive 4: Normal, Drive 5: Initialized
```
### Parameters
