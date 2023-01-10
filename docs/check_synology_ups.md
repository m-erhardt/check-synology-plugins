# check_synology_ups.py
this Icinga/Nagios plugin checks if a uninterruptible power supply is connected to the Synology NAS via USB.

![Output of check_synology_ups.py](img/check_synology_ups-small.png?raw=true "Output of check_synology_ups.py")

## Usage

```
./check_synology_ups.py --help
usage: check_synology_ups.py [-h] -H HOST [-p PORT] [-t TIMEOUT] -u USER
                             [-l {authPriv,authNoPriv}] -A AUTHKEY
                             [-X PRIVKEY]
                             [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                             [-x {DES,3DES,AES,AES192,AES256}]

Icinga/Nagios plugin which checks if a UPS device is connected to the NAS via
USB

optional arguments:
  -h, --help            show this help message and exit

Connection parameters:
  -H HOST, --host HOST  hostname or IP address
  -p PORT, --port PORT  SNMP port
  -t TIMEOUT, --timeout TIMEOUT
                        SNMP timeout

SNMPv3 parameters:
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
./check_synology_ups.py --host 1.2.3.4 \
                        --user monitoring \
                        --authmode SHA \
                        --authkey 'ABCDEF' \
                        --privmode AES \
                        --privkey '123456'


OK - UPS connected (Smart-UPS X 2200, Status: "OL")
```
### Parameters

