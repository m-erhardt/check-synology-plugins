# check_synology_cpu.py
this Icinga/Nagios plugin checks the CPU usage on a Synology NAS device.

![Output of check_synology_cpu.py](img/check_synology_cpu-small.png?raw=true "Output of check_synology_cpu.py")

## Usage

```
usage: check_synology_cpu.py [-h] -H HOST [-p PORT] [-t TIMEOUT] [-6] [-w WARN] [-c CRIT] -u USER [-l {authPriv,authNoPriv}] -A AUTHKEY [-X PRIVKEY]
                             [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}] [-x {DES,3DES,AES,AES192,AES256}]

Icinga/Nagios plugin which checks the CPU load on a Synology NAS

optional arguments:
  -h, --help            show this help message and exit

Connection parameters:
  -H HOST, --host HOST  hostname or IP address
  -p PORT, --port PORT  SNMP port
  -t TIMEOUT, --timeout TIMEOUT
                        SNMP timeout
  -6, --ipv6            Use IPv6

Thresholds:
  -w WARN, --warn WARN  Memory warning threshold (in percent)
  -c CRIT, --crit CRIT  Memory critical threshold (in percent)

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
./check_synology_cpu.py --host 1.2.3.4 \
                        --user monitoring \
                        --authmode SHA \
                        --authkey 'ABCDEF' \
                        --privmode AES \
                        --privkey '123456'

OK - System: 3%, User: 10%, Idle: 81%  | 'system'=3%;80.0;90.0;0;100 'user'=10%;80.0;90.0;0;100 'idle'=81%;;;;
```
### Parameters
