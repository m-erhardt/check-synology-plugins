# check_synology_ram.py
this Icinga/Nagios plugin checks the RAM usage on a Synology NAS.

![Output of check_synology_ram.py](img/check_synology_ram-small.png?raw=true "Output of check_synology_ram.py")

## Usage

```
./check_synology_ram.py --help
usage: check_synology_ram.py [-h] -H HOST [-p PORT] [-t TIMEOUT] -u USER
                             [-l {authPriv,authNoPriv}] -A AUTHKEY
                             [-X PRIVKEY]
                             [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                             [-x {DES,3DES,AES,AES192,AES256}] [-w WARN]
                             [-c CRIT]

Icinga/Nagios plugin which checks the RAM memory usage on a Synology NAS

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
  -w WARN, --warn WARN  Memory warning threshold (in percent)
  -c CRIT, --crit CRIT  Memory critical threshold (in percent)
```

### Usage example
```
./check_synology_ram.py --host 1.2.3.4 \
                        --user monitoring \
                        --authmode SHA \
                        --authkey 'ABCDEF' \
                        --privmode AES \
                        --privkey '123456' \
                        --warn 80 \
                        --crit 90

OK - Total: 7973MB, Used: 6868MB (86.14%), Buffer/Cache: 980MB (12.29%) | 'memory'=7032880KB;7348144;7756374;0;8164604 'buffer'=33236KB;;;; 'cache'=970352KB;;;;
```
### Parameters
