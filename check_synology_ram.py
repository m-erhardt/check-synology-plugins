#!/bin/env python3.6
"""
###############################################################################
# check_synology_ram.py
# Icinga/Nagios plugin that checks the memory usage on a Synology NAS station
# using the UCD-SNMP-MIB
#
#
# Author        : Mauno Erhardt <mauno.erhardt@burkert.com>
# Copyright     : (c) 2021 Burkert Fluid Control Systems
# Source        : https://github.com/m-erhardt/check-synology-plugins
# License       : GPLv3 (http://www.gnu.org/licenses/gpl-3.0.txt)
#
###############################################################################
"""

import sys
from argparse import ArgumentParser
from pysnmp.hlapi import bulkCmd, SnmpEngine, UsmUserData, \
                         UdpTransportTarget, \
                         ObjectType, ObjectIdentity, \
                         ContextData, usmHMACMD5AuthProtocol, \
                         usmHMACSHAAuthProtocol, \
                         usmHMAC128SHA224AuthProtocol, \
                         usmHMAC192SHA256AuthProtocol, \
                         usmHMAC256SHA384AuthProtocol, \
                         usmHMAC384SHA512AuthProtocol, usmDESPrivProtocol, \
                         usm3DESEDEPrivProtocol, usmAesCfb128Protocol, \
                         usmAesCfb192Protocol, usmAesCfb256Protocol

authprot = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
    }
privprot = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}


def get_args():
    """ Parse Arguments """
    parser = ArgumentParser(
                 description="Icinga/Nagios plugin which checks the RAM \
                             memory usage on a Synology NAS",
                 epilog=""
             )
    parser.add_argument("-H", "--host", required=True,
                        help="hostname or IP address", type=str, dest='host')
    parser.add_argument("-p", "--port", required=False, help="SNMP port",
                        type=int, dest='port', default=161)
    parser.add_argument("-t", "--timeout", required=False, help="SNMP timeout",
                        type=int, dest='timeout', default=10)
    parser.add_argument("-u", "--user", required=True,
                        help="SNMPv3 user name", type=str, dest='user')
    parser.add_argument("-l", "--seclevel", required=False,
                        help="SNMPv3 security level", type=str,
                        dest="v3mode",
                        choices=["authPriv", "authNoPriv"], default="authPriv")
    parser.add_argument("-A", "--authkey", required=True,
                        help="SNMPv3 auth key", type=str, dest='authkey')
    parser.add_argument("-X", "--privkey", required=False,
                        help="SNMPv3 priv key", type=str, dest='privkey')
    parser.add_argument("-a", "--authmode", required=False,
                        help="SNMPv3 auth mode", type=str, dest='authmode',
                        default='SHA',
                        choices=['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384',
                                 'SHA512'])
    parser.add_argument("-x", "--privmode", required=False,
                        help="SNMPv3 privacy mode", type=str, dest='privmode',
                        default='AES',
                        choices=['DES', '3DES', 'AES', 'AES192', 'AES256'])
    parser.add_argument("-w", "--warn", required=False,
                        help="Memory warning threshold (in percent)",
                        type=float, dest='warn', default="80")
    parser.add_argument("-c", "--crit", required=False,
                        help="Memory critical threshold (in percent)",
                        type=float, dest='crit', default="90")
    args = parser.parse_args()
    return args


def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    if args.v3mode == "authPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey, args.privkey,
                        authProtocol=authprot[args.authmode],
                        privProtocol=privprot[args.privmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )
    elif args.v3mode == "authNoPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey,
                        authProtocol=authprot[args.authmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            exit_plugin("3", ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print('%s at %s' % (error_status.prettyPrint(),
                                error_index and
                                var_binds[int(error_index) - 1][0] or '?'))
        else:
            # split OID and value into two fields and append to return element
            table.append([str(var_binds[0][0]), str(var_binds[0][1])])

    # return list with all OIDs/values from snmp table
    return table


def exit_plugin(returncode, output, perfdata):
    """ Check status and exit accordingly """
    if returncode == "3":
        print("UNKNOWN - " + str(output))
        sys.exit(3)
    if returncode == "2":
        print("CRITICAL - " + str(output) + " | " + str(perfdata))
        sys.exit(2)
    if returncode == "1":
        print("WARNING - " + str(output) + " | " + str(perfdata))
        sys.exit(1)
    elif returncode == "0":
        print("OK - " + str(output) + " | " + str(perfdata))
        sys.exit(0)


def main():
    """ Main program code """

    # Get Arguments
    args = get_args()

    # Get data via SNMP from UCD-SNMP-MIB
    #    UCD-SNMP-MIB::memTotalReal
    #    UCD-SNMP-MIB::memAvailReal
    #    UCD-SNMP-MIB::memBuffer
    #    UCD-SNMP-MIB::memCached
    mem_data = get_snmp_table('1.3.6.1.4.1.2021.4', args)

    if len(mem_data) == 0:
        # Check if we received data via SNMP, otherwise exit with state Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    for i in mem_data:
        # Extract values from returned table
        if str(i[0]) == '1.3.6.1.4.1.2021.4.5.0':
            total_ram = int(i[1])
        if str(i[0]) == '1.3.6.1.4.1.2021.4.6.0':
            free_ram = int(i[1])
        if str(i[0]) == '1.3.6.1.4.1.2021.4.14.0':
            buffer_ram = int(i[1])
        if str(i[0]) == '1.3.6.1.4.1.2021.4.15.0':
            cache_ram = int(i[1])

    # Calculate used memory
    used_ram = int(total_ram - free_ram - buffer_ram - cache_ram)

    # Calculate used percentage
    used_ram_pct = round((used_ram / total_ram) * 100, 2)
    buffer_ram_pct = round(((buffer_ram + cache_ram) / total_ram) * 100, 2)

    # Calculate thresholds
    used_warn = round(total_ram * (args.warn / 100))
    used_crit = round(total_ram * (args.crit / 100))

    # Construct output string
    output = ''.join(["Total: ",  str(round(total_ram / 1024)),
                      "MB, Used: ",  str(round(used_ram / 1024)), "MB (",
                      str(used_ram_pct), "%), Buffer/Cache: ",
                      str(round((buffer_ram + cache_ram) / 1024)),
                      "MB (",  str(buffer_ram_pct), "%)"])

    # Construct perfdata string
    perfdata = ''.join(["\'memory\'=", str(used_ram), "KB;", str(used_warn),
                        ";", str(used_crit), ";0;", str(total_ram),
                        " \'buffer\'=", str(buffer_ram), "KB;;;;",
                        " \'cache\'=", str(cache_ram), "KB;;;;"])

    # Evaluate against disk thresholds
    returncode = "0"
    if used_ram >= used_warn:
        returncode = "1"
    if used_ram >= used_crit:
        returncode = "2"

    exit_plugin(returncode, output, perfdata)


if __name__ == "__main__":
    main()
