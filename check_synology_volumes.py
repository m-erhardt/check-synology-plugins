#!/bin/env python3
"""
###############################################################################
# check_synology_volumes.py
# Icinga/Nagios plugin that checks the volume and volume group status on a
# Synology NAS device using the SYNOLOGY-RAID-MIB
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
from re import match
from argparse import ArgumentParser
from itertools import chain
from pysnmp.hlapi import bulkCmd, SnmpEngine, UsmUserData, \
                         UdpTransportTarget, Udp6TransportTarget, \
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
raid_state_dict = {
    # SYNOLOGY-RAID-MIB::raidStatus
    '1': "Normal",
    '2': "Repairing",
    '3': "Migrating",
    '4': "Expanding",
    '5': "Deleting",
    '6': "Creating",
    '7': "RaidSyncing",
    '8': "RaidParityChecking",
    '9': "RaidAssembling",
    '10': "Canceling",
    '11': "Degrade",
    '12': "Crashed",
    '13': "DataScrubbing",
    '14': "RaidDeploying",
    '15': "RaidUnDeploying",
    '16': "RaidMountCache",
    '17': "RaidUnmountCache",
    '18': "RaidExpandingUnfinishedSHR",
    '19': "RaidConvertSHRToPool",
    '20': "RaidMigrateSHR1ToSHR2",
    '21': "RaidUnknownStatus"
}

# Return CRIT / WARN if volume state is one of these
states_crit = [12, 14, 15, 16, 17, 18, 19, 21]
states_warn = [2, 3, 5, 10, 11, 20]


def get_args():
    """ Parse Arguments """
    parser = ArgumentParser(
                 description="Icinga/Nagios plugin which checks the RAID \
                             volume state on a Synology NAS")
    connopts = parser.add_argument_group('Connection parameters')
    connopts.add_argument("-H", "--host", required=True,
                          help="hostname or IP address", type=str, dest='host')
    connopts.add_argument("-p", "--port", required=False, help="SNMP port",
                          type=int, dest='port', default=161)
    connopts.add_argument("-t", "--timeout", required=False, help="SNMP timeout",
                          type=int, dest='timeout', default=10)
    connopts.add_argument("-6", "--ipv6", required=False, help='Use IPv6',
                          dest='ipv6', action='store_true', default=False)
    thresholds = parser.add_argument_group('Thresholds')
    thresholds.add_argument("-w", "--warn", required=False,
                            help="Volume warning threshold (in percent)",
                            type=float, dest='warn', default="80")
    thresholds.add_argument("-c", "--crit", required=False,
                            help="Volume critical threshold (in percent)",
                            type=float, dest='crit', default="90")
    thresholds.add_argument("-i", "--ignore-utilization", action='append',
                            help="Ignore utilization thresholds for volume (may be repeated)",
                            type=str, dest='ignore_utilization', default=[])
    snmpopts = parser.add_argument_group('SNMPv3 parameters')
    snmpopts.add_argument("-u", "--user", required=True, help="SNMPv3 user name",
                          type=str, dest='user')
    snmpopts.add_argument("-l", "--seclevel", required=False,
                          help="SNMPv3 security level", type=str,
                          dest="v3mode",
                          choices=["authPriv", "authNoPriv"], default="authPriv")
    snmpopts.add_argument("-A", "--authkey", required=True,
                          help="SNMPv3 auth key", type=str, dest='authkey')
    snmpopts.add_argument("-X", "--privkey", required=False,
                          help="SNMPv3 priv key", type=str, dest='privkey')
    snmpopts.add_argument("-a", "--authmode", required=False,
                          help="SNMPv3 auth mode", type=str, dest='authmode',
                          default='SHA',
                          choices=['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384',
                                   'SHA512'])
    snmpopts.add_argument("-x", "--privmode", required=False,
                          help="SNMPv3 privacy mode", type=str, dest='privmode',
                          default='AES',
                          choices=['DES', '3DES', 'AES', 'AES192', 'AES256'])
    args = parser.parse_args()
    return args


def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    if args.ipv6:
        transport_target = Udp6TransportTarget((args.host, args.port), timeout=args.timeout)
    else:
        transport_target = UdpTransportTarget((args.host, args.port), timeout=args.timeout)

    if args.v3mode == "authPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey, args.privkey,
                        authProtocol=authprot[args.authmode],
                        privProtocol=privprot[args.privmode]),
            transport_target,
            ContextData(),
            0, 50,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )
    elif args.v3mode == "authNoPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey,
                        authProtocol=authprot[args.authmode]),
            transport_target,
            ContextData(),
            0, 50,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            exit_plugin("3", ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print(f"{error_status.prettyPrint()} at "
                  f"{error_index and var_binds[int(error_index) - 1][0] or '?'}")
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

    # Get data via SNMP from SYNOLOGY-RAID-MIB
    #    SYNOLOGY-RAID-MIB::raidName
    #    SYNOLOGY-RAID-MIB::raidStatus
    #    SYNOLOGY-RAID-MIB::raidFreeSize
    #    SYNOLOGY-RAID-MIB::raidTotalSize
    raid_name = get_snmp_table('1.3.6.1.4.1.6574.3.1.1.2', args)
    raid_state = get_snmp_table('1.3.6.1.4.1.6574.3.1.1.3', args)
    raid_free = get_snmp_table('1.3.6.1.4.1.6574.3.1.1.4', args)
    raid_size = get_snmp_table('1.3.6.1.4.1.6574.3.1.1.5', args)

    if len(raid_name) == 0 or len(raid_state) == 0 or len(raid_free) == 0 or \
       len(raid_size) == 0:
        # Check if we received data via SNMP, otherwise exit with state Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    # Extract OID identifier from OID
    for entry in chain(raid_name, raid_state, raid_free, raid_size):
        entry[0] = entry[0].strip().split(".")[-1:]
        entry[0] = "".join(map(str, entry[0]))
        entry[1] = entry[1].strip()

    # Create list with volume identifiers
    volumeids = []
    for i in raid_name:
        volumeids.append(i[0])

    # Set return code and generate output and perfdata strings
    returncode = "0"
    perfdata = ""
    output = ""

    for vol_id in volumeids:
        # loop through volume ids

        for entry in raid_name:
            # loop through list with volume names
            if str(entry[0]) == str(vol_id):
                vol_name = str(entry[1])

        for entry in raid_state:
            # loop through list with volume states
            if str(entry[0]) == str(vol_id):
                vol_state = str(entry[1])

        for entry in raid_free:
            # loop through list with free space per volume
            if str(entry[0]) == str(vol_id):
                vol_free = int(entry[1])

        for entry in raid_size:
            # loop through list with free space per volume
            if str(entry[0]) == str(vol_id):
                vol_size = int(entry[1])

        # Calculate used space and thresholds in byte
        vol_used = int(vol_size - vol_free)
        vol_warn = round(vol_size * (args.warn / 100))
        vol_crit = round(vol_size * (args.crit / 100))

        # Calculate used percentage
        if vol_size == 0 and vol_used == 0:
            # Prevent ZeroDivisionError when vol_size is 0
            vol_used_pct = 0.0
        else:
            vol_used_pct = round((vol_used / vol_size) * 100, 2)

        # Remove whitespaces from volume name for perfdata label
        label = str(vol_name.replace(" ", ""))

        if match("^Volume *", vol_name):
            # Volume, apply disk thresholds

            if vol_name not in args.ignore_utilization:
                # Evaluate against disk thresholds
                if vol_used >= vol_crit and vol_size != 0:
                    returncode = "2"
                if returncode != "2" and vol_used >= vol_warn and vol_size != 0:
                    returncode = "1"
            else:
                vol_warn = ''
                vol_crit = ''

            # Append to outpur and perfdata string
            perfdata += ''.join(["\'", label, "\'=", str(vol_used), "B;",
                                 str(vol_warn), ";", str(vol_crit), ";0;",
                                 str(vol_size), " "])
            output += ''.join([vol_name, ": ",
                               str(raid_state_dict[str(vol_state)]),
                               " (", str(vol_used_pct), "%) "])

        if match("^Storage Pool *", vol_name):
            # Storage Pool, do not apply disk thresholds and do not append
            # perfdata with "used"-metric
            output += ''.join([vol_name, ": ",
                               str(raid_state_dict[str(vol_state)]), " "])
        # Evaluate against volume state
        if int(vol_state) in states_crit:
            returncode = "2"
        if returncode != "2" and int(vol_state) in states_warn:
            returncode = "1"

    # Remove last comma from output string
    output = output.rstrip(', ')

    exit_plugin(returncode, output, perfdata)


if __name__ == "__main__":
    main()
