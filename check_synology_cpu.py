#!/bin/env python3
"""
###############################################################################
# check_synology_cpu.py
# Icinga/Nagios plugin that checks the CPU load on a Synology NAS station using
# the UCD-SNMP-MIB
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
import asyncio
from argparse import ArgumentParser
from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd, SnmpEngine, UsmUserData, \
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


def get_args():
    """ Parse input arguments """
    parser = ArgumentParser(
                 description="Icinga/Nagios plugin which checks the CPU \
                              load on a Synology NAS")
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
                            help="Memory warning threshold (in percent)",
                            type=float, dest='warn', default="80")
    thresholds.add_argument("-c", "--crit", required=False,
                            help="Memory critical threshold (in percent)",
                            type=float, dest='crit', default="90")
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


async def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    # Set up TransportTarget object
    if args.ipv6:
        transport_target = await Udp6TransportTarget.create((args.host, args.port), args.timeout)
    else:
        transport_target = await UdpTransportTarget.create((args.host, args.port), args.timeout)

    # Set up UsmUserData object
    if args.v3mode == "authPriv":
        usm_user_data = UsmUserData(
            args.user, args.authkey, args.privkey,
            authProtocol=authprot[args.authmode],
            privProtocol=privprot[args.privmode]
        )
    elif args.v3mode == "authNoPriv":
        usm_user_data = UsmUserData(
            args.user, args.authkey,
            authProtocol=authprot[args.authmode]
        )
    else:
        # Should never occur - prevent pylint "possibly-used-before-assignment"
        usm_user_data = None

    snmp_engine = SnmpEngine()

    objects = bulk_walk_cmd(
        snmp_engine,
        usm_user_data,
        transport_target,
        ContextData(),
        0, 50,
        ObjectType(ObjectIdentity(table_oid)),
        lexicographicMode=False,
        lookupMib=False
    )

    iterator = [item async for item in objects]
    for error_indication, error_status, error_index, var_binds in iterator:

        if error_indication:
            # Exit if error occured during SNMP query
            exit_plugin(3, ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print(f"{error_status.prettyPrint()} at "
                  f"{error_index and var_binds[int(error_index) - 1][0] or '?'}")
        else:
            # loop over returned OIDs and append to table
            for oid_element in var_binds:
                table.append([str(oid_element[0]), str(oid_element[1])])

    snmp_engine.close_dispatcher()

    # return list with all OIDs/values from snmp table
    return table


def exit_plugin(returncode: int, output: str, perfdata: str = ""):
    """ Check status and exit accordingly """

    # Only append perfdata if it is set - otherwise the pipe character ends up in the output
    if perfdata == "":
        returnstring: str = f'{output}'
    else:
        returnstring: str = f'{output} | {perfdata}'

    if returncode == 3:
        print(f"UNKNOWN - {returnstring}")
        sys.exit(3)
    elif returncode == 2:
        print(f"CRITICAL - {returnstring}")
        sys.exit(2)
    elif returncode == 1:
        print(f"WARNING - {returnstring}")
        sys.exit(1)
    elif returncode == 0:
        print(f"OK - {returnstring}")
        sys.exit(0)


async def main():
    """ Main program code """

    # Get Arguments
    args = get_args()

    # Get CPU load from UCD-SNMP-MIB
    #    UCD-SNMP-MIB::ssCpuUser
    #    UCD-SNMP-MIB::ssCpuSystem
    #    UCD-SNMP-MIB::ssCpuIdle
    cpuload_data = await get_snmp_table('1.3.6.1.4.1.2021.11', args)

    if len(cpuload_data) == 0:
        # Check if we received data via SNMP, otherwise exit with state Unknown
        exit_plugin(3, "No data returned via SNMP", "NULL")

    for i in cpuload_data:
        # Extract values from returned table
        if str(i[0]) == '1.3.6.1.4.1.2021.11.9.0':
            cpuload_user = int(i[1])
        if str(i[0]) == '1.3.6.1.4.1.2021.11.10.0':
            cpuload_system = int(i[1])
        if str(i[0]) == '1.3.6.1.4.1.2021.11.11.0':
            cpuload_idle = int(i[1])

    # Calculate combinded CPU usage (System + User)
    cpuload_combined = int(cpuload_user + cpuload_system)  # pylint: disable=used-before-assignment

    # Construct output string
    output = ''.join(["System: ", str(cpuload_system), "%, User: ",
                      str(cpuload_user), "%, Idle: ",
                      str(cpuload_idle), "% "])  # pylint: disable=used-before-assignment

    # Construct perfdata string
    perfdata = ''.join(["\'system\'=", str(cpuload_system), "%;",
                        str(args.warn), ";", str(args.crit), ";0;100 ",
                        "\'user\'=", str(cpuload_user), "%;", str(args.warn),
                        ";", str(args.crit), ";0;100 ", "\'idle\'=",
                        str(cpuload_idle), "%;;;;"])

    # Evaluate against disk thresholds
    returncode = 0
    if cpuload_combined >= int(args.warn):
        returncode = 1
    if cpuload_combined >= int(args.crit):
        returncode = 2

    exit_plugin(returncode, output, perfdata)


if __name__ == "__main__":
    asyncio.run(main())
