import argparse
from blesuite.connection_manager import BLEConnectionManager
from blesuite_wrapper import ble_service_read, ble_service_read_async, ble_service_write, \
    ble_handle_subscribe, ble_service_scan, ble_service_write_async, ble_run_smart_scan
from blesuite import utils
from blesuite.utils.print_helper import print_data_and_hex
from blesuite.utils import validators
import logging


__version__ = "2.0"
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def parse_command():
    """
    Creates parser and parses command line tool call.

    :return: parsed arguments
    """
    global __version__
    #Dictionary of available commands. Place new commands here
    cmd_choices = {'scan': "Scan for BTLE devices",
                  'smartscan': "Scan specified BTLE device for device information, services, characteristics "
                               "(including associated descriptors). Note: This scan takes longer than the service scan",
                  'servicescan': 'Scan specified address for all services, characteristics, and descriptors. ',
                  'read': "Read value from specified device and handle",
                  'write': "Write value to specific handle on a device. Specify the --data or --files options"
                              "to set the payload data. Only data or file data can be specified, not both"
                              "(data submitted using the data flag takes precedence over data in files).",
                  'subscribe': "Write specified value (0000,0100,0200,0300) to chosen handle and initiate listener.",
                  'spoof': 'Modify your Bluetooth adapter\'s BT_ADDR. Use --address to set the address. Some chipsets'
                           ' may not be supported.'}

    address_type_choices = ['public', 'random']

    parser = argparse.ArgumentParser(prog="blesuite",
                                     description='Bluetooh Low Energy (BTLE) tool set for communicating and '
                                                 'testing BTLE devices on the application layer.')  # ,
    # formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', metavar='command', type=str, nargs=1,
                        action='store', choices=cmd_choices.keys(),
                        help='BLESuite command you would like to execute.' +
                             'The following are the currently supported commands:\n' +
                             '\n'.join(['\033[1m{}\033[0m: {}'.format(k, v) for k, v in cmd_choices.iteritems()]))

    parser.add_argument('--async', action='store_true', help='\033[1m<read, write>\033[0m '
                                                             'Enable asynchronous writing/reading. Any output'
                                                             'will be displayed when received. This prevents'
                                                             'blocking.')
    
    parser.add_argument('--skip-device-info-query', action='store_true', help='\033[1m<smartscan>\033[0m '
                                                             'When scanning a device, specify this flag'
                                                             'to force smartscan to skip querying the device'
                                                             'for common information such as device name. This'
                                                             'is helpful when devices do not implement these services.')

    parser.add_argument('--smart-read', action='store_true', help='\033[1m<smartscan>\033[0m '
                                                                   'When scanning a device, specify this flag'
                                                                   'to force smartscan to attempt to read'
                                                                   'from each discovered characteristic descriptor.'
                                                                   'Note: This will increase scan time to handle'
                                                                   'each read operation.')
    parser.add_argument('-m', '--mode', metavar='mode', default=[1],
                        type=int, nargs=1, required=False,
                        action='store', help='\033[1m<subscribe>\033[0m '
                                                             'Selects which configuration to set'
                                                            'for a characteristic configuration descriptor.'
                                                            '0=off,1=notifications,2=indications,'
                                                            '3=notifications and inidications')
    parser.add_argument('--timeout', metavar='timeout', default=[5],
                        type=int, nargs=1,
                        required=False, action='store',
                        help='\033[1m<lescan, read, write>\033[0m '
                             'Timeout (in seconds) for attempting to retrieve data from a device '
                             '(ie reading from a descriptor handle). (Default: 5 seconds)')

    parser.add_argument('--subscribe-timeout', metavar='subscribe-timeout', default=[None],
                        type=int, nargs=1,
                        required=False, action='store',
                        help='\033[1m<subscribe>\033[0m '
                             'Time (in seconds) for attempting to retrieve data from a device '
                             'when listening for notifications or indications. (Default: Indefinite)')

    # Device for discovery service can be specified
    parser.add_argument('-i', '--adapter', metavar='adapter', default=[0],
                        type=int, nargs=1,
                        required=False, action='store',
                        help='\033[1m<all commands>\033[0m '
                             'Specify which Bluetooth adapter should be used. '
                             'These can be found by running (hcitool dev).')

    parser.add_argument('-d', '--address', metavar='address', type=validators.validate_bluetooth_address_cli, nargs=1,
                        required=False, action='store',
                        help='\033[1m<all commands>\033[0m '
                             'Bluetooth address (BD_ADDR) of the target Bluetooth device')

    parser.add_argument('-a', '--handles', metavar='handles', type=str, nargs="+",
                        required=False, action='store', default=[],
                        help='\033[1m<read, write>\033[0m '
                             'Hexadecimal handel list of characteristics to access (ex: 005a 006b). If '
                             'you want to access the value of a characteristic, use the handle_value '
                             'value from the service scan.')
    parser.add_argument('-u', '--uuids', metavar='uuids', type=str, nargs="+",
                        required=False, action='store', default=[],
                        help='\033[1m<read>\033[0m '
                             'UUID list of characteristics to access. If '
                             'you want to access the value of a characteristic, use the UUID '
                             'value from the service scan.')

    parser.add_argument('--data', metavar='data', type=str, nargs="+",
                        required=False, action='store', default=[],
                        help='\033[1m<write>\033[0m '
                             'Strings that you want to write to a handle (separated by spaces).')

    parser.add_argument('--files', metavar='files', type=str, nargs="+",
                        required=False, action='store', default=[],
                        help='\033[1m<write>\033[0m '
                             'Files that contain data to write to handle (separated by spaces)')

    parser.add_argument('--payload-delimiter', metavar='payload-delimiter', type=str, nargs=1,
                    required=False, action='store', default=["EOF"],
                    help='\033[1m<write>\033[0m '
                         'Specify a delimiter (string) to use when specifying data for BLE payloads.'
                         'For instance, if I want to send packets with payloads in a file separated'
                         'by a comma, supply \'--payload-delimiter ,\'. Supply EOF if you want the entire contents'
                         'of a file sent. (Default: EOF)')


    parser.add_argument("-t", '--address-type', metavar='address-type', type=str, nargs=1,
                        required=False, action='store', default=['public'], choices=address_type_choices,
                        help='\033[1m<all commands>\033[0m '
                        'Type of BLE address you want to connect to [public | random].')

    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

    parser.add_argument('--debug', action='store_true', help='\033[1m<all commands>\033[0m '
                                                             'Enable logging for debug statements.')

    return parser.parse_args()


def process_args(args):
    """
    Process command line tool arguments parsed by argparse
    and call appropriate bleSuite functions.

    :param args: parser.parse_args()
    :return:
    """

    command = args.command[0]
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    timeout = args.timeout[0] * 1000 # convert seconds to ms

    if command == 'spoof':
        import bdaddr
        if args.address[0] == "":
            print "Please specify an address to spoof."
        else:
            logger.debug("About to spoof to address %s for adapter %s" % (args.address[0], args.adapter[0]))
            ret = bdaddr.bdaddr(("hci"+str(args.adapter[0])), args.address[0])
            if ret == -1:
                raise ValueError('Spoofing failed. Your device may not be supported.')

    if command == 'scan':
        print "BTLE Scan beginning"
        with BLEConnectionManager(args.adapter[0], 'central') as connection_manager:
            discovered = connection_manager.scan(timeout)

            print "Discovered:"
            for i in discovered.keys():
                print "\t", i, "(public)" if discovered[i][0] == 0 else "(random)"
                for h, j in enumerate(discovered[i][1]):
                    gap = connection_manager.decode_gap_data(str(discovered[i][1][h]))
                    info = connection_manager.generate_gap_data_dict(gap)
                    for k in info.keys():
                        print "\t\t", k + ":"
                        print "\t\t\t", info[k]

    if command == 'smartscan':
        print "BTLE Smart Scan beginning"
        device = ble_run_smart_scan(args.address[0], args.adapter[0],
                                    args.address_type[0], skip_device_info_query=args.skip_device_info_query,
                                    attempt_read=args.smart_read,
                                    timeout=timeout)

    if command == 'servicescan':
        print "BTLE Scanning Services"
        ble_service_scan(args.address[0], args.adapter[0],
                         args.address_type[0])

    if command == 'read':
        if len(args.handles) <= 0 and len(args.uuids) <= 0:
            print "ERROR: No handles or UUIDs supplied for read operation."
            return
        print "Reading value from handle or UUID"
        if args.async:
            uuidData, handleData = ble_service_read_async(args.address[0], args.adapter[0],
                                                          args.address_type[0],
                                                          args.handles, args.uuids,
                                                          timeout=timeout)
            for dataTuple in handleData:
                print "\nHandle:", "0x" + dataTuple[0]
                print_data_and_hex(dataTuple[1], False)
                '''
                if isinstance(dataTuple[1][0], str):
                    utils.print_helper.print_data_and_hex(dataTuple[1], False)
                else:
                    utils.print_helper.print_data_and_hex(dataTuple[1][1], False)'''
            for dataTuple in uuidData:
                print "\nUUID:", dataTuple[0]
                print_data_and_hex(dataTuple[1], False)
                '''
                if isinstance(dataTuple[1][0], str):
                    utils.print_helper.print_data_and_hex(dataTuple[1], False)
                else:
                    utils.print_helper.print_data_and_hex(dataTuple[1][1].received(), True)'''
        else:
            uuidData, handleData = ble_service_read(args.address[0], args.adapter[0],
                                                    args.address_type[0],
                                                    args.handles, args.uuids, timeout=timeout)
            for dataTuple in handleData:
                print "\nHandle:", "0x" + dataTuple[0]
                print_data_and_hex(dataTuple[1], False)
            for dataTuple in uuidData:
                print "\nUUID:", dataTuple[0]
                print_data_and_hex(dataTuple[1], False)

    if command == 'write':
        if len(args.handles) <= 0:
            print "ERROR: No handles supplied for write operation. Note: Write operation does not support use of UUIDs."
            return
        print "Writing value to handle"
        if args.async:
            logger.debug("Async Write")
            if len(args.data) > 0:
                handleData = ble_service_write_async(args.address[0], args.adapter[0],
                                                     args.address_type[0],
                                                     args.handles, args.data,
                                                     timeout=timeout)
            elif args.payload_delimiter[0] == 'EOF':
                logger.debug("Payload Delimiter: EOF")
                dataSet = []
                for dataFile in args.files:
                    if dataFile is None:
                        continue
                    logger.debug("Reading file: %s", dataFile)
                    f = open(dataFile, 'r')
                    dataSet.append(f.read())
                    f.close()
                logger.debug("Sending data set: %s" % dataSet)
                handleData = ble_service_write_async(args.addr[0], args.adapter[0],
                                                     args.address_type[0],
                                                     args.handles, dataSet,
                                                     timeout=timeout)
                logger.debug("Received data: %s" % handleData)
                '''for dataTuple in handleData:
                    print "\nHandle:", "0x" + dataTuple[0]
                    utils.print_helper.print_data_and_hex(dataTuple[1], False)'''
            else:
                logger.debug("Payload Delimiter: %s", args.payload_delimiter[0])
                dataSet = []
                for dataFile in args.files:
                    if dataFile is None:
                        continue
                    f = open(dataFile, 'r')
                    data = f.read()
                    f.close()
                    data = data.split(args.payload_delimiter[0])
                    dataSet.extend(data)

                logger.debug("Sending dataSet: %s" % dataSet)

                handleData = ble_service_write_async(args.address[0], args.adapter[0],
                                                     args.address_type[0],
                                                     args.handles, dataSet,
                                                     timeout=timeout)
            for dataTuple in handleData:
                print "\nHandle:", "0x" + dataTuple[0]
                print "Input:"
                utils.print_helper.print_data_and_hex(dataTuple[2], False, prefix="\t")
                print "Output:"
                #if tuple[1][0] is a string, it means our cmdLineToolWrapper removed the GattResponse object
                #due to a timeout, else we grab the GattResponse and its response data
                if isinstance(dataTuple[1][0], str):
                    utils.print_helper.print_data_and_hex(dataTuple[1], False, prefix="\t")
                else:
                    utils.print_helper.print_data_and_hex(dataTuple[1][1].received(), False, prefix="\t")
        else:
            logger.debug("Sync Write")
            print args.data
            if len(args.data) > 0:
                handleData = ble_service_write(args.address[0], args.adapter[0],
                                               args.address_type[0],
                                               args.handles, args.data, timeout=timeout)

                '''for dataTuple in handleData:
                    print "\nHandle:", "0x" + dataTuple[0]
                    utils.print_helper.print_data_and_hex(dataTuple[1], False)'''

            elif args.payload_delimiter[0] == 'EOF':
                logger.debug("Payload Delimiter: EOF")
                dataSet = []
                for dataFile in args.files:
                    if dataFile is None:
                        continue
                    logger.debug("Reading file: %s", dataFile)
                    f = open(dataFile, 'r')
                    dataSet.append(f.read())
                    f.close()
                logger.debug("Sending data set: %s" % dataSet)
                handleData = ble_service_write(args.address[0], args.adapter[0],
                                               args.address_type[0],
                                               args.handles, dataSet, timeout=timeout)
                logger.debug("Received data: %s" % handleData)
                '''for dataTuple in handleData:
                    print "\nHandle:", "0x" + dataTuple[0]
                    utils.print_helper.print_data_and_hex(dataTuple[1], False)'''
            else:
                logger.debug("Payload Delimiter: %s", args.payload_delimiter[0])
                dataSet = []
                for dataFile in args.files:
                    if dataFile is None:
                        continue
                    f = open(dataFile, 'r')
                    data = f.read()
                    f.close()
                    data = data.split(args.payload_delimiter[0])
                    dataSet.extend(data)
                logger.debug("Sending dataSet: %s" % dataSet)
                handleData = ble_service_write(args.address[0], args.adapter[0],
                                               args.address_type[0],
                                               args.handles, dataSet, timeout=timeout)
            for dataTuple in handleData:
                print "\nHandle:", "0x" + dataTuple[0]
                print "Input:"
                print_data_and_hex([dataTuple[2]], False, prefix="\t")
                print "Output:"
                print_data_and_hex(dataTuple[1], False, prefix="\t")

    if command == 'subscribe':
        print "Subscribing to device"
        if args.subscribe_timeout[0] is not None:
            timeout = args.subscribe_timeout[0] * 1000
        else:
            timeout = None
        ble_handle_subscribe(args.address[0], args.handles, args.adapter[0],
                             args.address_type[0], args.mode[0], timeout)

    return


def main():
    """
    Main loop for BLESuite command line tool.

    :return:
    """
    args = parse_command()
    process_args(args)

    logger.debug("Args: %s" % args)


