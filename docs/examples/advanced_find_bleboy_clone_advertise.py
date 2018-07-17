from blesuite.connection_manager import BLEConnectionManager
import blesuite.utils.gap_utils as gap_utils
import bdaddr
import gevent
import time

adapter = 0
timeout_seconds = 10
target_device_name = "BLEBoy"

target_address = None
target_address_type = None
target_device_bledevice = None
successful_scan = False

with BLEConnectionManager(adapter, 'central') as connection_manager:

    # enable scanning
    connection_manager.start_scan()

    # Take start time
    start_time = time.time()

    # initialize dictionary of discovered devices, readable format.
    readable_discovered_devices = {}
    device_found = False
    while True:
        # timeout condition
        current_time = time.time()
        if current_time - start_time >= timeout_seconds:
            break
        # get devices
        discovered_devices = connection_manager.get_discovered_devices()

        # Decode GAP data into readable values
        for i in discovered_devices.keys():
            if i not in readable_discovered_devices.keys():
                readable_discovered_devices[i] = {}
            if discovered_devices[i][0] == 0:
                readable_discovered_devices[i]['address_type'] = 'public'
            else:
                readable_discovered_devices[i]['address_type'] = 'random'
            for h, j in enumerate(discovered_devices[i][1]):
                gap = connection_manager.decode_gap_data(str(discovered_devices[i][1][h]))
                info = connection_manager.generate_gap_data_dict(gap)

                for info_key in info.keys():
                    readable_discovered_devices[i][info_key] = info[info_key]

        # check if target device name found
        for device in readable_discovered_devices.keys():
            if ('Complete Local Name' in readable_discovered_devices[device].keys() and
               readable_discovered_devices[device]['Complete Local Name'] == target_device_name):
                print "Found BLEBoy at address: %s with type: %s" % (device,
                                                                     readable_discovered_devices[device]['address_type'])
                device_found = True
                target_address = device
                target_address_type = readable_discovered_devices[device]['address_type']

        if device_found:
            break

        # if device not found, wait 1 second for additional scanning
        gevent.sleep(1)

    # Timeout reached our device found, stop scanning
    connection_manager.stop_scan()
    if device_found:
        print "Smart scanning device for clone"
        connection = connection_manager.init_connection(target_address, target_address_type)
        connection_manager.connect(connection)
        target_device_bledevice = connection_manager.smart_scan(connection)
        successful_scan = True
        print "Done smart scanning"

if successful_scan:

    with BLEConnectionManager(adapter, "peripheral") as connection_manager:

        # spoofing address
        ret = bdaddr.bdaddr(("hci" + str(adapter)), target_address)
        if ret == -1:
            raise ValueError('Spoofing failed. Your device may not be supported.')
        else:
            print "Address spoofed"

        # Using distinguishable name for demonstration purposes
        local_name = "BLEBoy-Clone"
        complete_name = "BLEBoy-Clone"

        # generate integer representation of advertisement data flags using helper function
        flag_int = gap_utils.generate_ad_flag_value(le_general_discoverable=True,
                                                    bredr_not_supported=True)

        # generate advertisement data entry using helper function
        flag_entry = gap_utils.advertisement_data_entry_builder("Flags", chr(flag_int))

        # generate advertisement data entry for shortened local name using helper function
        short_local_name_entry = gap_utils.advertisement_data_entry_builder("Shortened Local Name", complete_name)

        # generate advertisement data entry for complete local name using helper function
        complete_local_name_entry = gap_utils.advertisement_data_entry_builder("Complete Local Name", local_name)

        # build advertisement data list
        ad_entries_list = [flag_entry, short_local_name_entry, complete_local_name_entry]

        # build finalized advertisement data from list
        ad_entries = gap_utils.advertisement_data_complete_builder(ad_entries_list)

        # Set advertising data sent in advertising packets
        connection_manager.set_advertising_data(ad_entries)

        # Set data sent in response to an inquiry packet
        connection_manager.set_scan_response_data(ad_entries)

        # Set advertising parameters - advertising type, channel map, interval_min, interval_max,
        # destination address (only used if using directed advertising, just set to 00:00:00:00:00:00),
        # destination address type (only used if using directed advertising, set to 0x00 otherwise which is public)
        connection_manager.set_advertising_parameters(gap_utils.gap.GAP_ADV_TYPES['ADV_IND'], 7, 0x0020, 0x00a0,
                                                      "00:00:00:00:00:00", 0x00)

        connection_manager.initialize_gatt_server_from_ble_device(target_device_bledevice, True)

        # Retrieve GATT server
        gatt_server = connection_manager.get_gatt_server()

        # Print GATT server for demonstration purposes
        gatt_server.debug_print_db()

        connection_manager.start_advertising()

        print "Advertising Started"

        timeout_seconds = 15
        start = time.time()
        while True:
            current = time.time()
            if current - start >= timeout_seconds:
                break
            gevent.sleep(1)

        connection_manager.stop_advertising()

else:
    print "Scan unsuccessful, cloning failed."
