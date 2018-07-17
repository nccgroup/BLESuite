from blesuite.connection_manager import BLEConnectionManager
from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils
import blesuite.utils.gap_utils as gap_utils
import json
import gevent

adapter = 0
role = 'peripheral'

with BLEConnectionManager(adapter, role) as connection_manager:
    '''
    Generate a GATT server for interaction by a Central device
    '''
    # Generate BLEDevice
    ble_device = BLEDevice()

    # Add Services and Characteristics to BLEDevice
    service1 = ble_device.add_service(0x01, 0x06, "2124")
    characteristic1 = service1.add_characteristic(0x03, 0x02, "2124",
                                                  Permissions.READ | Permissions.WRITE,
                                                  "testValue1",
                                                  characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION,
                                                  characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION
                                                  )
    characteristic1.add_user_description_descriptor(0x04,
                                                    "Characteristic 1")

    # Generate GATT server on host using BLEDevice information.
    # 2nd param (True) tells the GATT import process to use attribute handles specified in the BLEDevice rather
    # than sequentially assigning them as attributes are added to the server
    connection_manager.initialize_gatt_server_from_ble_device(ble_device, True)

    # Retrieve GATT server
    gatt_server = connection_manager.get_gatt_server()

    # Print GATT server for demonstration purposes
    gatt_server.debug_print_db()

    # Configure advertising name
    local_name = "Name Foo2"
    complete_name = "Foo4"

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
    local_name = "Name Foo2"
    complete_name = "Foo4"

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

    # Begin advertising and block until we are connected to a Central device (or until timeout is reached)
    result, ble_connection = connection_manager.advertise_and_wait_for_connection()

    if result:
        print "BLE connection established"
        # Wait for pairing process to complete after being initiated by the Central device
        while True:
            if (connection_manager.is_connection_encrypted(ble_connection) and
               not connection_manager.is_pairing_in_progress(ble_connection)):
                break
            # Sleep for a second, using gevent to prevent blocking packet routing routine
            gevent.sleep(1)
        print "Pairing process complete"
        # export ltk database from security manager
        ltk_db = connection_manager.export_security_manager_long_term_key_database_for_storage()

        for ltk_entry in ltk_db:
            print "Address: %s addr_type: %d LTK: %s Ediv: %s Rand: %s IRK: %s CSRK: %s security mode: %s security level: %s" % (
                ltk_entry['address'], ltk_entry['address_type'], ltk_entry['ltk'], ltk_entry['ediv'], ltk_entry['rand'], ltk_entry['irk'],
                ltk_entry['csrk'], ltk_entry['security_mode'], ltk_entry['security_level']
            )
        # Write JSON to file
        ltk_json_output = json.dumps(ltk_db, indent=4)
        f = open("long_term_key_database.json", "w")
        f.write(ltk_json_output)
        f.close()

    else:
        print "Failed to get BLE Connection"
