from blesuite.connection_manager import BLEConnectionManager
import blesuite.utils.gap_utils as gap_utils
import gevent
import time


with BLEConnectionManager(0, "peripheral") as connection_manager:
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

    connection_manager.start_advertising()

    timeout_seconds = 5
    start = time.time()
    while True:
        current = time.time()
        if current - start >= timeout_seconds:
            break
        gevent.sleep(1)

    connection_manager.stop_advertising()
