from blesuite.connection_manager import BLEConnectionManager
import gevent
import time

adapter = 0
role = 'central'
timeout_seconds = 10
target_device_name = "BLEBoy"

with BLEConnectionManager(adapter, role) as connection_manager:

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
                break

        if device_found:
            break

        # if device not found, wait 1 second for additional scanning
        gevent.sleep(1)

    # Timeout reached our device found, stop scanning
    connection_manager.stop_scan()
