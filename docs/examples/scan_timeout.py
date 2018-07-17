from blesuite.connection_manager import BLEConnectionManager

adapter = 0
role = 'central'
timeout_seconds = 10

with BLEConnectionManager(adapter, role) as connection_manager:

    # Retrieve list of discovered devices with GAP data
    discovered_devices = connection_manager.scan(timeout_seconds)

    readable_discovered_devices = {}
    # Decode GAP data into readable values
    for i in discovered_devices.keys():
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

    print readable_discovered_devices
