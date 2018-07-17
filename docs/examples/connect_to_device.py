from blesuite.connection_manager import BLEConnectionManager

adapter = 0
role = 'central'

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    success = connection_manager.connect(connection)

    if not success:
        print "Failed to connected to target device"
    else:
        print "Connected!"
