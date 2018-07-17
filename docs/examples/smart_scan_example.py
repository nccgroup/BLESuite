from blesuite.connection_manager import BLEConnectionManager

adapter = 0
role = 'central'

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    connection_manager.connect(connection)

    # Run a smart scan on the target device. This will generate a new BLEDevice object, unless
    # one is supplied in the smart_scan function call. Additionally, we set attempt_desc_read
    # to False in order to increase the scan speed. By setting it to true, the procedure will
    # attempt to read from every identified descriptor, regardless of the GATT properties set by
    # the peer BLE device (which may not actually reflect the ATT database permissions)
    ble_device = connection_manager.smart_scan(connection, attempt_desc_read=False)

    ble_device.print_device_structure()
