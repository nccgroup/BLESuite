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

    # read from handle 0x0a
    read_request = connection_manager.gatt_read_handle(connection, 0x0a)

    if read_request.has_error():
        print "Got error:", read_request.get_error_message()
    elif read_request.has_response():
        print "Got response:", read_request.response.data, "from handle", hex(read_request.handle)

    # write to handle 0x0b
    write_request = connection_manager.gatt_write_handle(connection, 0x0b, "test value")
    if write_request.has_error():
        print "Got error:", write_request.get_error_message()
    elif write_request.has_response():
        print "Got response:", write_request.response.data, "from handle", hex(write_request.handle)
