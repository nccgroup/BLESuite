from blesuite.connection_manager import BLEConnectionManager
import gevent
import time

adapter = 0
role = 'central'
timeout_seconds = 10

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    connection_manager.connect(connection)

    # read from handle 0x0a
    read_request = connection_manager.gatt_read_handle_async(connection, 0x0a)

    # write to handle 0x0b
    write_request = connection_manager.gatt_write_handle_async(connection, 0x0b, "test value")

    start_time = time.time()
    # wait for read response with requested data. Write response is less important for us to monitor unless we want to
    # know the success state
    while not read_request.has_response():
        # check for GATTError
        if read_request.has_error():
            break
        # check if timeout reached
        current_time = time.time()
        if current_time - start_time >= timeout_seconds:
            break

        gevent.sleep(1)

    if read_request.has_response():
        print "Got response:", read_request.response.data, "from handle", hex(read_request.handle)
    elif read_request.has_error():
        print "Got error:", read_request.get_error_message()
    else:
        print "Our custom timeout was reached"
    # Not printing write request response. Either an error or a confirmation.
