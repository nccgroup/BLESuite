from blesuite.connection_manager import BLEConnectionManager
from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils
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

    # Begin advertising and block until we are connected to a Central device (or until timeout is reached)
    result, ble_connection = connection_manager.advertise_and_wait_for_connection()

    if result:
        print "We are connected!"

        # After peer connects, quickly scan their gatt server and see what info is there
        ble_device = connection_manager.smart_scan(ble_connection, look_for_device_info=False, timeout=5)

        ble_device.print_device_structure()

        # assuming we know a handle by this point, we can then start reading data
        # read from handle 0x0a
        read_request = connection_manager.gatt_read_handle(ble_connection, 0x0a)

        if read_request.has_error():
            print "Got error:", read_request.get_error_message()
        elif read_request.has_response():
            print "Got response:", read_request.response.data, "from handle", hex(read_request.handle)
