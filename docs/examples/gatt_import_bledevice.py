from blesuite.connection_manager import BLEConnectionManager
from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils

with BLEConnectionManager(0, "peripheral") as connection_manager:
    # Generate BLEDevice
    ble_device = BLEDevice()

    # Add Services and Characteristics to BLEDevice with pre-defined ATT handles and UUIDs

    # Service start handle, end handle, and UUID
    service1 = ble_device.add_service(0x01, 0x06, "2124")

    # Add characteristic with value handle, handle, UUID, GATT permissions, and value
    characteristic1 = service1.add_characteristic(0x03, 0x02, "2124",
                                                  Permissions.READ | Permissions.WRITE,
                                                  "testValue1")
    # Add user descriptor with handle, and name
    characteristic1.add_user_description_descriptor(0x04,
                                                    "Characteristic 1")

    # Add service include with handle, include service handle, included service end handle,
    # and included service UUID
    service1.add_include(0x05, 0x07, 0x0c, "000AA000-0BB0-10C0-80A0-00805F9B34FB")

    service2 = ble_device.add_service(0x07, 0x0c, "000AA000-0BB0-10C0-80A0-00805F9B34FB")

    # Adding characteristic, but this time adding custom ATT permissions that require various security modes
    # for read and write.
    characteristic2 = service2.add_characteristic(0x09, 0x08, "2125",
                                                  Permissions.READ | Permissions.WRITE | Permissions.NOTIFY,
                                                  "newTestValue",
                                                  characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                                  characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION)
    characteristic2.add_user_description_descriptor(0x0a, "Characteristic2")
    characteristic2.add_client_characteristic_configuration_descriptor(0x0b)

    # Generate GATT server on host using BLEDevice information.
    # 2nd param (True) tells the GATT import process to use attribute handles specified in the BLEDevice rather
    # than sequentially assigning them as attributes are added to the server
    connection_manager.initialize_gatt_server_from_ble_device(ble_device, True)

    # Retrieve GATT server
    gatt_server = connection_manager.get_gatt_server()

    # Print GATT server for demonstration purposes
    gatt_server.debug_print_db()