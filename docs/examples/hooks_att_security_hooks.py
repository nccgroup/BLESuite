from blesuite.connection_manager import BLEConnectionManager
from blesuite.event_handler import ATTSecurityHook
from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils
import gevent
import logging

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

adapter = 0
role = 'peripheral'

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"


class MyCustomATTSecurityHandler(ATTSecurityHook):

    def att_authorization_check_hook(self, att_opcode, uuid, att_property, att_read_permission, att_write_permission,
                                     connection_permission, authorization_required):

        if authorization_required:
            answer = raw_input("Press y to authorize access to attribute %s with operation %d, else press n followed by enter" % (uuid, att_opcode))
            if answer == "y":
                check_passed = True
            else:
                check_passed = False
            log.debug("ATT Authorization check invoked. Operation: %d Target Attribute: %s ATT Property: %d "
                      "ATT Read Security Mode: %d ATT Read Security Level: %d "
                      "ATT Read Security Mode: %d ATT Read Security Level: %d "
                      "Connection Security Mode: %d Connection Security Level: %d "
                      "Attribute requires authorization: %d" %
                      (att_opcode, uuid, att_property, att_read_permission.security_mode, att_read_permission.security_level,
                       att_write_permission.security_mode, att_write_permission.security_level,
                       connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level(),
                       authorization_required))
        else:
            check_passed = True
        return check_passed
    '''
    def att_authentication_check_hook(self, att_authentication_check_result,
                                      att_opcode, uuid, att_property, att_read_permission,
                                      att_write_permission, connection_permission):
        check_passed = att_authentication_check_result
        log.debug("ATT Authentication check invoked. Result: %d"
                  "Operation: %d Target Attribute: %s ATT Property: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "Connection Security Mode: %d Connection Security Level: %d" %
                  (att_authentication_check_result,
                   att_opcode, uuid, att_property, att_read_permission.security_mode, att_read_permission.security_level,
                   att_write_permission.security_mode, att_write_permission.security_level,
                   connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level()))
        # always throw an authentication error to see how the peer device responds
        return False
    '''


# initialize event handler
event_handler = MyCustomATTSecurityHandler()

with BLEConnectionManager(adapter, role, att_security_event_hook=event_handler) as connection_manager:
    # Generate BLEDevice
    ble_device = BLEDevice()

    # Add Services and Characteristics to BLEDevice
    service1 = ble_device.add_service(0x01, 0x06, "2124")

    #Add characteristic with open permissions, but requires authorization, thus triggering our event handler
    characteristic1 = service1.add_characteristic(0x03, 0x02, "2124",
                                                  Permissions.READ | Permissions.WRITE,
                                                  "testValue1",
                                                  characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                                  characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                                  characteristic_value_attribute_require_authorization=True
                                                  )
    characteristic1.add_user_description_descriptor(0x04,
                                                    "Characteristic 1")

    # Add service 2
    service2 = ble_device.add_service(0x07, 0x0c, "000AA000-0BB0-10C0-80A0-00805F9B34FB")

    # Add characteristic2 to service 2, this time specifying GATT propertries: read, write, and notify. As well
    # as setting ATT attribute permissions for the characterisitic value descriptor attribute. It also requires
    # pairing with a method that provides security mode 1, level 3
    characteristic2 = service2.add_characteristic(0x09, 0x08, "2125",
                                                  Permissions.READ | Permissions.WRITE | Permissions.NOTIFY,
                                                  "newTestValue",
                                                  characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_WITH_AUTHENTICATION,
                                                  characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_WITH_AUTHENTICATION)

    # Add user descriptor to characteristic
    characteristic2.add_user_description_descriptor(0x0a, "Characteristic2")

    # Generate GATT server on host using BLEDevice information.
    # 2nd param (True) tells the GATT import process to use attribute handles specified in the BLEDevice rather
    # than sequentially assigning them as attributes are added to the server
    connection_manager.initialize_gatt_server_from_ble_device(ble_device, True)

    # Retrieve GATT server
    gatt_server = connection_manager.get_gatt_server()

    # Print GATT server for demonstration purposes
    gatt_server.debug_print_db()

    # alternate method: set event handler
    connection_manager.set_att_security_hook(event_handler)

    # begin advertising
    connection_manager.start_advertising()

    # continually run server without blocking packet processing
    while True:
        gevent.sleep(1)