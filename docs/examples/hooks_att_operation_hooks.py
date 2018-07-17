from blesuite.connection_manager import BLEConnectionManager
from blesuite.event_handler import ATTEventHook
from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Read_Response, ATT_Error_Response
import gevent
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

adapter = 0
role = 'peripheral'


class MyCustomATTEventHandler(ATTEventHook):
    # override
    def att_write_hook(self, gatt_handle, data):
        write_value_to_attribute = True
        log.debug("ATT write hook triggered. Write value to attribute: %s value: %s" % (hex(gatt_handle), data))

        print "Received value:", data
        # replace data peer is attempting to write with string below
        data = "Intercepted write value"

        print "New write value is:", data

        return (write_value_to_attribute, gatt_handle, data)
    # Only enable one of these hooks at a time, otherwise the functionality will clash and prevent you from
    # seeing the effects of both.
    '''
    def att_response_hook(self, received_packet, our_response_packet):
        send_packet = True
        log.debug("ATT response hook triggered. Received packet: %s Send packet: %s packet: %s" % (received_packet, send_packet, our_response_packet))

        # If we receive an ATT Write Request and that results in some error, instead of sending the error packet,
        # send a valid ATT Write Response to trick the peer device.
        if ATT_Read_Request in received_packet and ATT_Error_Response in our_response_packet:
            our_response_packet = ATT_Read_Response("Intercepted!")

        return (send_packet, our_response_packet)
    '''


# initialize event handler
event_handler = MyCustomATTEventHandler()

with BLEConnectionManager(adapter, role, att_operation_event_hook=event_handler) as connection_manager:
    # Generate BLEDevice
    ble_device = BLEDevice()

    # Add Services and Characteristics to BLEDevice
    service1 = ble_device.add_service(0x01, 0x06, "2124")
    characteristic1 = service1.add_characteristic(0x03, 0x02, "2124",
                                                  Permissions.READ | Permissions.WRITE,
                                                  "testValue1",
                                                  characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                                                  characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN
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

    # alternate method: set event handler
    connection_manager.set_att_operation_hook(event_handler)

    # begin advertising
    connection_manager.start_advertising()

    # continually run server without blocking packet processing
    while True:
        gevent.sleep(1)
