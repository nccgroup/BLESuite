from blesuite.connection_manager import BLEConnectionManager
from blesuite.event_handler import BTEventHandler
import logging
import os

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

adapter = 0
role = 'central'

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"


class MyCustomBTEventHandler(BTEventHandler):
    # override on_att_event function
    def on_att_event(self, connection_handle, data):
        from blesuite.pybt.att import ATT_PDU_OPCODE_BY_NAME
        log.debug("ATT Event Connection Handle: %s Data: %s" % (connection_handle, data))

        ble_connection = self.connection_manager.get_bleconnection_from_connection_handle(connection_handle)
        if ble_connection is not None:
            if data.opcode == ATT_PDU_OPCODE_BY_NAME["Handle Value Notification"]:
                # Device should not expect confirmation as per the spec
                log.debug("Packet was notification from handle %s" % data.handle)

            if data.opcode == ATT_PDU_OPCODE_BY_NAME["Handle Value Indication"]:
                log.debug("Packet was indication from handle %s, sending malformed data" % data.handle)
                self.connection_manager.att_send_raw(ble_connection, os.urandom(16))
        return


with BLEConnectionManager(adapter, role) as connection_manager:
    # initialize event handler
    event_handler = MyCustomBTEventHandler(connection_manager)

    # set event handler
    connection_manager.set_event_handler(event_handler)

    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # set event handler
    connection_manager.set_event_handler(event_handler)

    # create connection
    connection_manager.connect(connection)
