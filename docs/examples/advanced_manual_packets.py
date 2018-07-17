from blesuite.connection_manager import BLEConnectionManager
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Hdr, L2CAP_Hdr
import os

adapter = 0
role = 'central'

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    connection_manager.connect(connection)

    # Send a raw ATT body packet, which will encapsulate the packet with the correct L2CAP header and HCI headers
    att_packet = ATT_Hdr() / ATT_Read_Request(gatt_handle=0x0a)

    connection_manager.att_send_raw(connection, att_packet)

    # Same ATT packet as above, but this time we are manually constructing L2CAP Hdr
    l2cap_packet = L2CAP_Hdr(cid=4) / att_packet

    connection_manager.l2cap_send_raw(connection, l2cap_packet)

    # Dumb fuzz test cases
    connection_manager.att_send_raw(connection, ATT_Hdr() / os.urandom(16))

    # Careful, this packet can cause your Bluetooth adapter to crash. Likely since the CID is unexpected and not
    # known how to be handled
    connection_manager.l2cap_send_raw(connection, L2CAP_Hdr(cid=int(os.urandom(1).encode('hex'), 16)) / os.urandom(16))
