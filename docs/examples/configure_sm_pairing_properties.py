from blesuite.connection_manager import BLEConnectionManager

adapter = 0
role = 'central'
io_cap = 0x03
oob = 0x00
mitm = 0x01
bond = 0x01
lesc = 0x01
keypress = 0x00
ct2 = 0x01
rfu = 0x00
max_key_size = 16
initiator_key_distribution = 0x01
responder_key_distribution = 0x01

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # Get default Security Manager pairing properties to see baseline
    print connection_manager.get_security_manager_protocol_default_pairing_parameters()

    # Sets the default Security Manager pairing properties for all established connections
    connection_manager.set_security_manager_protocol_default_pairing_parameters(io_cap, oob, mitm, bond, lesc,
                                                                                keypress, ct2, rfu, max_key_size,
                                                                                initiator_key_distribution,
                                                                                responder_key_distribution)

    print connection_manager.get_security_manager_protocol_default_pairing_parameters()

    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    connection_manager.connect(connection)

    # modify pairing parameters for just this connection
    connection_manager.set_security_manager_protocol_pairing_parameters_for_connection(connection, io_cap=0x02)

    # show the changes for the security manager made for the connection made in the last step
    print connection_manager.get_security_manager_protocol_pairing_parameters_for_connection(connection)

