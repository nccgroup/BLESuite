from blesuite.connection_manager import BLEConnectionManager
import json

adapter = 0
role = 'central'

io_cap = 0x03
oob = 0x00
mitm = 0x00
bond = 0x01
lesc = 0x00
keypress = 0x00
ct2 = 0x01
rfu = 0x00
max_key_size = 16
initiator_key_distribution = 0x01
responder_key_distribution = 0x01

peer_device_address = "AA:BB:CC:DD:EE:FF"
peer_address_type = "public"

with BLEConnectionManager(adapter, role) as connection_manager:
    # Sets the default Security Manager pairing properties for all established connections
    connection_manager.set_security_manager_protocol_default_pairing_parameters(io_cap, oob, mitm, bond, lesc,
                                                                                keypress, ct2, rfu, max_key_size,
                                                                                initiator_key_distribution,
                                                                                responder_key_distribution)

    # initialize BLEConnection object
    connection = connection_manager.init_connection(peer_device_address, peer_address_type)

    # create connection
    connection_manager.connect(connection)

    pairing_timeout_seconds = 15

    # initiate pairing (sends pairing request, the stack will handle the rest of the procedure)
    # this call is blocking
    result = connection_manager.pair(connection, pairing_timeout_seconds)

    if result:
        print "Pairing successful!"
        # export keys for later use
        ltk_db = connection_manager.export_security_manager_long_term_key_database_for_storage()

        for ltk_entry in ltk_db:
            print "Address: %s addr_type: %d LTK: %s Ediv: %s Rand: %s IRK: %s CSRK: %s security mode: %s security level: %s" % (
                ltk_entry['address'], ltk_entry['address_type'], ltk_entry['ltk'], ltk_entry['ediv'], ltk_entry['rand'],
                ltk_entry['irk'],
                ltk_entry['csrk'], ltk_entry['security_mode'], ltk_entry['security_level']
            )
        # Write JSON to file
        ltk_json_output = json.dumps(ltk_db, indent=4)
        f = open("long_term_key_database_after_pairing.json", "w")
        f.write(ltk_json_output)
        f.close()
    else:
        print "Something went wrong during pairing"
