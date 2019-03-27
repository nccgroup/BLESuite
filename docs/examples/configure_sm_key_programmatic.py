from blesuite.connection_manager import BLEConnectionManager

adapter = 0
role = 'central'
#address = 'AA:BB:CC:DD:EE:FF'
address_bytes = "AABBCCDDEEFF".decode('hex')
peer_address_type = 0 # public
ltk = "\xAB" * 16
ediv = 56007
rand = "\xCD" * 8
irk = None
csrk = None
security_mode = 1
security_level = 3

with BLEConnectionManager(adapter, role) as connection_manager:
    # Add new LTK to the Security Manager from previously established encryption keys
    connection_manager.add_key_to_security_manager_long_term_key_database(address_bytes, peer_address_type,
                                                                          ltk, ediv, rand, irk, csrk,
                                                                          security_mode, security_level)
    print connection_manager.get_security_manager_long_term_key_database().long_term_keys
