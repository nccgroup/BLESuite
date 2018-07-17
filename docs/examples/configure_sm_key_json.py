from blesuite.connection_manager import BLEConnectionManager
import json

adapter = 0
role = 'central'

with BLEConnectionManager(adapter, role) as connection_manager:
    # Add new LTK to the Security Manager from previously established encryption keys, orignally exported to JSON
    with open("long_term_key_database.json", "r") as f:
        long_term_key_database = json.loads(f.read())
    connection_manager.import_long_term_key_database_to_security_manager(long_term_key_database)
    print connection_manager.get_security_manger_long_term_key_database().long_term_keys

