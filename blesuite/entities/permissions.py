class Permissions:
    """
    Permissions is class that contains the definitions for BLE GATT permissions.
    BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part G page 2235
    """
    BROADCAST = 0x01
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10
    INDICATE = 0x20
    AUTHENTICATED_SIGNED_WRITES = 0x40
    EXTENDED_PROPERTIES = 0x80
    permission_dict = {
        BROADCAST: "Broadcast",
        READ: "Read",
        WRITE_WITHOUT_RESPONSE: "Write Without Response",
        WRITE: "Write",
        NOTIFY: "Notify",
        INDICATE: "Indicate",
        AUTHENTICATED_SIGNED_WRITES: "Authenticated Signed Writes",
        EXTENDED_PROPERTIES: "Extended Properties"
    }

    permission_dictionary_lookup_by_name = {name.lower(): opcode for opcode, name in permission_dict.iteritems()}
