from blesuite.pybt.sm import SecurityMode

"""
Useful GAP definitions and helper functions.
"""

GATT_PERMIT_READ = 0x01
GATT_PERMIT_WRITE = 0x02
GATT_PERMIT_AUTH_READ = 0x04
GATT_PERMIT_AUTH_WRITE = 0x08

GATT_PROP_BCAST = 0x01
GATT_PROP_READ = 0x02
GATT_PROP_WRITE_NO_RSP = 0x04
GATT_PROP_WRITE = 0x08
GATT_PROP_NOTIFY = 0x10
GATT_PROP_INDICATE = 0x20
GATT_PROP_AUTHENTICATED_SIGNED_WRITES = 0x40
GATT_PROP_EXTENDED_PROPERTIES = 0x80

ATT_PROP_READ = 0x01
ATT_PROP_WRITE = 0x02

ATT_SECURITY_MODE_NO_ACCESS = SecurityMode(0, 0)
ATT_SECURITY_MODE_OPEN = SecurityMode(1, 1)
ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION = SecurityMode(1, 2)
ATT_SECURITY_MODE_ENCRYPTION_WITH_AUTHENTICATION = SecurityMode(1, 3)
ATT_SECURITY_MODE_ENCRYPTION_WITH_SECURE_CONNECTIONS = SecurityMode(1, 4)
ATT_SECURITY_MODE_DATA_SIGNING_NO_AUTHENTICATION = SecurityMode(2, 1)
ATT_SECURITY_MODE_DATA_SIGNING_WITH_AUTHENTICATION = SecurityMode(2, 2)


def get_att_security_mode_from_mode_and_level(mode, level):
    """
    Generate SecurityMode class instance based on a supplied mode and level.

    :param mode: Security mode
    :type mode: int
    :param level: Security level
    :type level: level
    :return: SecurityMode object corresponding to supplied values or False if DNE
    :rtype: SecurityMode || bool
    """
    if mode == 0 and level == 0:
        return ATT_SECURITY_MODE_NO_ACCESS
    elif mode == 1:
        if level == 1:
            return ATT_SECURITY_MODE_OPEN
        if level == 2:
            return ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION
        if level == 3:
            return ATT_SECURITY_MODE_ENCRYPTION_WITH_AUTHENTICATION
        if level == 4:
            return ATT_SECURITY_MODE_ENCRYPTION_WITH_SECURE_CONNECTIONS
    elif mode == 2:
        if level == 1:
            return ATT_SECURITY_MODE_DATA_SIGNING_NO_AUTHENTICATION
        if level == 2:
            return ATT_SECURITY_MODE_DATA_SIGNING_WITH_AUTHENTICATION

    return False
