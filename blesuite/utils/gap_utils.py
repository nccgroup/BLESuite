import blesuite.pybt.gap as gap
from blesuite.pybt.gap import GAP, GAP_MANUFACTURERS, GAP_ADV_AD_TYPES, GAP_ADV_TYPES
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

"""
Useful GAP definitions and helper functions.
"""


class AddressTypes:
    """
    GAP Address Type definitions (integer values for address types
    """
    PUBLIC_DEVICE_ADDRESS = 0x00
    RANDOM_DEVICE_ADDRESS = 0x01


class Roles:
    """
    GAP Role definitions for role values (integer values for roles)
    """

    ROLE_CENTRAL = 0x00
    ROLE_PERIPHERAL = 0x01


GAP_ADV_AD_TYPE_BY_NAME = {name: opcode for opcode, name in GAP_ADV_AD_TYPES.iteritems()}


def decode_gap_data(data):
    gap = GAP()
    try:
        gap.decode(data)
    except Exception as e:
        if "Data too short" in str(e):
            logger.debug("Data too short, leaving off malformed data")
        else:
            raise e

    return gap


def generate_gap_data_dict(gap):
    return gap.gap_dict()


def generate_ad_flag_value(le_limited_discoverable=False, le_general_discoverable=False, bredr_not_supported=False,
                           simultaneous_le_bredr_controller=False,
                           simultaneous_le_bredr_host=False):
    """
    Generate advertising data flag value based on user supplied options. This is a helper function to
    simplify creation of a single octet containing all the AD flags.
    See Supplement to Bluetooth Core Specification | CSSv7, Part A page 12

    :param le_limited_discoverable: Enable LE limited discoverable flag
    :type le_limited_discoverable: bool
    :param le_general_discoverable: Enable LE general discoverable flag
    :type le_general_discoverable: bool
    :param bredr_not_supported: Enable BR/EDR not supported flag
    :type bredr_not_supported: bool
    :param simultaneous_le_bredr_controller: Enable simultaneous LE and BR/EDR controller flag
    :type simultaneous_le_bredr_controller: bool
    :param simultaneous_le_bredr_host: Enable simultaneous LE and BR/EDR host flag
    :type simultaneous_le_bredr_host: bool
    :return: AD flag value (single octet) based on supplied options
    :rtype: int
    """
    value = 0
    if le_limited_discoverable:
        value += (1 << 0)
    if le_general_discoverable:
        value += (1 << 1)
    if bredr_not_supported:
        value += (1 << 2)
    if simultaneous_le_bredr_controller:
        value += (1 << 3)
    if simultaneous_le_bredr_host:
        value += (1 << 4)

    return value


def advertisement_data_entry_builder(name_of_ad_type, value):
    """
    Generates the final advertisement data entry for a single data type (specified by name) and
    the specified value. These entries are combined in a list and fed to
    blesuite.utils.gap_utils.advertisement_data_complete_builder to build the final AD string that
    can be passed to the BLEConnectionManager for setting advertising data.

    :param name_of_ad_type: Name of AD type (see blesuite.pybt.gap.GAP_ADV_AD_TYPE_BY_NAME or Supplement to Bluetooth Core Specification | CSSv7)
    :type name_of_ad_type: str
    :param value: Value to set for AD type (sent in advertising packets)
    :type value: str
    :return: Finalized advertisement data entry value
    :rtype: str
    """
    return chr(GAP_ADV_AD_TYPE_BY_NAME[name_of_ad_type]) + value


def advertisement_data_complete_builder(list_of_ad_entries):
    """
    Generate a finalized advertisement data value from a list of AD entries that can be passed
    to the BLEConnectionManager to set the advertisement data that is sent during advertising.

    :param list_of_ad_entries: List of AD entries (can be built using blesuite.utils.gap_utils.advertisement_data_entry_builder)
    :type list_of_ad_entries: [str,]
    :return: Finalized AD data
    :rtype: str
    """
    data = ""
    for ad in list_of_ad_entries:
        length = len(ad)
        ad_string = chr(length) + ad
        data = data + ad_string
    return data
