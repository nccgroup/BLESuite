"""
Parse HCI SCO packets
"""
import struct
import ctypes
from ctypes import c_uint


"""
SCO handle is 12 bits, followed by 2 bits packet status flags.

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
-------------------------------------------------
|            handle     |ps |xx |    length     |
-------------------------------------------------
"""
class SCO_HEADER_BITS( ctypes.LittleEndianStructure ):
    _fields_ = [("handle",  c_uint,  12),
                ("ps",      c_uint,  2 ),
                ("xx",      c_uint,  2 ),
                ("length",  c_uint,  8)]


class SCO_HEADER( ctypes.Union ):
    """
    This is a trick for converting bitfields to separate values
    """
    _fields_ = [("b", SCO_HEADER_BITS),
                ("asbyte", c_uint)]


def parse(data):
    """
    Parse HCI ACL data

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5) - HCI Data Formats
    ** [vol 2] Part E (Section 5.4) - Exchange of HCI-specific information

    """
    hdr = SCO_HEADER()
    hdr.asbyte = struct.unpack("<HB", data[:3])[0]
    handle = int(hdr.b.handle)
    ps = int(hdr.b.pb)
    length = int(hdr.b.length)
    return (handle, ps, length, data[3:])


def ps_to_str(ps):
    """
    Return a string representing the packet status flag
    """
    assert ps in [0, 1, 2, 3]