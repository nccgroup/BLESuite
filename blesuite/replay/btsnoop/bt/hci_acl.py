"""
Parse HCI ACL packets
"""
import struct
import ctypes
from ctypes import c_uint


"""
ACL handle is 12 bits, followed by 2 bits packet boundary flags and 2
bits broadcast flags.

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
-----------------------------------------------------------------
|            handle     |pb |bc |             length            |
-----------------------------------------------------------------

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5.4.2) - HCI ACL Data Packets
"""
class ACL_HEADER_BITS( ctypes.LittleEndianStructure ):
    _fields_ = [("handle",  c_uint,  12),
                ("pb",      c_uint,  2 ),
                ("bc",      c_uint,  2 ),
                ("length",  c_uint,  16)]

class ACL_HEADER( ctypes.Union ):
    """
    This is a trick for converting bitfields to separate values
    """
    _fields_ = [("b", ACL_HEADER_BITS),
                ("asbyte", c_uint)]


"""
Packet Boundary flag

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5.4.2) - HCI ACL Data Packets
"""
PB_START_NON_AUTO_L2CAP_PDU = 0
PB_CONT_FRAG_MSG = 1
PB_START_AUTO_L2CAP_PDU = 2
PB_COMPLETE_L2CAP_PDU = 3


PB_FLAGS = {
        PB_START_NON_AUTO_L2CAP_PDU : "ACL_PB START_NON_AUTO_L2CAP_PDU",
        PB_CONT_FRAG_MSG : "ACL_PB CONT_FRAG_MSG",
        PB_START_AUTO_L2CAP_PDU : "ACL_PB START_AUTO_L2CAP_PDU",
        PB_COMPLETE_L2CAP_PDU : "ACL_PB COMPLETE_L2CAP_PDU"
    }


def parse(data):
    """
    Parse HCI ACL data

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5) - HCI Data Formats
    ** [vol 2] Part E (Section 5.4) - Exchange of HCI-specific information

    """
    hdr = ACL_HEADER()
    hdr.asbyte = struct.unpack("<I", data[:4])[0]
    handle = int(hdr.b.handle)
    pb = int(hdr.b.pb)
    bc = int(hdr.b.bc)
    length = int(hdr.b.length)
    return (handle, pb, bc, length, data[4:])


def pb_to_str(pb):
    """
    Return a string representing the packet boundary flag
    """
    assert pb in [0, 1, 2, 3]
    return PB_FLAGS[pb]