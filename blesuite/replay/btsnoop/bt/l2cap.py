"""
Parse L2CAP packets
"""
import struct
from . import hci_acl


"""
Fixed channel ids for L2CAP packets

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part A (Section 2.1) - Channel identifiers
"""
L2CAP_CID_NUL = 0x0000
L2CAP_CID_SCH = 0x0001
L2CAP_CID_ATT = 0x0004
L2CAP_CID_LE_SCH = 0x0005
L2CAP_CID_SMP = 0x0006


L2CAP_CHANNEL_IDS = {
        L2CAP_CID_NUL : "L2CAP CID_NUL",
        L2CAP_CID_SCH : "L2CAP CID_SCH",
        L2CAP_CID_ATT : "L2CAP CID_ATT",
        L2CAP_CID_LE_SCH : "L2CAP CID_LE_SCH",
        L2CAP_CID_SMP : "L2CAP CID_SMP"
    }


def parse_hdr(data):
    """
    Parse L2CAP packet

     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 
    -----------------------------------------------------------------
    |            length             |          channel id           |
    -----------------------------------------------------------------

    L2CAP is packet-based but follows a communication model based on channels.
    A channel represents a data flow between L2CAP entities in remote devices.
    Channels may be connection-oriented or connectionless. Fixed channels
    other than the L2CAP connectionless channel (CID 0x0002) and the two L2CAP
    signaling channels (CIDs 0x0001 and 0x0005) are considered connection-oriented.

    All L2CAP layer packet fields shall use Little Endian byte order with the exception of the 
    information payload field. The endian-ness of higher layer protocols encapsulated within 
    L2CAP information payload is protocol-specific

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part A (Section 3) - Data Packet Format

    Returns a tuple of (length, cid, data)
    """
    length, cid = struct.unpack("<HH", data[:4])
    data = data[4:]
    return length, cid, data


"""
Codes and names for L2CAP Signaling Protocol
"""
L2CAP_SCH_PDUS = {
        0x01 : "SCH Command reject",
        0x02 : "SCH Connection request",
        0x03 : "SCH Connection response",
        0x04 : "SCH Configure request",
        0x05 : "SCH Configure response",
        0x06 : "SCH Disconnection request",
        0x07 : "SCH Disconnection response",
        0x08 : "SCH Echo request",
        0x09 : "SCH Echo response",
        0x0a : "SCH Information request",
        0x0b : "SCH Information response",
        0x0c : "SCH Create Channel request",
        0x0d : "SCH Create Channel response",
        0x0e : "SCH Move Channel request",
        0x0f : "SCH Move Channel response",
        0x10 : "SCH Move Channel Confirmation",
        0x11 : "SCH Move Channel Confirmation response",
        0x12 : "LE SCH Connection_Parameter_Update_Request",
        0x13 : "LE SCH Connection_Parameter_Update_Response",
        0x14 : "LE SCH LE_Credit_Based_Connection Request",
        0x15 : "LE SCH LE_Credit_Based_Connection Response",
        0x16 : "LE SCH LE_Flow_Control_Credit",
    }


def parse_sch(l2cap_data):
    """
    Parse the signaling channel data.

    The signaling channel is a L2CAP packet with channel id 0x0001 (L2CAP CID_SCH)
    or 0x0005 (L2CAP_CID_LE_SCH)

     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    -----------------------------------------------------------------
    |      code     |        id     |             length            |
    -----------------------------------------------------------------

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part A (Section 4) - Signaling Packet Formats

    Returns a tuple of (code, id, length, data)
    """
    code, id, length = struct.unpack("<BBH", l2cap_data[:4])
    return (code, id, length, l2cap_data[4:])


PKT_TYPE_PARSERS = { hci_acl.PB_START_NON_AUTO_L2CAP_PDU : parse_hdr,
                     hci_acl.PB_CONT_FRAG_MSG : parse_hdr,
                     hci_acl.PB_START_AUTO_L2CAP_PDU : parse_hdr,
                     hci_acl.PB_COMPLETE_L2CAP_PDU : parse_hdr }


def parse(l2cap_pkt_type, data):
    """
    Convenience method for switching between parsing methods based on type
    """
    parser = PKT_TYPE_PARSERS[l2cap_pkt_type]
    if parser is None:
        raise ValueError("Illegal L2CAP packet type")
    return parser(data)


def cid_to_str(cid):
    """
    Return a string representing the L2CAP channel id
    """
    return L2CAP_CHANNEL_IDS[cid]


def sch_code_to_str(code):
    """
    Return a string representing the signaling channel PDU
    """
    return L2CAP_SCH_PDUS[code]