"""
  Parse hci uart information from binary string
"""
import sys
import struct


"""
HCI Packet types for UART Transport layer
Core specification 4.1 [vol 4] Part A (Section 2) - Protocol
"""
HCI_CMD = 0x01
ACL_DATA = 0x02
SCO_DATA = 0x03
HCI_EVT = 0x04


HCI_UART_PKT_TYPES = {
    HCI_CMD : "HCI_CMD",
    ACL_DATA : "ACL_DATA",
    SCO_DATA : "SCO_DATA",
    HCI_EVT : "HCI_EVT"
}


def parse(data):
    """
    Parse a hci information from the specified data string

    There are four kinds of HCI packets that can be sent via the UART Transport
    Layer; i.e. HCI Command Packet, HCI Event Packet, HCI ACL Data Packet
    and HCI Synchronous Data Packet (see Host Controller Interface Functional
    Specification in Volume 2, Part E). HCI Command Packets can only be sent to
    the Bluetooth Host Controller, HCI Event Packets can only be sent from the
    Bluetooth Host Controller, and HCI ACL/Synchronous Data Packets can be
    sent both to and from the Bluetooth Host Controller.

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 4] Part A (Section 2) Protocol

    Returns a tuple (pkt_type, data) with the HCI type and data.
    """
    pkt_type = struct.unpack("<B", data[:1])[0]
    return ( pkt_type, data[1:] )


def type_to_str(pkt_type):
    """
    Return a string representing the HCI packet type
    """
    assert pkt_type in [HCI_CMD, ACL_DATA, SCO_DATA, HCI_EVT]
    return HCI_UART_PKT_TYPES[pkt_type]