"""
  Parse hci packet information from binary string
"""
import sys
import struct
import hci_uart
import hci_cmd
import hci_evt
import hci_acl
import hci_sco


PKT_TYPE_PARSERS = {hci_uart.HCI_CMD : hci_cmd.parse,
                    hci_uart.ACL_DATA : hci_acl.parse,
                    hci_uart.SCO_DATA : hci_sco.parse,
                    hci_uart.HCI_EVT : hci_evt.parse}


def parse(hci_pkt_type, data):
    """
    Convenience method for switching between parsing methods based on type
    """
    parser = PKT_TYPE_PARSERS[hci_pkt_type]
    if parser is None:
        raise ValueError("Illegal HCI packet type")
    return parser(data)