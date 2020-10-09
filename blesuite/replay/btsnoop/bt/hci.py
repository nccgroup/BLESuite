"""
  Parse hci packet information from binary string
"""
import sys
import struct
import blesuite.replay.btsnoop.bt.hci_uart as hci_uart
import blesuite.replay.btsnoop.bt.hci_cmd as hci_cmd
import blesuite.replay.btsnoop.bt.hci_evt as hci_evt
import blesuite.replay.btsnoop.bt.hci_acl as hci_acl
import blesuite.replay.btsnoop.bt.hci_sco as hci_sco


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
