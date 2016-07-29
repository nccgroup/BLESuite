import argparse
import re

def checkValidBTAddr(addr):
    """
    Validates BT address string

    :param addr: BT Address
    :type: str
    :return: addr
    """
    if addr != None:
        match = re.search("^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$"
                          , addr)
        if match != None and match.group(0) != None:
            return addr

    raise argparse.ArgumentTypeError("%s is an invalid Bluetooth address (BD_ADDR)" % addr)

