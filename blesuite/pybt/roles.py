import logging

from blesuite.pybt.stack import BTStack
from blesuite.pybt.att import AttributeProtocol
from blesuite.pybt.gatt import Server
from blesuite.pybt.sm import SM, SecurityManagerProtocol
import os

from select import select

log = logging.getLogger(__name__)

ROLE_TYPE_CENTRAL = 0x00
ROLE_TYPE_PERIPHERAL = 0x01

PUBLIC_DEVICE_ADDRESS = 0x00
RANDOM_DEVICE_ADDRESS = 0x01

# TODO: Add support for resolvable and non-resolvable private addresses. Currently, we
# only support static random addresses.


class LECentral:
    def __init__(self, adapter=0, address_type=PUBLIC_DEVICE_ADDRESS, random=None,
                 att_operation_event_hook=None):
        self.stack = BTStack(adapter=adapter)
        self.smp = SecurityManagerProtocol(self.stack)
        self.att = AttributeProtocol(self.stack, self.smp, event_hook=att_operation_event_hook)
        self.address = self.stack.addr
        if address_type == RANDOM_DEVICE_ADDRESS:
            if random is not None:
                self.address = ''.join(map(lambda x: chr(int(x, 16)), random.split(':')))
            else:
                self.address = os.urandom(6)
            # Static random address
            self.stack.set_random_address(self.address[::-1])
            self.address_type = 1

        else:
            self.address = self.stack.addr
            self.address_type = 0

    def destroy(self):
        log.debug("Destroying LECentral")
        if self.stack is not None:
            self.stack.destroy()
        if self.att is not None:
            self.att.__del__()
        self.att = None
        self.stack = None
        self.smp = None


class LEPeripheral:
    def __init__(self, gatt_server, adapter=0, mtu=23, address_type=PUBLIC_DEVICE_ADDRESS, random=None,
                 att_operation_event_hook=None):
        self.stack = BTStack(adapter=adapter)
        self.smp = SecurityManagerProtocol(self.stack)
        self.gatt_server = gatt_server
        self.att = AttributeProtocol(self.stack, self.smp, gatt_server=self.gatt_server, mtu=mtu,
                                     event_hook=att_operation_event_hook)

        if address_type == RANDOM_DEVICE_ADDRESS:
            if random is not None:
                self.address = ''.join(map(lambda x: chr(int(x, 16)), random.split(':')))
            else:
                self.address = os.urandom(6)
            # Static random address
            self.stack.set_random_address(self.address[::-1])
            self.address_type = 1

        else:
            self.address = self.stack.addr
            self.address_type = 0

    def destroy(self):
        log.debug("Destroying LEPeripheral")
        if self.stack is not None:
            self.stack.destroy()
        if self.att is not None:
            self.att.__del__()
        self.att = None
        self.stack = None
        self.smp = None
