
class BLEDescriptor(object):
    """
    BLEDescriptor is used to represent a descriptor of a characteristic located on a BTLE device

    :var handle: Handle of descriptor
    :type handle: int - base 10
    :ivar handle: initial value: handle
    :ivar lastReadValue: initials value: None
    """
    def __init__(self, handle):
        self.handle = handle
        self.lastReadValue = None
