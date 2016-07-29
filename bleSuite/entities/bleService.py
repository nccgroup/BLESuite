class BLEService(object):
    """ BLEService is used to represent a service located on a BTLE device

        :var start: Start handle for service
        :var end: End handle for service
        :var uuid: UUID of service
        :type start: int - base 10
        :type end: int - base 10
        :type uuid: str
        :ivar start: initial value: start
        :ivar end: initial value: end
        :ivar uuid: initial value: uuid
        :ivar characteristics: initial value: []

    """
    def __init__(self, start, end, uuid):
        self.uuid = uuid
        self.start = start
        self.end = end
        self.characteristics = []