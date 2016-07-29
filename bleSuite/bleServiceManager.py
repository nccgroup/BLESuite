from entities.bleDevice import BLEDevice
import logging


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def bleServiceWriteToHandle(connectionManager, handle, data):
    """
    Writes data to handle using the supplied BLEConnectionManager object
    and returns response.

    :param connectionManager: BLEConnectionManager with connection to target device
    :param handle: Target handle
    :param data: Data string to write
    :type connectionManager: BLEConnectionManager
    :type handle: int - base 10
    :param data: str
    :rtype: list of strings
    """
    data = connectionManager.requester.write_by_handle(handle, data)
    logger.debug("RAWWrite: %s" % (data))
    return data


def bleServiceWriteToHandleAsync(connectionManager, handle, data, responseFunction=None):
    """
    Writes data to handle using the supplied BLEConnectionManager object
    using an asynchronous method. If a response function is supplied,
    the function is called with a single parameter (string) that contains
    the data of the target device's response. If no function is supplied,
    then the returned GATTResponse object will contain the response
    data, which can be accessed by calling its .received() method (note:
    the .received method can only be used if a function is not supplied).

    :param connectionManager: BLEConnectionManager with connection to target device
    :param handle: Target handle
    :param data: Data to write to handle
    :param responseFunction: Function that will be called upon receiving response, if None, then GATTResponse returned will contain response
    :type connectionManager: BLEConnectionManager
    :type handle: int - base 10
    :type data: str
    :type responseFunction: function pointer
    :return: (responseID, GATTResponse)
    :rtype: tuple
    """

    requester = connectionManager.requester
    counterAndResponse = connectionManager.createResponse(responseFunction=responseFunction)
    response = counterAndResponse[1]
    requester.write_by_handle_async(handle, data, response)
    return counterAndResponse


def bleServiceReadByHandle(connectionManager, handle):
    """
    Reads data from handle using the supplied BLEConnectionManager object
    and returns response.

    :param connectionManager: BLEConnectionManager with connection to target device
    :param handle: Target handle
    :return: Data returned from read
    :type connectionManager: BLEConnectionManager
    :type handle: int - base 10
    :rtype: list of strings
    """
    #print "Received Handle:", handle
    #if convertBase16:
    #print "Converted Handle:", int(handle, 16)
    #data = connectionManager.requester.read_by_handle(int(handle, 16))
    #else:
    data = connectionManager.requester.read_by_handle(handle)


    logger.debug("Handle: %s   RAW: %s" % (hex(handle), data))
    return data

'''
def bleServiceLongReadByHandle(connectionManager, handle, offset):
    """
    Reads data from handle using the supplied BLEConnectionManager object
    and returns response.

    :param connectionManager: BLEConnectionManager with connection to target device
    :param handle: Target handle
    :return: Data returned from read
    :type connectionManager: BLEConnectionManager
    :type handle: int - base 10
    :rtype: list of strings
    """
    #print "Received Handle:", handle
    #if convertBase16:
    #print "Converted Handle:", int(handle, 16)
    #data = connectionManager.requester.read_by_handle(int(handle, 16))
    #else:
    data = connectionManager.requester.long_read_by_handle(handle, offset)


    logger.debug("Handle: %s   RAW: %s" % (hex(handle), data))
    return data
'''

def bleServiceReadByHandleAsync(connectionManager, handle, responseFunction=None):
    """
    Reads data from handle using the supplied BLEConnectionManager object
    using an asynchronous method. If a response function is supplied,
    the function is called with a single parameter (string) that contains
    the data of the target device's response. If no function is supplied,
    then the returned GATTResponse object will contain the response
    data, which can be accessed by calling its .received() method (note:
    the .received method can only be used if a function is not supplied).

    :param connectionManager: BLEConnectionManager with connection to target device
    :param handle: Target handle
    :param responseFunction: Function that will be called upon receiving response, if None, then GATTResponse returned will contain response
    :type connectionManager: BLEConnectionManager
    :type handle: int - base 10
    :type responseFunction: function pointer
    :return: (responseID, GATTResponse)
    :rtype: tuple
    """

    requester = connectionManager.requester
    counterAndResponse = connectionManager.createResponse(responseFunction=responseFunction)
    response = counterAndResponse[1]
    requester.read_by_handle_async(handle, response)
    return counterAndResponse


def bleServiceReadByUUID(connectionManager, UUID):
    """
    Reads data from UUID using the supplied BLEConnectionManager object
    and returns response. Note: The first two bytes of every data
    string is the handle of the descriptor that corresponds to the UUID.

    :param connectionManager: BLEConnectionManager with connection to target device
    :param UUID: Target UUID
    :type connectionManager: BLEConnectionManager
    :type UUID: str
    :rtype: list of strings
    """

    data = connectionManager.requester.read_by_uuid(UUID)
    logger.debug("UUID: %s  RAW: %s" % (UUID, data))
    return data


def bleServiceReadByUUIDAsync(connectionManager, UUID, responseFunction=None):
    """
    Reads data from UUID using the supplied BLEConnectionManager object
    using an asynchronous method. If a response function is supplied,
    the function is called with a single parameter (string) that contains
    the data of the target device's response. If no function is supplied,
    then the returned GATTResponse object will contain the response
    data, which can be accessed by calling its .received() method (note:
    the .received() method can only be used if a function is not supplied).
    Note: The first two bytes of every data
    string is the handle of the descriptor that corresponds to the UUID.

    :param connectionManager: BLEConnectionManager with connection to target device
    :param UUID: Target UUID
    :param responseFunction: Function that will be called upon receiving response, if None, then GATTResponse returned will contain response
    :type connectionManager: BLEConnectionManager
    :type UUID: str
    :type responseFunction: function pointer
    :return: (responseID, GATTResponse)
    :rtype: tuple
    """

    requester = connectionManager.requester
    counterAndResponse = connectionManager.createResponse(responseFunction=responseFunction)
    response = counterAndResponse[1]
    requester.read_by_uuid_async(UUID, response)
    return counterAndResponse


def bleServiceDiscovery(address, connectionManager):
    """
    Scans device associated with supplied BLEConnectionManager
    for all services and characteristics and creates a
    BLEDevice object.

    :param address: Address of target BTLE device
    :param connectionManager: BLEConnectionManager with connection to target device
    :type address: str
    :type connectionManager: BLEConnectionManager
    :rtype: BLEDevice
    """
    connectionManager.connect()

    bleDevice = BLEDevice(address)
    deviceDiscoverPrimaryServices(bleDevice, connectionManager.requester)
    deviceDiscoverCharacteristics(bleDevice, connectionManager.requester)


    return bleDevice



def deviceDiscoverPrimaryServices(device, requester):
    """
    Scans device associated with requester for all primary services
    and stores them in the provided BLEDevice.

    :param device: Target BLEDevice
    :param requester: GATTRequester associated with target device
    :type device: BLEDevice
    :type requester: GATTRequester
    :return:
    """
    primaries = requester.discover_primary()
    for primary in primaries:
        device.addService(primary['start'], primary['end'], primary['uuid'])


def deviceDiscoverCharacteristics(device, requester):
    """
    Scans device associated with requester for all characteristics
    and stores them in the provided BLEDevice.

    :param device: Target BLEDevice
    :param requester: GATTRequester associated with target device
    :type device: BLEDevice
    :type requester: GATTRequester
    :return:
    """
    characteristics = requester.discover_characteristics()

    for characteristic in characteristics:
        device.addCharacteristic(characteristic['value_handle'], characteristic['handle'],
                                 characteristic['uuid'], characteristic['properties'])



