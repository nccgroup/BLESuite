from bleServiceManager import bleServiceDiscovery, bleServiceReadByHandle,  \
    bleServiceReadByUUID
from utils.printHelper import printDataAndHex
from bleConnectionManager import BLEConnectionManager
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def bleSmartScan(address, connectionManager):
    """ Performs a Smart Scan on the specified BTLE address using the specified adapter.
    This scan includes queries for device information, services, characteristics, and a comprehensive
    list of characteristic descriptors available.

    :param address: Target BTLE address
    :param connectionManager: Connection manager for target BLE device
    :type address: str
    :type connectionManager: BLEConnectionManager
    :return: Device object that represents scanned BLE device
    :rtype: bleDevice
    """
    deviceInformationQueryList = [
        ("Device name", "2A00"),
        ("Manufacturer string", "2A29"),
        ("Model number string", "2A24"),
        ("Firmware revision string", "2A26"),
        ("Hardware revision string", "2A27"),
        ("Software revision string", "2A28"),
        ("System ID", "2A23"),
        ("Regulatory Certification Data List", "2A2A"),
        ("PnP ID", "2A50"),
        ("Peripheral preferred connection parameters", "2A04"),
        ("Appearance", "2A01"),
        ("Client Characteristic Configuration (CCC)", "2902"),
        ("Server Characteristic Configuration (SCC)", "2903")
    ]
    #[(queryTitle, UUID, handle, data)]
    deviceInformation = []

    #connectionManager = BLEConnectionManager(address, adapter, addressType, securityLevel)
    #connectionManager.connect()

    #scan for services
    device = bleServiceDiscovery(address, connectionManager)

    #scan for device information
    logger.debug("Querying device for basic information")
    for query in deviceInformationQueryList:
        try:
            #reset handle value
            handles = None
            data = bleServiceReadByUUID(connectionManager, query[1])
        except RuntimeError as e:
            if "Invalid handle" in str(e) or "No attribute found within the given range" in str(e):
                data = -1
            elif "Attribute can't be read" in str(e):
                data = -2
            else:
                logger.debug("Unknown Exception: %s", e)
                raise RuntimeError(e)

        #print "DataPre:",data
        if isinstance(data, int) and data == -1:
            device.addDeviceInfo(query[0], query[1], handles, -1)
            continue
        elif isinstance(data, int) and data == -2:
            device.addDeviceInfo(query[0], query[1], handles, -2)
            continue
        handles = []
        for i, entry in enumerate(data):
            handles.append(entry[:2][::-1])
            data[i] = entry[2:]

        device.addDeviceInfo(query[0], query[1], handles, data)




    #calculate descriptors
    indentifyDescriptors(device, connectionManager)

    return device


def indentifyDescriptors(device, connectionManager):
    """ Attempts to identify all descriptors for a device's characteristics and stores them
    in the characteristic objects.

    :param device: Device object of target BTLE device
    :param connectionManager: Connection manager used to manage BTLE device connection
    :type device: BLEDevice
    :type connectionManager: BLEConnectionManager
    :return:
    """
    logger.debug("Identifying descriptors")
    for i, service in enumerate(device.services):
        for j, characteristic in enumerate(service.characteristics):
            value = characteristic.handle
            #print value
            #grab handle of next characteristic (if possible)
            if j < (len(service.characteristics) - 1):
                compareValue = service.characteristics[j + 1].handle
            #if no more characteristics under service, grab start of next service (if possible)
            elif i < (len(device.services) - 1):
                compareValue = device.services[i + 1].start
            #if no more services, read 4 handles
            else:
                compareValue = value + 5
            #print "Value:", value
            #print "CompareValue", compareValue
            for k in range(value, compareValue):
                #print "Descriptor Handle:", k
                try:
                    data = bleServiceReadByHandle(connectionManager, k)
                except RuntimeError as e:
                    if "Invalid handle" in str(e):
                            data = -1
                    elif "Attribute can't be read" in str(e):
                            data = -2
                    else:
                        logger.debug("Unknown Exception: %s", e)
                        raise RuntimeError(e)
                    #if we get a -1 back, that means we are done reading descriptors within
                    #a characteristic. Note: -2 indicates that we are tying to read from a value
                    #that is not read-able
                    if isinstance(data, int) and data == -1:
                        break
                characteristic.addDescriptorWithData(k, data)
    return
