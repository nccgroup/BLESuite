from blesuite import connection_manager
import blesuite.utils.print_helper as print_helper
from blesuite import event_handler
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def ble_service_read(address, adapter, addressType, handles, UUIDS, timeout):
    """
    Used by command line tool to read data from device by handle

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param handles: List of handles to read from
    :param UUIDS: List of UUIDs to read from
    :param maxTries: Maximum number of times to attempt each write operation. Default: 5
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type handles: list of base 10 ints
    :type UUIDS: list of strings
    :type maxTries: int
    :return: uuidData, handleData
    :rtype: list of (UUID, data) tuples and list of (handle, data) tuples
    """
    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return

        uuidData = []
        handleData = []
        for handle in handles:
            if handle is not None:
                tries = 0
                if not connectionManager.is_connected(connection):
                    connectionManager.connect(connection)
                req = connectionManager.gatt_read_handle(connection, int(handle, 16), timeout=timeout)

                if req.has_error():
                    handleData.append((handle, req.get_error_message()))
                else:
                    handleData.append((handle, req.response.data))
        for UUID in UUIDS:
            if UUID is not None:
                tries = 0
                if not connectionManager.is_connected(connection):
                    connectionManager.connect(connection)
                req = connectionManager.gatt_read_uuid(connection, UUID, timeout=timeout)

                if req.has_error():
                    uuidData.append((UUID, req.get_error_message()))
                else:
                    uuidData.append((UUID, req.response.data))

    # returns list of tuples (handle, data)
    return uuidData, handleData


def ble_service_read_async(address, adapter, addressType, handles, UUIDS, timeout=5):
    """
    Used by command line tool to read data from device by handle using the async
    method. As of now, errors are not returned when reading asynchronously, so a
    timeout must be specified to determine when we should stop looking for a response
    from a device. (Note: This call is blocking until responses are received or a timeout
    is reached).

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param handles: List of handles to read from
    :param UUIDS: List of UUIDs to read from
    :param maxTries: Maximum number of times to attempt each write operation. Default: 5
    :param timeout: Time (in seconds) until each read times out if there's an issue. Default: 5
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type handles: list of base 10 ints
    :type UUIDS: list of strings
    :type maxTries: int
    :type timeout: int
    :return: uuidData, handleData
    :rtype: list of (UUID, data) tuples and list of (handle, data) tuples
    """
    import time
    import gevent

    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return

        uuidRequests = []
        handleRequests = []

        handleRequestQueue = []
        uuidRequestQueue = []
        for handle in handles:
            if handle is not None:
                tries = 0
                if not connectionManager.is_connected(connection):
                    connectionManager.connect(connection)
                logger.debug("Attempting to read from handle: %s" % handle)
                req = connectionManager.gatt_read_handle_async(connection, int(handle, 16), timeout=timeout)
                handleRequestQueue.append((handle, req, req.creation_time))

        for UUID in UUIDS:
            if UUID is not None:
                tries = 0
                if not connectionManager.is_connected(connection):
                    connectionManager.connect(connection)
                logger.debug("Attempting to read from UUID: %s" % UUID)
                req = connectionManager.gatt_read_uuid_async(connection, UUID, timeout=timeout)
                uuidRequestQueue.append((UUID, req, req.creation_time))


        #returns list of tuples (handle, data)
        while True:
            for i in handleRequestQueue:
                req = i[1]
                if req.has_response():
                    data = req.response.data
                    logger.debug("Handle: %s Received data: %s" % (i[0], data))
                    handleRequests.append((i[0], data))
                    handleRequestQueue.remove(i)
                elif req.has_error():
                    error = req.get_error_message()
                    logger.debug("Handle: %s Error message: %s" % (i[0], error))
                    handleRequests.append((i[0], error))
                    handleRequestQueue.remove(i)
                logger.debug("Response creation time: %s current time: %s" % (i[2], time.time()))
            for i in uuidRequestQueue:
                req = i[1]
                if req.has_response():
                    data = req.response.data
                    logger.debug("UUID: %s Received data: %s" % (i[0], data))
                    uuidRequests.append((i[0], data))
                    uuidRequestQueue.remove(i)
                elif req.has_error():
                    error = req.get_error_message()
                    uuidRequests.append((i[0], error))
                    uuidRequestQueue.remove(i)
                logger.debug("Response creation time: %s current time: %s" % (i[2], time.time()))
            if len(handleRequestQueue) <= 0 and len(uuidRequestQueue) <= 0:
                logger.debug("Out of responses")
                break
            logger.debug("Number of responses that haven't received: %s" % (len(handleRequestQueue) +
                                                                            len(uuidRequestQueue)))
            gevent.sleep(0.1)

    return uuidRequests, handleRequests


def ble_service_write(address, adapter, addressType, handles, inputs, timeout):
    """
    Used by command line tool to wrtie data to a device handle

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param handles: List of handles to write to
    :param inputs: List of strings to write to handles
    :param maxTries: Maximum number of times to attempt each write operation. Default: 5
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type handles: list of base 10 ints
    :type inputs: list of strings
    :type maxTries: int
    :return: list of (handle, data, input)
    :rtype: list of tuples (int, str, str)
    """
    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return
        handleData = []
        for inputVal in inputs:
            for handle in handles:
                if handle is not None:
                    tries = 0

                    if not connectionManager.is_connected(connection):
                        connectionManager.connect(connection)
                    req = connectionManager.gatt_write_handle(connection, int(handle, 16), inputVal,
                                                              timeout=timeout)
                    if req.has_error():
                        handleData.append((handle, req.get_error_message(), inputVal))
                    else:
                        handleData.append((handle, req.response.data, inputVal))
    return handleData


def ble_service_write_async(address, adapter, addressType, handles, inputs, timeout=5):
    """
    Used by command line tool to write data to device by handle using the async
    method. As of now, errors are not returned when reading asynchronously, so a
    timeout must be specified to determine when we should stop looking for a response
    from a device. (Note: This call is blocking until responses are received or a timeout
    is reached).

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param handles: List of handles to read from
    :param inputs: List of input strings to send
    :param maxTries: Maximum number of times to attempt each write operation. Default: 5
    :param timeout: Time (in seconds) until each read times out if there's an issue. Default: 5
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type handles: list of base 10 ints
    :type inputs: list of str
    :type maxTries: int
    :type timeout: int
    :return: list of (handle, data, inputVal) tuples
    :rtype: list of (int, str, str) tuples
    """
    import time
    import gevent

    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return
        handleRequests = []

        handleRequestQueue = []

        for inputVal in inputs:
            for handle in handles:
                if handle is not None:
                    if not connectionManager.is_connected(connection):
                        connectionManager.connect(connection)
                    logger.debug("Attempting to send %s to handle %s" % (inputVal, handle))
                    req = connectionManager.gatt_write_handle_async(connection, int(handle, 16),
                                                                    inputVal, timeout=timeout)
                    handleRequestQueue.append((handle, req, req.creation_time, [inputVal]))


        #returns list of tuples (handle, data)
        while True:
            for i in handleRequestQueue:
                req = i[1]
                if req.has_response():
                    data = req.response.data
                    logger.debug("Handle: %s Received data: %s" % (i[0], data))
                    handleRequests.append((i[0], [data], i[3]))
                    handleRequestQueue.remove(i)
                elif req.has_error():
                    error = req.get_error_message()
                    logger.debug("Handle: %s Received error: %s" % (i[0], error))
                    handleRequests.append((i[0], [error], i[3]))
                    handleRequestQueue.remove(i)
                logger.debug("Response creation time: %s current time: %s" % (i[2], time.time()))
            if len(handleRequestQueue) <= 0:
                logger.debug("Out of responses")
                break
            logger.debug("Number of responses that haven't received: %s" % len(handleRequestQueue))
            gevent.sleep(0.1)

    return handleRequests


def ble_handle_subscribe(address, handles, adapter, addressType, mode, listenTime=None):
    """
    Used by command line tool to enable specified handles' notify mode
    and listen until user interrupts.

    :param address: Address of target BTLE device
    :param handles: List of handle descriptors to write 0100 (enable notification) to
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param mode: Mode to set for characteristic configuration (0=off,1=notifications,2=indications,
    3=notifications and inidications)
    :type address: str
    :type handles: list of base 10 ints
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type mode: int
    :return:
    """
    import time
    import gevent
    logger.debug("Beginning Subscribe Function")
    if address is None:
        raise Exception("%s Bluetooth address is not valid. Please supply a valid Bluetooth address value." % address)

    if mode == 0:
        configVal = str(bytearray([00, 00]))
    elif mode == 1:
        configVal = str(bytearray([01, 00]))
    elif mode == 2:
        configVal = str(bytearray([02, 00]))
    elif mode == 3:
        configVal = str(bytearray([03, 00]))
    else:
        raise Exception("%s is not a valid mode. Please supply a value between 0 and 3 (inclusive)" % mode)

    class EventHandler(event_handler.BTEventHandler):
        def __init__(self, connection_manager):
            event_handler.BTEventHandler.__init__(self, connection_manager)
            self.connectionManager = connection_manager

        def on_att_event(self, connection_handle, data):
            from blesuite.pybt.att import ATT_PDU_OPCODE_BY_NAME
            if data.opcode == 0x1b:#notification
                print "\nNotification on Handle %s" % hex(data.gatt_handle)
                print "======================="
                #print format(originHandle, "#8x")
                print_helper.print_data_and_hex([data.value], False)
            elif data.opcode == 0x1d:#indication
                print "\nIndication on Handle %s" % hex(data.gatt_handle)
                print "======================="
                print_helper.print_data_and_hex([data.value], False)

    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return
        connectionManager.set_event_handler(EventHandler(connectionManager))

        for handle in handles:
            connectionManager.gatt_write_handle(connection, int(handle, 16), configVal)
        start = time.time() * 1000
        while True:
            if connectionManager.is_connected(connection):
                if listenTime is not None:
                    if ((time.time()*1000) - start) >= listenTime:
                        break
                gevent.sleep(.1)
                continue
            logger.debug("Connection Lost, re-connecting subscribe")
            connectionManager.connect(connection)
            for i in handles:
                connectionManager.gatt_write_handle(connection, int(i, 16), configVal)

            if listenTime is not None:
                if ((time.time()*1000) - start) >= listenTime:
                    break
            gevent.sleep(.1)


def ble_service_scan(address, adapter, addressType):
    """
    Used by command line tool to initiate and print results for
    a scan of all services,
    characteristics, and descriptors present on a BTLE device.

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :return:
    """
    if address is None:
        raise Exception("%s Bluetooth address is not valid. Please supply a valid Bluetooth address value." % address)
    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return

        device = connectionManager.gatt_discover_primary_services(connection)
        device = connectionManager.gatt_discover_characteristics(connection, device=device)
        device = connectionManager.gatt_discover_descriptors(connection, device=device)

    device.print_device_structure()


def ble_run_smart_scan(address, adapter, addressType, skip_device_info_query=False, attempt_read=False,
                       timeout=None):
    """
    Used by command line tool to initiate and print results for
    a scan of all services,
    characteristics, and descriptors present on a BTLE device.

    :param address: Address of target BTLE device
    :param adapter: Host adapter (Empty string to use host's default adapter)
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :return:
    """
    if address is None:
        raise Exception("%s Bluetooth address is not valid. Please supply a valid Bluetooth address value." % address)

    with connection_manager.BLEConnectionManager(adapter, 'central') as connectionManager:
        logger.debug("ConnectionManager available")
        connection = connectionManager.init_connection(address, addressType)
        success = connectionManager.connect(connection)
        if not success:
            print "Failed to connected to target device"
            return
        logger.debug("Connected!")
        device = connectionManager.smart_scan(connection, device=None,
                                              look_for_device_info=(not skip_device_info_query),
                                              attempt_desc_read=attempt_read, timeout=timeout)

    print "**********************"
    print "Smart Scan Results"
    print "**********************"

    device.print_device_structure()

    print "**********************"
    print "Finished"
    print "**********************"
