from blesuite.entities.gatt_device import BLEDevice
import logging


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

"""
Functions in this file are used to carry out standard GATT actions
and some can be used to construct BLEDevice objects (device enumeration functions).
These are helper functions used by the BLEConnectionManager.

See: BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part G Page 2272 for GATT/ATT function mappings
"""


def gatt_procedure_write_handle(stack_connection, connection_handle, handle, data, timeout=15 * 1000):
    """
    Writes data to target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param data: Data string to write
    :type handle: int
    :param data: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    request = stack_connection.write_req_sync(handle, data, connection_handle, timeout=timeout)
    if request.has_error():
        logger.debug("Write Response Error")
    else:
        logger.debug("Write Response Data(str): %s" % request.response.data)
    return request


def gatt_procedure_write_handle_async(stack_connection, connection_handle, handle, data, timeout=15 * 1000):
    """
    Writes data to target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param data: Data to write to handle
    :type handle: int - base 10
    :type data: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    request = stack_connection.write_req_async(handle, data, connection_handle, timeout=timeout)
    return request


def gatt_procedure_write_command_handle(stack_connection, connection_handle, handle, data):
    """
    Writes data to target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request without
    returning any value since the write command request will not receive a defined response from the peer
    device.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param data: Data string to write
    :type handle: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :param data: str
    """
    stack_connection.write_command(handle, data, connection_handle)


def gatt_procedure_prepare_write_handle(stack_connection, connection_handle, handle, data, offset, timeout=15 * 1000):
    """
    Writes data at a specific offset to the prepared write queue of the peer device for the
    target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param data: Data string to write
    :param offset: Offset of data written
    :type handle: int - base 10
    :type offset: int - base 10
    :param data: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    request = stack_connection.prepare_write_req_sync(handle, data, offset, connection_handle, timeout=timeout)
    if request.has_error():
        logger.debug("Prepare Write Response Error")
    else:
        logger.debug("Prepare Write Response Data(str): %s" % request.response.data)
    return request


def gatt_procedure_prepare_write_handle_async(stack_connection, connection_handle, handle, data, offset,
                                              timeout=15 * 1000):
    """
    Writes data at a specific offset to the prepared write queue of the peer device for the
    target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param data: Data to write to handle
    :param offset: Offset of data written
    :type handle: int - base 10
    :type offset: int - base 10
    :type data: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    request = stack_connection.prepare_write_req_async(handle, data, offset, connection_handle,
                                                       timeout=timeout)
    return request


def gatt_procedure_execute_write(stack_connection, connection_handle, flags, timeout=15 * 1000):
    """
    Sends an execute write request to the peer device with a flag to indicate the action
    for the peer device's prepared write queue and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param flags: Flags (0 - cancel all prepared writes;1 - write all pending prepared writes)
    :type flags: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    request = stack_connection.execute_write_req_sync(flags, connection_handle, timeout=timeout)
    if request.has_error():
        logger.debug("Execute Write Response Error")
    else:
        logger.debug("Execute Write Response Data(str): %s" % request.response.data)
    return request


def gatt_procedure_execute_write_async(stack_connection, connection_handle, flags, timeout=15 * 1000):
    """
    Sends an execute write request to the peer device with a flag to indicate the action
    for the peer device's prepared write queue and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param flags: Flags (0 - cancel all prepared writes;1 - write all pending prepared writes)
    :type flags: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    request = stack_connection.execute_write_req_async(flags, connection_handle, timeout=timeout)
    return request


def gatt_procedure_read_handle(stack_connection, connection_handle, handle, timeout=15 * 1000):
    """
    Read data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :return: Data returned from read
    :type handle: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    request = stack_connection.read_sync(handle, connection_handle, timeout=timeout)
    if not request.has_error():
        logger.debug("Request Error! Handle: %s   Response(str): %s" % (hex(handle), request.response.data))
    else:
        logger.debug("Response timed out for handle: %s" % hex(handle))
    return request


def gatt_procedure_read_handle_async(stack_connection, connection_handle, handle, timeout=15 * 1000):
    """
    Read data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :type handle: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    request = stack_connection.read_async(handle, connection_handle, timeout=timeout)
    return request


def gatt_procedure_read_multiple_handles(stack_connection, connection_handle, handles, timeout=15 * 1000):
    """
    Read data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handles: List of target handles
    :return: Data returned from read
    :type handles: list of int
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    import struct

    handle_string = ""
    for handle in handles:
        handle_string += struct.pack("<H", handle)
    request = stack_connection.read_multiple_sync(handle_string, connection_handle, timeout=timeout)
    if not request.has_error():
        logger.debug("Request Error! Response(str): %s" % (request.response.data))
    else:
        logger.debug("Response timed out")
    return request


def gatt_procedure_read_multiple_handles_async(stack_connection, connection_handle, handles, timeout=15 * 1000):
    """
    Read data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handles: Target handle
    :type handles: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    import struct

    handle_string = ""
    for handle in handles:
        handle_string += struct.pack("<H", handle)
    request = stack_connection.read_multiple_async(handle_string, connection_handle, timeout=timeout)
    return request


def gatt_procedure_read_blob_handle(stack_connection, connection_handle, handle, offset, timeout=15 * 1000):
    """
    Read blob of data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. The GATT server will return a attribute value up to the negotiated MTU, the offset
    is used to change the start of the value sent in the packet. This is a
    synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param offset: Offset to begin attribute read
    :type offset: int
    :return: Data returned from read
    :type handle: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    request = stack_connection.read_blob_sync(handle, offset, connection_handle, timeout=timeout)
    if not request.has_error():
        logger.debug("Request Error! Handle: %s   Response(str): %s" % (hex(handle), request.response.data))
    else:
        logger.debug("Response timed out for handle: %s" % hex(handle))
    return request


def gatt_procedure_read_blob_handle_async(stack_connection, connection_handle, handle, offset, timeout=15 * 1000):
    """
   Read blob of data from target attribute handle and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. The GATT server will return a attribute value up to the negotiated MTU, the offset
    is used to change the start of the value sent in the packet.
    This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param handle: Target handle
    :param offset: Offset to begin attribute read
    :type offset: int
    :type handle: int - base 10
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    request = stack_connection.read_blob_async(handle, offset, connection_handle, timeout=timeout)
    return request


def gatt_procedure_read_uuid(stack_connection, connection_handle, uuid, timeout=15 * 1000):
    """
    Read data from target GATT entity with the specified UUID and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is a synchronous function that waits until the issued request
    receives a response, an error, or reaches the specified timeout.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param uuid: Target UUID
    :type uuid: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """
    from blesuite.pybt.gatt import UUID

    if uuid.type == UUID.TYPE_16:
        logger.debug("16 bit UUID!")
        request = stack_connection.read_by_type_sync(uuid, connection_handle, timeout=timeout)
    elif uuid.type == UUID.TYPE_128:
        logger.debug("128 bit UUID!")
        request = stack_connection.read_by_type_sync_128bit(uuid, connection_handle, timeout=timeout)

    return request


def gatt_procedure_read_uuid_async(stack_connection, connection_handle, uuid, timeout=15 * 1000):
    """
    Read data from target GATT entity with the specified UUID and returns a GATTRequest object that contains either
    a GATTResponse for a GATTError. This is an asynchronous function that issues the request
    and returns a GATTRequest object. The GATTRequest can then be manually managed using the
    has_response and has_error class instance functions to wait for a response.

    :param stack_connection: Connection to the pybt core that allows us to send BLE packets
    :type stack_connection: blesuite.pybt.core.Connection
    :param connection_handle: Connection handle to send the request to
    :type connection_handle: int
    :param uuid: Target UUID
    :type uuid: str
    :param timeout: Timeout for the ATT request (miliseconds)
    :type timeout: int
    :rtype: blesuite.pybyt.core.GATTRequest
    :return: GATTRequest object
    """

    from blesuite.pybt.gatt import UUID

    if uuid.type == UUID.TYPE_16:
        logger.debug("16 bit UUID!")
        request = stack_connection.read_by_type_async(uuid, connection_handle, timeout=timeout)
    elif uuid.type == UUID.TYPE_128:
        logger.debug("128 bit UUID!")
        request = stack_connection.read_by_type_async_128bit(uuid, connection_handle, timeout=timeout)
    return request


def gatt_procedure_discover_primary_services(connection_manager, connection, device):
    """
    Scans device associated with BLEConnection for all primary services
    and stores them in the provided BLEDevice.

    :param connection_manager: BLEConnectionManager that can send request to the peer device associated with the supplied connection.
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection that is associated with the target peer device
    :type connection: BLEConnection
    :param device: BLEDevice object that represents the peer device
    :type device: BLEDevice
    :return: Poplulated BLEDevice
    :rtype: BLEDevice
    """

    from blesuite.pybt.gatt import UUID
    import struct

    bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
    next_start_handle = 0x0001
    connection_handle = connection.connection_handle

    while True:
        if not connection_manager.is_connected(connection):
            logger.debug("Primary service discovery: device not connected! Reconnecting...")
            connection_manager.connect(connection)
        request = connection_manager.stack_connection.read_by_group_type_sync(next_start_handle, 0xffff, UUID(0x2800),
                                                                              connection_handle)
        if request.has_error():
            logger.debug("Primary service discovery error when reading from handle:%s, "
                         "continuing" % hex(next_start_handle))
            break
        logger.debug("Response received. Stored packet len: %s", request.response.pkt.length)
        length = request.response.pkt.length
        service_data = request.response.pkt.data
        next_start_handle = None
        if length == 6:  # 4 byte uuid, 2 2-byte handles
            logger.debug("We've got services with 16-bit UUIDs!")
            services = []
            i = 0
            end_loop = False
            while i < len(service_data):
                services.append(service_data[i:i+6])
                i += 6
            # print "Services:", services
            for service in services:
                start = struct.unpack("<h", service[:2])[0]
                end = struct.unpack("<h", service[2:4])[0]
                uuid_16 = struct.unpack("<h", service[4:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if end == -1:
                    end = 0xffff
                if start == -1:
                    start = 0xffff
                device.add_service(start, end, uuid_128)
                if end >= 0xFFFF or end < 0:
                    end_loop = True
                if next_start_handle is None or end >= next_start_handle:
                    next_start_handle = end + 1
            if end_loop:
                logger.debug("End of primary service discovery!")
                break
        elif length == 20:  # 16 byte uuid, 2 2-byte handles
            logger.debug("We've got services with 128-bit UUIDs!")
            start = struct.unpack("<h", service_data[:2])[0]
            end = struct.unpack("<h", service_data[2:4])[0]
            uuid_128 = struct.unpack("<QQ", service_data[4:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if end == -1:
                end = 0xffff
            if start == -1:
                start = 0xffff
            device.add_service(start, end, uuid_128)
            if end >= 0xFFFF or end < 0:
                logger.debug("End of primary service discovery!")
                break
            next_start_handle = end + 1
        else:
            logger.error("UNEXPECTED PRIMARY SERVICE DISCOVERY RESPONSE. BAILING")
            break

    return device


def gatt_procedure_discover_secondary_services(connection_manager, connection, device):
    """
    Scans device associated with BLEConnection for all secondary services
    and stores them in the provided BLEDevice.

    :param connection_manager: BLEConnectionManager that can send request to the peer device associated with the supplied connection.
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection that is associated with the target peer device
    :type connection: BLEConnection
    :param device: BLEDevice object that represents the peer device
    :type device: BLEDevice
    :return: Poplulated BLEDevice
    :rtype: BLEDevice
    :return:
    """

    from blesuite.pybt.gatt import UUID
    import struct

    bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
    next_start_handle = 0x0001
    connection_handle = connection.connection_handle

    while True:
        if not connection_manager.is_connected(connection):
            logger.debug("Secondary service discovery: device not connected! Reconnecting...")
            connection_manager.connect(connection)
        request = connection_manager.stack_connection.read_by_group_type_sync(next_start_handle, 0xffff, UUID(0x2801),
                                                                              connection_handle)
        if request.has_error():
            logger.debug("Secondary service discovery error when reading from handle:%s, "
                         "continuing" % hex(next_start_handle))
            break
        logger.debug("Response received. Stored packet len: %s", request.response.pkt.length)
        length = request.response.pkt.length
        service_data = request.response.pkt.data
        next_start_handle = None
        if length == 6:  # 4 byte uuid, 2 2-byte handles
            logger.debug("We've got services with 16-bit UUIDs!")
            services = []
            i = 0
            end_loop = False
            while i < len(service_data):
                services.append(service_data[i:i+6])
                i += 6
            # print "Services:", services
            for service in services:
                start = struct.unpack("<h", service[:2])[0]
                end = struct.unpack("<h", service[2:4])[0]
                uuid_16 = struct.unpack("<h", service[4:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if end == -1:
                    end = 0xffff
                if start == -1:
                    start = 0xffff
                device.add_service(start, end, uuid_128)
                if end >= 0xFFFF or end < 0:
                    end_loop = True
                if next_start_handle is None or end >= next_start_handle:
                    next_start_handle = end + 1
            if end_loop:
                logger.debug("End of Secondary service discovery!")
                break
        elif length == 20:  # 16 byte uuid, 2 2-byte handles
            logger.debug("We've got services with 128-bit UUIDs!")
            start = struct.unpack("<h", service_data[:2])[0]
            end = struct.unpack("<h", service_data[2:4])[0]
            uuid_128 = struct.unpack("<QQ", service_data[4:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if end == -1:
                end = 0xffff
            if start == -1:
                start = 0xffff
            device.add_service(start, end, uuid_128)
            if end >= 0xFFFF or end < 0:
                logger.debug("End of secondary service discovery!")
                break
            next_start_handle = end + 1
        else:
            logger.error("UNEXPECTED SECONDARY SERVICE DISCOVERY RESPONSE. BAILING")
            break

    return device


def gatt_procedure_discover_characteristics(connection_manager, connection, device):
    """
    Scans device associated with BLEConnection for all characteristics
    and stores them in the provided BLEDevice.

    :param connection_manager: BLEConnectionManager that can send request to the peer device associated with the supplied connection.
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection that is associated with the target peer device
    :type connection: BLEConnection
    :param device: BLEDevice object that represents the peer device
    :type device: BLEDevice
    :return: Poplulated BLEDevice
    :rtype: BLEDevice
    """
    from blesuite.pybt.gatt import UUID
    import struct

    bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
    next_start_handle = 0x0001
    connection_handle = connection.connection_handle
    
    while True:
        if not connection_manager.is_connected(connection):
            logger.debug("Characteristic discovery: device not connected! Reconnecting...")
            connection_manager.connect(connection)
        # Note: This is not exactly the procedure described in the spec (BLUETOOTH SPECIFICATION Version 5.0 |
        # Vol 3, Part G page 2253-4), but it's independent of a service scan.
        request = connection_manager.stack_connection.read_by_type_sync(UUID(0x2803), start=next_start_handle,
                                                                        end=0xffff,
                                                                        conn_handle=connection_handle)
        if request.has_error():
            logger.debug("Characteristic discovery error when reading from handle:%s, "
                         "continuing" % hex(next_start_handle))
            break
        characteristic_data = request.response.pkt.data
        length = int(characteristic_data[0].encode('hex'), 16)
        characteristic_data = characteristic_data[1:]
        logger.debug("Response received. Stored packet len: %s", length)
        next_start_handle = None
        if length == 7:  # 4byte uuid, 2 2-byte handles, 1 byte permission
            logger.debug("We've got services with 16-bit UUIDs!")
            characteristics = []
            i = 0
            end_loop = False
            while i < len(characteristic_data):
                characteristics.append(characteristic_data[i:i+7])
                i += 7
            # print "Services:", services
            for characteristic in characteristics:
                handle = struct.unpack("<h", characteristic[:2])[0]
                perm = struct.unpack("<B", characteristic[2:3])[0]
                value_handle = struct.unpack("<h", characteristic[3:5])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                uuid_16 = struct.unpack("<h", characteristic[5:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                if value_handle == -1:
                    value_handle = 0xffff
                device.add_characteristic(value_handle, handle, uuid_128, perm)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if next_start_handle is None or handle > next_start_handle:
                    next_start_handle = handle + 1
            if end_loop:
                logger.debug("End of characteristic discovery!")
                break
        elif length == 21:  # 16 byte uuid, 2 2-byte handles, 1 byte permission
            logger.debug("We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<h", characteristic_data[:2])[0]
            perm = struct.unpack("<B", characteristic_data[2:3])[0]
            value_handle = struct.unpack("<h", characteristic_data[3:5])[0]
            uuid_128 = struct.unpack("<QQ", characteristic_data[5:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if handle == -1:
                handle = 0xffff
            if value_handle == -1:
                value_handle = 0xffff
            device.add_characteristic(value_handle, handle, uuid_128, perm)
            if handle >= 0xFFFF or handle < 0:
                logger.debug("End of characteristic discovery!")
                break
            next_start_handle = handle + 1
        else:
            logger.error("UNEXPECTED CHARACTERISTIC DISCOVERY RESPONSE. BAILING. Length:%s" % length)
            break

    return device


def gatt_procedure_discover_includes(connection_manager, connection, device):
    """
    Scans device associated with BLEConnection for all service includes
    and stores them in the provided BLEDevice.

    :param connection_manager: BLEConnectionManager that can send request to the peer device associated with the supplied connection.
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection that is associated with the target peer device
    :type connection: BLEConnection
    :param device: BLEDevice object that represents the peer device
    :type device: BLEDevice
    :return: Poplulated BLEDevice
    :rtype: BLEDevice
    :return:
    """
    from blesuite.pybt.gatt import UUID
    import struct

    bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
    next_start_handle = 0x0001
    connection_handle = connection.connection_handle

    while True:
        if not connection_manager.is_connected(connection):
            logger.debug("Include discovery: device not connected! Reconnecting...")
            connection_manager.connect(connection)
        # Note: This is not exactly the procedure described in the spec (BLUETOOTH SPECIFICATION Version 5.0 |
        # Vol 3, Part G page 2253-4), but it's independent of a service scan.
        request = connection_manager.stack_connection.read_by_type_sync(UUID(0x2802), start=next_start_handle,
                                                                        end=0xffff,
                                                                        conn_handle=connection_handle)
        if request.has_error():
            logger.debug("Include discovery error when reading from handle:%s, "
                         "continuing" % hex(next_start_handle))
            break
        include_data = request.response.pkt.data
        length = int(include_data[0].encode('hex'), 16)
        include_data = include_data[1:]
        logger.debug("Response received. Stored packet len: %s", length)
        next_start_handle = None
        if length == 8:  # 2 byte handle of this attribute, 2 byte uuid, 2 end group handle, 2 byte handle of included service declaration
            logger.debug("We've got includes with 16-bit UUIDs!")
            includes = []
            i = 0
            end_loop = False
            while i < len(include_data):
                includes.append(include_data[i:i + 7])
                i += 7
            # print "Services:", services
            for incl in includes:
                handle = struct.unpack("<H", incl[:2])[0]
                included_att_handle = struct.unpack("<H", incl[2:4])[0]
                end_group_handle = struct.unpack("<H", incl[4:6])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                included_service_uuid_16 = struct.unpack("<H", incl[6:])[0]
                #conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                #uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                #                      conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                #uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                device.add_include(handle, included_att_handle, end_group_handle, included_service_uuid_16)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if next_start_handle is None or handle > next_start_handle:
                    next_start_handle = handle + 1
            if end_loop:
                logger.debug("End of include discovery!")
                break
        elif length == 6:  # 2 byte handle of this attribute, 2 end group handle, 2 byte handle of included service declaration
            logger.debug("We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<H", include_data[:2])[0]
            included_att_handle = struct.unpack("<H", include_data[2:4])[0]
            end_group_handle = struct.unpack("<H", include_data[4:6])[0]
            if handle == -1:
                handle = 0xffff
            device.add_include(handle, included_att_handle, end_group_handle, None)
            if handle >= 0xFFFF or handle < 0:
                logger.debug("End of include discovery!")
                break
            next_start_handle = handle + 1
        else:
            logger.error("UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length:%s" % length)
            break

    return device


def gatt_procedure_discover_descriptors(connection_manager, connection, device):
    """
    Scans device associated with BLEConnection for all characteristic descriptors
    and stores them in the provided BLEDevice.

    :param connection_manager: BLEConnectionManager that can send request to the peer device associated with the supplied connection.
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection that is associated with the target peer device
    :type connection: BLEConnection
    :param device: BLEDevice object that represents the peer device.
    :type device: BLEDevice
    :return: Poplulated BLEDevice
    :rtype: BLEDevice
    """
    import struct
    # CHARACTERISTICS REQUIRED!
    bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
    connection_handle = connection.connection_handle
    
    for i, service in enumerate(device.services):
        for j, characteristic in enumerate(service.characteristics):
            start = characteristic.handle + 1
            if j >= len(service.characteristics) - 1:
                if i >= len(device.services) - 1:
                    end = service.end
                else:
                    end = device.services[i+1].start - 1
            else:
                end = service.characteristics[j+1].handle - 1

            if end == -1 or end > 0xffff:
                end = 0xffff
            if start == -1:
                start = 0xffff
            
            if not connection_manager.is_connected(connection):
                logger.debug("Descriptor discovery: device not connected! Reconnecting...")
                connection_manager.connect(connection)
            request = connection_manager.stack_connection.find_information_sync(start, end, connection_handle)
            if request.has_error():
                logger.debug("Descriptor discovery error when reading from handle:%s, "
                             "continuing" % hex(start))
                continue

            data = request.response.pkt.data
            uuid_format = request.response.pkt.format
            if uuid_format == 1:  # 16 bit uuid
                mark = 0
                descriptors = []
                while mark < len(data):
                    descriptors.append(data[mark:mark+4])  # 2 byte handle, 2 byte uuid
                    mark += 4
                for desc in descriptors:
                    handle = struct.unpack("<h", desc[:2])[0]
                    uuid_16 = struct.unpack("<h", desc[2:])[0]
                    conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                    uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                           conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                    uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16],
                                         uuid_128[16:20], uuid_128[20:]))
                    characteristic.add_descriptor_with_data(handle, uuid_128, None)

            elif uuid_format == 2:  # 128-bit uuid
                handle = struct.unpack("<h", data[:2])[0]
                uuid_128 = struct.unpack("<QQ", data[2:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))

                characteristic.add_descriptor_with_data(handle, uuid_128, None)
    return device
