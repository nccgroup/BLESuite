import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def blesuite_smart_scan(connection_manager, connection, device, look_for_device_info=True, attempt_desc_read=False,
                        timeout=None):
    """
    Performs a Smart Scan on the specified BTLE address using the specified adapter.
    This scan includes queries for device information, services, characteristics, and a comprehensive
    list of characteristic descriptors available.

    :param connection_manager: Connection manager for target BLE device
    :type connection_manager: BLEConnectionManager
    :param connection: BLEConnection associated with the target device
    :type connection: BLEConnection
    :param device: BLEDevice object to populate with scan results
    :type device: BLEDevice
    :param look_for_device_info: Flag that indicates the scan to look for common BLE device characteristics
    :type look_for_device_info: bool
    :param attempt_desc_read: Flag that indicates the scan should attempt to read from each discovered attribute
    :type attempt_desc_read: bool
    :param timeout: Timeout for each ATT request (milliseconds)
    :type timeout: int
    :return: Device object that represents scanned BLE device
    :rtype: BLEDevice
    """
    device_information_query_list = [
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

    device = connection_manager.gatt_discover_primary_services(connection, device)
    device = connection_manager.gatt_discover_secondary_services(connection, device)
    device = connection_manager.gatt_discover_characteristics(connection, device)
    # This maps relationships between a service that includes another service within them.
    device = connection_manager.gatt_discover_includes(connection, device)

    device = connection_manager.gatt_discover_descriptors(connection, device)

    # scan for device information
    if look_for_device_info:
        logger.debug("Querying device for basic information")
        for query in device_information_query_list:

            if timeout is None:
                request = connection_manager.gatt_read_uuid(connection, query[1])
            else:
                request = connection_manager.gatt_read_uuid(connection, query[1], timeout)

            if request.has_error():
                device.add_device_info(query[0], query[1], None, [request.get_error_message()])
            else:
                device.add_device_info(query[0], query[1], request.response.handle, [request.response.data])

    if attempt_desc_read:
        # read descriptors
        for service in device.services:
            for characteristic in service.characteristics:
                for desc in characteristic.descriptors:
                    # this can miss things, need to revert to reading all possible descriptors in characteristic
                    # handle to beginning of next char handle (or end service handle)
                    # ran into case where during descriptor discovery, device reported "attribute not found",
                    # when it really existed. Other cases included it not returning
                    # attributes that exist
                    successful = False
                    reconnected = False
                    tries = 0
                    while not successful:
                        if not connection_manager.is_connected(connection):
                            logger.debug("Smart Scan: device is not connected! Reconnecting...")
                            connection_manager.connect(connection)
                            reconnected = True
                        if timeout is None:
                            request = connection_manager.gatt_read_handle(connection, desc.handle)
                        else:
                            request = connection_manager.gatt_read_handle(connection, desc.handle, timeout)
                        if request.has_error():
                            desc.value = [request.get_error_message()]
                            # extra logic to retry reading descriptors if we
                            # see a timeout error (issued by us) and we had to reconnect
                            # to the device. Covers case where device disconnects and we
                            # re-connect mid-read
                            if request.error_object.ecode is None and reconnected:
                                logger.debug("Smart Scan: Descriptor read time out and we reconnected during the read, "
                                             "retrying. Try: %d" % tries)
                                reconnected = False
                                tries += 1
                                if tries >= 3:
                                    successful = True
                                continue
                        else:
                            desc.value = [request.response.data]
                        successful = True

    return device
