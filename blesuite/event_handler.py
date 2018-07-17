from blesuite.pybt.gap import GAP
import blesuite.pybt.att as att
import logging

log = logging.getLogger(__name__)
# log.addHandler(logging.NullHandler())


class BTEventHandler(object):
    """
    BTEventHandler is a event handling class passed to the BLEConnectionManager in order to
    have user-controlled callbacks that are called when BLE events occur (ATT, SMP, L2CAP, Connection, scan, metadata,
    and disconnect event). This class provides the skeleton for functions called by the stack when an event
    is received. For instance, when an ATT packet is received, the stack will process the packet and other ATT hooks,
    then trigger supplied BTEventHandler instance BTEventHandler.on_att_event(connection_handle, data)

    :param connection_manager: BLEConnectionManager instance that allows the user to send packets whilst
    processing an event hook trigger.
    :type connection_manager: BLEConnectionManager
    """

    def __init__(self, connection_manager):
        self.connection_manager = connection_manager

    def __del__(self):
        self.connection_manager = None

    def on_scan_event(self, address, address_type, data):
        """
        Called when a scan event is received by the stack.

        :param address: Address of the seen peer device
        :type address: str
        :param address_type: Address type of the seen peer device
        :type address_type: int
        :param data: GAP data from the peer device advertisement packet
        :type data: list of strings or a single string
        :return:
        :rtype:
        """
        log.debug("Saw %s (%s)" % (address, "public" if address_type == 0 else "random"))
        if len(data) > 0:
            try:
                gap = GAP()
                if isinstance(data, list):
                    log.debug("data was list!")
                    for i, j in enumerate(data):
                        gap.decode(str(data[i]))
                else:
                    gap.decode(data)
                log.debug("GAP: %s" % gap)
            except Exception as e:
                log.debug("Exception when reading GAP: %s" % e)
        return

    def on_metadata_event(self, status, connection_handle, meta, address, event):
        """
        Called when a metadata event is triggered by the HCI device. This represents a metadata event not
        associated with a scan or connection event.

        :param status: Status of the LE Meta Event - Sub Event
        :type status: int
        :param connection_handle: The connection handle the event was received
        :type connection_handle: int
        :param meta: The metadata
        :type meta: str
        :param address: Peer address that caused the metadata event
        :type address: str
        :param event: The sub event code
        :type event: int
        :return:
        :rtype:
        """
        log.debug("Received LE Meta packet from %s Event: %s!" % (address, event))

    def on_connect_event(self, status, connection_handle, meta, address, address_type):
        """
        Called when a metadata event is triggered by the HCI device with a Connection Compete LE sub event.

        :param status: Status of the connection
        :type status: int
        :param connection_handle: The connection handle the event was received
        :type connection_handle: int
        :param meta: The metadata
        :type meta: str
        :param address: Peer address that caused the metadata event
        :type address: str
        :param address_type: Peer address type
        :type address_type: int
        :return:
        :rtype:
        """
        log.debug("Connected to %s!" % address)
        return

    def on_disconnect_event(self, connection_handle, reason):
        """
        Called when a disconnect event is received.

        :param connection_handle: The connection handle the disconnect occurred on.
        :type connection_handle: int
        :param reason: The reason for the disconnect
        :type reason: int
        :return:
        :rtype:
        """
        log.debug("Disconnected! ConnectionHandle: %s reason: %s" % (connection_handle, reason))
        return

    def on_att_event(self, connection_handle, data):
        """
        Called when an ATT event is received (after other ATT processing and handlers have been invoked).

        :param connection_handle: Connection handle the event was received on
        :type connection_handle: int
        :param data: Packet data
        :type data: Scapy ATT packet -- scapy.layers.bluetooth -- Contains an ATT Header and an ATT body
        :return:
        :rtype:
        """
        log.debug("ATT Event Connection Handle: %s Data: %s" % (connection_handle, data))

        return

    def on_unknown_event(self, packet):
        """
        Called when an unknown event is received. Note: These are usually packet types not supported currently
        by the routing core of the stack.

        :param packet: Scapy Bluetooth packet.
        :type packet: Packet
        :return:
        :rtype:
        """
        log.debug("Unknown Event Packet: %s" % packet)
        return


class ATTSecurityHook(object):
    """
    ATTSecurityHook is used by the blesuite.pybyt.gatt to hook, modify, or overwrite security decisions
    made by the ATT database based on the current BLE connection security, the attribute properties, and
    the attribute permissions. These hooks are called after each security evaluation step has completed and allows the
    hook to view and modify the final result of the check. The hooks receive identifyin information about the target
    attribute and the association permissions and properties.
    """
    def __init__(self):
        pass

    def att_authorization_check_hook(self, att_opcode, uuid, att_property, att_read_permission, att_write_permission,
                                     connection_permission, authorization_required):
        """
        Called when an authorization check is made. This check is part of the security check workflow
        and validates that if the attribute requires authorization in order to access it, then the
        authorization procedure must succeed (implementation dependent procedure). In BLESuite, this function
        acts as the authorization procedure.

        :param att_opcode: ATT opcode of the request attempting to access the attribute
        :type att_opcode: int
        :param uuid: UUID (16-bit or 128-bit) of the target attribute
        :type uuid: blesuite.pybt.gatt.UUID object instance
        :param att_property: Attribute properties assigned to the attribute (blesuite.utils.att_utils.ATT_PROP_READ | blesuite.utils.att_utils.ATT_PROP_WRITE)
        :type att_property: int
        :param att_read_permission: Security requirements of attribute in order to read the value
        :type att_read_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param att_write_permission: Security requirements of attribute in order to write to the value
        :type att_write_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param connection_permission: Security Manager associated with the current BLE connection where the attribute is being accessed.
        :type connection_permission: blesuite.pybt.sm.SecurityManager
        :param authorization_required: Flag to indicate whether the attribute requires authorization
        :type authorization_required: bool
        :return: Result that indicates if the check passed or not (True = passed)
        :rtype: bool
        """
        check_passed = True
        log.debug("ATT Authorization check invoked. Operation: %d Target Attribute: %s ATT Property: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "Connection Security Mode: %d Connection Security Level: %d "
                  "Attribute requires authorization: %d" %
                  (att_opcode, uuid, att_property, att_read_permission.security_mode, att_read_permission.security_level,
                   att_write_permission.security_mode, att_write_permission.security_level,
                   connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level(),
                   authorization_required))
        return check_passed

    def att_authentication_check_hook(self, att_authentication_check_result,
                                      att_opcode, uuid, att_property, att_read_permission,
                                      att_write_permission, connection_permission):
        """
        Called when an authentication check is made. This check is part of the security check workflow
        and validates that the connection, on which the attribute access request is being made, has been
        authenticated. (This means that the pairing method used to establish the encrypted connection must
        be authenticated if authentication is required)

        :param att_authentication_check_result: Result of the ATT server's authentication check
        :type att_authentication_check_result: bool
        :param att_opcode: ATT opcode of the request attempting to access the attribute
        :type att_opcode: int
        :param uuid: UUID (16-bit or 128-bit) of the target attribute
        :type uuid: blesuite.pybt.gatt.UUID object instance
        :param att_property: Attribute properties assigned to the attribute (blesuite.utils.att_utils.ATT_PROP_READ | blesuite.utils.att_utils.ATT_PROP_WRITE)
        :type att_property: int
        :param att_read_permission: Security requirements of attribute in order to read the value
        :type att_read_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param att_write_permission: Security requirements of attribute in order to write to the value
        :type att_write_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param connection_permission: Security Manager associated with the current BLE connection where the attribute is being accessed.
        :type connection_permission: blesuite.pybt.sm.SecurityManager
        :return: Result that indicates if the check passed or not (True = passed)
        :rtype: bool
        """
        check_passed = att_authentication_check_result
        log.debug("ATT Authentication check invoked. Result: %d"
                  "Operation: %d Target Attribute: %s ATT Property: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "Connection Security Mode: %d Connection Security Level: %d" %
                  (att_authentication_check_result,
                   att_opcode, uuid, att_property, att_read_permission.security_mode, att_read_permission.security_level,
                   att_write_permission.security_mode, att_write_permission.security_level,
                   connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level()))
        return check_passed

    def att_encryption_check_hook(self, att_encryption_check_result,
                                  att_opcode, uuid, att_property, att_read_permission,
                                  att_write_permission, connection_permission, is_connection_encrypted):
        """
        Called when an encryption check is made. This check is part of the security check workflow
        and validates that the connection, on which the attribute access request is being made, is
        encrypted.

        :param att_encryption_check_result: Result of the ATT server's encryption check
        :type att_encryption_check_result: bool
        :param att_opcode: ATT opcode of the request attempting to access the attribute
        :type att_opcode: int
        :param uuid: UUID (16-bit or 128-bit) of the target attribute
        :type uuid: blesuite.pybt.gatt.UUID object instance
        :param att_property: Attribute properties assigned to the attribute (blesuite.utils.att_utils.ATT_PROP_READ | blesuite.utils.att_utils.ATT_PROP_WRITE)
        :type att_property: int
        :param att_read_permission: Security requirements of attribute in order to read the value
        :type att_read_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param att_write_permission: Security requirements of attribute in order to write to the value
        :type att_write_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param connection_permission: Security Manager associated with the current BLE connection where the attribute is being accessed.
        :type connection_permission: blesuite.pybt.sm.SecurityManager
        :param is_connection_encrypted: Flag to indicate whether the connection requesting access to the attribute is encrypted
        :type is_connection_encrypted: bool
        :return: Result that indicates if the check passed or not (True = passed)
        :rtype: bool
        """
        check_passed = att_encryption_check_result
        log.debug("ATT Encryption check invoked. Result: %d"
                  "Operation: %d Target Attribute: %s ATT Property: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "Connection Security Mode: %d Connection Security Level: %d Is Connection Encrypted?: %s",
                  (att_encryption_check_result,
                   att_opcode, uuid, att_property, att_read_permission.security_mode, att_read_permission.security_level,
                   att_write_permission.security_mode, att_write_permission.security_level,
                   connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level(),
                   is_connection_encrypted))
        return check_passed

    def att_operation_supported_check_hook(self, att_operation_supported_check_result,
                                           att_opcode, uuid, att_property):
        """
        Called when an ATT operation check is made. This check is part of the security check workflow
        and validates that the requested ATT operation (read, write) is supported by the target attribute.

        :param att_operation_supported_check_result: Result of the ATT server's ATT operation check
        :type att_operation_supported_check_result: bool
        :param att_opcode: ATT opcode of the request attempting to access the attribute
        :type att_opcode: int
        :param uuid: UUID (16-bit or 128-bit) of the target attribute
        :type uuid: blesuite.pybt.gatt.UUID object instance
        :param att_property: Attribute properties assigned to the attribute (blesuite.utils.att_utils.ATT_PROP_READ | blesuite.utils.att_utils.ATT_PROP_WRITE)
        :type att_property: int
        :return: Result that indicates if the check passed or not (True = passed)
        :rtype: bool
        """
        check_passed = att_operation_supported_check_result
        log.debug("ATT Operation supported check invoked. Result: %d"
                  "att_opcode: %d uuid: %s att_property: %d" % (
                      att_operation_supported_check_result, att_opcode,
                      uuid, att_property
        ))
        return check_passed

    def att_security_check_hook(self, att_operation_supported_check_result,
                                att_authorization_check_result,
                                att_encryption_check_result,
                                att_authentication_check_result,
                                att_opcode, uuid, att_property, att_read_permission, att_write_permission,
                                connection_permission, authorization_required, is_connection_encrypted):
        """
        Called when a request to access an attribute has been made by a peer before the operation
        is executed. This hook occurs at the end of the security check function that processes
        the ATT operation, authorization requirements, encryption requirements,
        and authentication requirements security checks. This hook receives all results of the security checks
        and the returned result will notify the ATT server if the operation should continue or be discarded
        with a particular error. (Errors will trigger based on the check that fails. The order of checks is
        operation, authorization, encryption, and authentication)

        :param att_operation_supported_check_result: Result of the ATT server's ATT operation check
        :type att_operation_supported_check_result: bool
        :param att_authorization_check_result: Result of the ATT server's authorization check
        :type att_authorization_check_result: bool
        :param att_encryption_check_result: Result of the ATT server's encryption check
        :type att_encryption_check_result: bool
        :param att_authentication_check_result: Result of the ATT server's authentication check
        :type att_authentication_check_result: bool
        :param att_opcode: ATT opcode of the request attempting to access the attribute
        :type att_opcode: int
        :param uuid: UUID (16-bit or 128-bit) of the target attribute
        :type uuid: blesuite.pybt.gatt.UUID object instance
        :param att_property: Attribute properties assigned to the attribute (blesuite.utils.att_utils.ATT_PROP_READ | blesuite.utils.att_utils.ATT_PROP_WRITE)
        :type att_property: int
        :param att_read_permission: Security requirements of attribute in order to read the value
        :type att_read_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param att_write_permission: Security requirements of attribute in order to write to the value
        :type att_write_permission: blesuite.pybt.sm.SecurityMode (has attributes security_level and security_mode)
        :param connection_permission: Security Manager associated with the current BLE connection where the attribute is being accessed.
        :param authorization_required: Flag to indicate whether the attribute requires authorization
        :type authorization_required: bool
        :type connection_permission: blesuite.pybt.sm.SecurityManager
        :param is_connection_encrypted: Flag to indicate whether the connection requesting access to the attribute is encrypted
        :type is_connection_encrypted: bool
        :return: Result that indicates each check has passed (order - operation, authorization, encryption, authentication)
        :rtype: tuple of bool (4 element)
        """
        log.debug("ATT Security check hook invoked. "
                  "ATT Operation supported check result: %d "
                  "ATT Authorization security check result: %d "
                  "ATT encryption security check result: %d "
                  "ATT Authentication security check result: %d "
                  "Operation: %d Target Attribute: %s ATT Property: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "ATT Read Security Mode: %d ATT Read Security Level: %d "
                  "Connection Security Mode: %d Connection Security Level: %d "
                  "Authorization required: %d "
                  "Is connection encrypted?: %s" %
                  (att_operation_supported_check_result,
                   att_authorization_check_result,
                   att_encryption_check_result,
                   att_authentication_check_result,
                   att_opcode, uuid, att_property, att_read_permission.security_mode,
                   att_read_permission.security_level,
                   att_write_permission.security_mode, att_write_permission.security_level,
                   connection_permission.get_security_mode_mode(), connection_permission.get_security_mode_level(),
                   authorization_required,
                   is_connection_encrypted))
        return (att_operation_supported_check_result,
                att_authorization_check_result,
                att_encryption_check_result,
                att_authentication_check_result)


class ATTEventHook(object):
    """
    ATTEventHook is used by blesuite.pybt.att to allow the user to hook ATT operations triggered by a peer
    ATT request. These hooks allow the user to view and/or modify outgoing ATT responses, incoming write requests,
    and incoming long write requests (prepared write and execute write).
    """

    def __init__(self):
        pass

    def att_response_hook(self, received_packet, our_response_packet):
        """
        Called before an ATT response packet is sent to a peer device. This enables the response packet to be
        viewed in order to modify read response data, send notifications/indications based on a read
        or error operation, modify error messages, or send packets to a peer device based upon
        the received packet and/or our response.

        :param received_packet: ATT request packet received from peer
        :type received_packet: scapy.layers.bluetooth ATT packet with ATT header
        :param our_response_packet: ATT response packet to be sent to our peer
        :type our_response_packet: scapy.layers.bluetooth ATT packet with ATT header
        :return: A flag to indicate whether we should send the response packet and the packet to send.
        :rtype: bool, ATT packet body (header is appended automatically)
        """
        send_packet = True
        log.debug("ATT response hook triggered. Received packet: %s Send packet: %s packet: %s" % (received_packet, send_packet, our_response_packet))
        return (send_packet, our_response_packet)

    def att_prepare_queued_write_hook(self, gatt_handle, offset, data):
        """
        Called when the peer device sends a Prepare Write request. This enables the attribute handle, offset,
        and data from the request to be viewed and/or modified. Additionally, this allows the user to
        deny the write from being performed.

        :param gatt_handle: ATT handle of the target attribute
        :type gatt_handle: int
        :param offset: Offset to begin the write operation to the prepared write queue
        :type offset: int
        :param data: Data to write to the prepared write queue
        :type data: str
        :return: A flag to indicate if the value should be written to the prepared write queue, the offset to begin the write, and the data to write
        :rtype: bool, int, int, str
        """
        write_value_to_queue = True
        log.debug("ATT queued write hook triggered. Write value to attribute pepared write queue"
                  "for attribute: %s on offset: %d with value: %s" % (hex(gatt_handle), offset, data))

        return (write_value_to_queue, gatt_handle, offset, data)

    def att_execute_queued_write_hook(self, flags):
        """
        Called when the peer device sends an Execute Write request. This enables the flag
        from the request to be viewed and/or modified. Additionally, this allows the user to
        deny the write from being performed.

        :param flags: Execute write flags
        :type flags: int
        :return: Flag to indicate that the execute write should continue and the execute write flags to pass along
        :rtype: bool, int
        """
        execute = True
        log.debug("ATT execute write hook triggered. Action: %d" % flags)

        return (execute, flags)

    def att_write_hook(self, gatt_handle, data):
        """
        Called when the peer device sends a write request. This enables the attribute handle and data
        from the request to be viewed and/or modified. Additionally, this allows the user to
        deny the write from being performed.

        :param gatt_handle: ATT handle of the target attribute
        :type gatt_handle: int
        :param data: Data to write to the attribute
        :type data: str
        :return: Flag to indicate that the write should continue, the target attribute handle, and the data to write
        :rtype: bool, int, str
        """
        write_value_to_attribute = True
        log.debug("ATT write hook triggered. Write value to attribute: %s value: %s" % (hex(gatt_handle), data))
        return (write_value_to_attribute, gatt_handle, data)