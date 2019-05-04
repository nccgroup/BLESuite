import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.bluetooth import *

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

ATT_OPCODE_NAME = {
        0x01: "Error Response",
        0x02: "Exchange MTU Request",
        0x03: "Exchange MTU Response",
        0x04: "Find Information Request",
        0x05: "Find Information Response",
        0x06: "Find By Type Value Request",
        0x07: "Find By Type Value Response",
        0x08: "Read By Type Request",
        0x09: "Read By Type Response",
        0x0a: "Read Request",
        0x0b: "Read Response",
        0x0c: "Read Blob Request",
        0x0d: "Read Blob Response",
        0x0e: "Read Multiple Request",
        0x0f: "Read Multiple Response",
        0x10: "Read By Group Type Request",
        0x11: "Read By Group Type Response",
        0x12: "Write Request",
        0x13: "Write Response",
        0x52: "Write Command",
        0x16: "Prepare Write Request",
        0x17: "Prepare Write Response",
        0x18: "Execute Write Request",
        0x19: "Execute Write Response",
        0x1b: "Handle Value Notification",
        0x1d: "Handle Value Indication",
        0x1e: "Handle Value Confirmation",
        0xd2: "Signed Write Command"
    }

ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS = {
        "error_response": (None, 0x01),
        "exchange_MTU": (0x02, 0x03),
        "find_information": (0x04, 0x05),
        "find_by_type_value": (0x06, 0x07),
        "read_by_type": (0x08, 0x09),
        "read": (0x0a, 0x0b),
        "read_blob": (0x0c, 0x0d),
        "read_multiple": (0x0e, 0x0f),
        "read_by_group_type": (0x10, 0x11),
        "write": (0x12, 0x13),
        "prepare_write": (0x16, 0x17),
        "execute_write": (0x18, 0x19),
        "notification": (0x1b, None),
        "indication": (0x1d, 0x1e),
        "write_command": (0x52, None),
        "signed_write_command": (0xd2, None)
    }

ATT_ERROR_CODE_NAME = {
        -1: "Malformed Packet",  # self-defined
        0x01: "Invalid Handle",
        0x02: "Read Not Permitted",
        0x03: "Write Not Permitted",
        0x04: "Invalid PDU",
        0x05: "Insufficient Authentication",
        0x06: "Request Not Supported",
        0x07: "Invalid Offset",
        0x08: "Insufficient Authorization",
        0x09: "Prepare Queue Full",
        0x0a: "Attribute Not Found",
        0x0b: "Attribute Not Long",
        0x0c: "Insufficient Encryption Key Size",
        0x0d: "Invalid Attribute Value Length",
        0x0e: "Unlikely Error",
        0x0f: "Insufficient Encryption",
        0x10: "Unsupported Group Type",
        0x11: "Insufficient Resources"
    }

ATT_PDU_OPCODE_BY_NAME = {name: opcode for opcode, name in ATT_OPCODE_NAME.iteritems()}
ROLE_TYPE_CENTRAL = 0x00
ROLE_TYPE_PERIPHERAL = 0x01


def get_att_pdu_request_opcodes():
    req_opcodes = [opcode_tuple[0] for key, opcode_tuple in ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS.iteritems()]
    req_opcodes.remove(None)
    return req_opcodes


def get_att_pdu_response_opcodes():
    resp_opcodes = [opcode_tuple[1] for key, opcode_tuple in ATT_OPCODE_REQUEST_RESPONSE_ASSOCIATIONS.iteritems()]
    resp_opcodes.remove(None)
    return resp_opcodes


class AttributeProtocol:

    def __init__(self, stack, security_manager_protocol, mtu=23, gatt_server=None, require_encryption=False,
                 event_hook=None):
        self.stack = stack
        self.gatt_server = gatt_server
        self.require_encryption = require_encryption
        self.mtu = mtu
        self.security_manager_protocol = security_manager_protocol
        self.encrypted = False
        self.event_hook = event_hook
        self.negotiated_mtu_by_address = {}

    def __del__(self):
        self.stack = None

    def set_mtu(self, mtu):
        self.mtu = mtu
        if self.gatt_server is not None:
            self.gatt_server.set_mtu(mtu)

    def send(self, body, conn_handle, length=None):
        self.stack.raw_att(ATT_Hdr() / body, conn_handle, length=length)

    def send_raw(self, body, conn_handle, length=None):
        self.stack.raw_att(body, conn_handle, length=length)

    def marshall_request(self, conn_handle, req_pkt, peer_address):
        security_manager = self.security_manager_protocol.security_managers[peer_address]
        is_connection_encrypted = self.security_manager_protocol.get_connection_encryption_status(conn_handle)
        connection_permission = security_manager
        log.debug("Is connection currently encrypted? : %s" % is_connection_encrypted)
        log.debug("Security mode for peer address: %s mode: %d level: %d" % (peer_address,
                                                                             security_manager.get_security_mode_mode(),
                                                                             security_manager.get_security_mode_level())
                  )
        opcode = req_pkt.opcode
        p = None
        if opcode == ATT_PDU_OPCODE_BY_NAME['Exchange MTU Request']:# 0x02:
            self.send(ATT_Exchange_MTU_Response(mtu=self.mtu), conn_handle)
            log.debug("Received MTU Exchange Request. Peer MTU: %d Our MTU: %d" % (
                req_pkt.mtu, self.mtu
            ))
            new_mtu = (req_pkt.mtu if req_pkt.mtu < self.mtu else self.mtu)
            log.debug("New MTU: %d" % new_mtu)
            self.negotiated_mtu_by_address[peer_address] = new_mtu
            if self.gatt_server is not None:
                # TODO: Reminder. We need to overwrite mtu in gatt_server if user sets it after initialization
                self.gatt_server.set_mtu(self.mtu)
        # Handle Notification and Indications processed here since the requests are initiated by the peer.
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Handle Value Notification']:
            log.debug("Received Handle Value Notification. From handle: %d with value: %s" % (
                req_pkt.gatt_handle, req_pkt.value
            ))

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Handle Value Indication']:
            p = ATT_PDU_OPCODE_BY_NAME["Handle Value Confirmation"]
            log.debug("Received Handle Value Indication. From handle: %d with value: %s" % (
                req_pkt.gatt_handle, req_pkt.value
            ))

        elif self.gatt_server is None:
            if 'gatt_handle' in req_pkt.fields.keys():
                p = ATT_Error_Response(request=opcode, handle=req_pkt.gatt_handle, ecode=0x06)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.start, ecode=0x06)

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Find Information Request']:#0x04: # find information request
            success, body = self.gatt_server.find_information(req_pkt.start, req_pkt.end)
            if success:
                p = ATT_Find_Information_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.start, ecode=body)
            # self.send(p, conn_handle)

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Find By Type Value Request']:#0x06:  # find by type value request
            success, body = self.gatt_server.find_by_type_value(req_pkt.start, req_pkt.end, req_pkt.uuid, req_pkt.data)
            if success:
                p = ATT_Find_By_Type_Value_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.start, ecode=body)
            # self.send(p, conn_handle)

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Read By Type Request']:#0x08:  # read by type
            success, body = self.gatt_server.read_by_type(req_pkt.start, req_pkt.end, req_pkt.uuid,
                                                          connection_permission, is_connection_encrypted)
            if success:
                p = ATT_Read_By_Type_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.start, ecode=body)

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Read Request']:#0x0a:  # read request
            log.debug("Received read request for handle: %d" % req_pkt.gatt_handle)
            success, body = self.gatt_server.read(req_pkt.gatt_handle, connection_permission, is_connection_encrypted)
            if success:
                p = ATT_Read_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.gatt_handle, ecode=body)
            # self.send(p, conn_handle)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Read Blob Request']:
            log.debug("Received read blob request for handle: %d with offset %d" % (
                req_pkt.gatt_handle, req_pkt.offset
            ))
            success, body = self.gatt_server.read_blob(req_pkt.gatt_handle, req_pkt.offset, connection_permission,
                                                       is_connection_encrypted)
            if success:
                p = ATT_Read_Blob_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.gatt_handle, ecode=body)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Read Multiple Request']:
            log.debug("Received read multiple request for handles: %s" % req_pkt.handles.encode('hex'))
            handles = [req_pkt.handles[i:i+2] for i in range(0, len(req_pkt.handles), 2)]
            success, body, error_handle = self.gatt_server.read_multiple(handles, connection_permission,
                                                                         is_connection_encrypted)
            if success:
                p = ATT_Read_Multiple_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=error_handle, ecode=body)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Read By Group Type Request']:#0x10:  # read by group type
            success, body = self.gatt_server.read_by_group_type(req_pkt.start, req_pkt.end, req_pkt.uuid,
                                                                connection_permission, is_connection_encrypted)
            if success:
                p = ATT_Read_By_Group_Type_Response(body)
            else:
                p = ATT_Error_Response(request=opcode, handle=req_pkt.start, ecode=body)

        elif opcode == ATT_PDU_OPCODE_BY_NAME['Write Request']:#0x12: # write request
            log.debug("Received write request for handle: %d with data: %s" % (
                req_pkt.gatt_handle, req_pkt.data))
            gatt_handle = req_pkt.gatt_handle
            should_write = True
            data = req_pkt.data
            if self.event_hook is not None:
                should_write, gatt_handle, data = self.event_hook.att_write_hook(gatt_handle, data)
            if should_write:
                success, body = self.gatt_server.write(gatt_handle, data, connection_permission,
                                                       is_connection_encrypted)

                if success:
                    p = ATT_Write_Response()
                else:
                    p = ATT_Error_Response(request=opcode, handle=gatt_handle, ecode=body)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Prepare Write Request']:
            log.debug('Received prepare write request')
            gatt_handle = req_pkt.gatt_handle
            offset = req_pkt.offset
            data = req_pkt.data
            should_write = True
            if self.event_hook is not None:
                should_write, gatt_handle, offset, data = self.event_hook.att_prepare_queued_write_hook(gatt_handle,
                                                                                                        offset, data)
            if should_write:
                success, body = self.gatt_server.prepare_write(gatt_handle, offset, data,
                                                               connection_permission, is_connection_encrypted)
                if success:
                    p = ATT_Prepare_Write_Response(body)
                else:
                    p = ATT_Error_Response(request=opcode, handle=gatt_handle, ecode=body)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Execute Write Request']:
            log.debug('Received execute write request')
            flags = req_pkt.flags
            should_execute = True
            if self.event_hook is not None:
                should_execute, flags = self.event_hook.att_execute_queued_write_hook(flags)
            if should_execute:
                success, body = self.gatt_server.execute_write(flags)
                if success:
                    p = ATT_Execute_Write_Response()
                else:
                    # TODO: Verify what handle we're supposed to return in the error here
                    p = ATT_Error_Response(request=opcode, handle=0x00, ecode=body)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Write Command']:#0x52: # write command
            log.debug("Received write command for handle: %d with data: %s" % (
                req_pkt.gatt_handle, req_pkt.data))
            gatt_handle = req_pkt.gatt_handle

            should_write = True
            data = req_pkt.data
            if self.event_hook is not None:
                should_write, gatt_handle, data = self.event_hook.att_write_hook(gatt_handle, data)
            if should_write:
                # Success and body aren't used since write command doesn't result in a response packet
                success, body = self.gatt_server.write(gatt_handle, data, connection_permission,
                                                       is_connection_encrypted)
        elif opcode == ATT_PDU_OPCODE_BY_NAME['Signed Write Command']:
            log.debug('Received signed write command')
            log.debug('Command not supported')
            p = ATT_Error_Response(request=opcode, ecode=0x06)

        else:
            log.debug("Received unrecognized request opcode: %s" % (opcode))
            p = ATT_Error_Response(request=opcode, ecode=0x06)

        if p is not None:
            should_send = True
            if self.event_hook is not None:
                should_send, p = self.event_hook.att_response_hook(req_pkt, p)
            if should_send:
                self.send(p, conn_handle)

    def raw_att(self, body, conn_handle):
        self.send_raw(body, conn_handle)

    def exchange_mtu(self, mtu, conn_handle):
        self.send(ATT_Exchange_MTU_Request(mtu=mtu), conn_handle)

    def read_by_group_type(self, start, end, uuid, conn_handle):
        self.send(ATT_Read_By_Group_Type_Request(start=start, end=end, uuid=uuid), conn_handle)

    def read_by_type(self, start, end, uuid, conn_handle):
        self.send(ATT_Read_By_Type_Request(start=start, end=end, uuid=uuid), conn_handle)

    def read_by_type_128bit(self, start, end, uuid1, uuid2, conn_handle):
        self.send(ATT_Read_By_Type_Request_128bit(start=start, end=end, uuid1=uuid1, uuid2=uuid2), conn_handle)

    def read(self, handle, conn_handle):
        self.send(ATT_Read_Request(gatt_handle=handle), conn_handle)

    def read_blob(self, handle, offset, conn_handle):
        self.send(ATT_Read_Blob_Request(gatt_handle=handle, value_offset=offset), conn_handle)

    def read_multiple(self, handles, conn_handle):
        self.send(ATT_Read_Multiple_Request(handles=handles), conn_handle)

    def write_req(self, handle, value, conn_handle):
        self.send(ATT_Write_Request(gatt_handle=handle, data=value), conn_handle)

    def write_cmd(self, handle, value, conn_handle):
        self.send(ATT_Write_Command(gatt_handle=handle, data=value), conn_handle)

    def prepare_write_req(self, handle, value, offset, conn_handle):
        self.send(ATT_Prepare_Write_Request(gatt_handle=handle, offset=offset, data=value), conn_handle)

    def execute_write_req(self, flags, conn_handle):
        self.send(ATT_Execute_Write_Request(flags=flags), conn_handle)

    def write_cmd(self, handle, value, conn_handle):
        self.send(ATT_Write_Command(gatt_handle=handle, data=value), conn_handle)

    def find_information(self, conn_handle, start=0x0000, end=0xffff):
        self.send(ATT_Find_Information_Request(start=start, end=end), conn_handle)
