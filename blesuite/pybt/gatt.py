from struct import pack, unpack
from binascii import hexlify
from blesuite.pybt.sm import SecurityMode
from collections import OrderedDict
import logging

log = logging.getLogger(__name__)
'''
BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part F page 2176

Attribute permissions are a combination of access permissions, encryption permissions, authentication permissions 
and authorization permissions.
The following access permissions are possible:
* Readable
* Writeable
* Readable and writable
The following encryption permissions are possible:
* Encryption required
* No encryption required
The following authentication permissions are possible:
* Authentication Required
* No Authentication Required
The following authorization permissions are possible:
* Authorization Required
* No Authorization Required

BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part G page 2226

Attribute Permissions is part of the Attribute that cannot be read from or written to using the Attribute Protocol. 
It is used by the server to determine whether read or write access is permitted for a given attribute. 
Attribute Permissions are established by the GATT profile, a higher layer profile or are implementation 
specific if not specified.
'''
GATT_PERMIT_READ = 0x01
GATT_PERMIT_WRITE = 0x02
GATT_PERMIT_AUTH_READ = 0x04
GATT_PERMIT_AUTH_WRITE = 0x08

GATT_PROP_BCAST = 0x01
GATT_PROP_READ = 0x02
GATT_PROP_WRITE_NO_RSP = 0x04
GATT_PROP_WRITE = 0x08
GATT_PROP_NOTIFY = 0x10
GATT_PROP_INDICATE = 0x20
GATT_PROP_AUTHENTICATED_SIGNED_WRITES = 0x40
GATT_PROP_EXTENDED_PROPERTIES = 0x80

ATT_PROP_READ = 0x01
ATT_PROP_WRITE = 0x02


class InvalidUUIDException(Exception):
    """Base class for Invalid HandleException -- The attribute handle given was not valid on this server."""

    def __init__(self, uuid):
        self.code = 0x01
        self.name = "Invalid UUID"
        self.description = "The supplied UUID (%s) is not a valid 16-bit or 128-bit UUID. "\
                           "(ex: 2a1b or 000AA000-0BB0-10C0-80A0-00805F9B34FB" % uuid


class ATTInvalidHandleException(Exception):
    """Base class for Invalid HandleException -- The attribute handle given was not valid on this server."""

    def __init__(self):
        self.code = 0x01
        self.name = "Invalid Handle"
        self.description = "The attribute handle given was not valid on this server."


class ATTReadNotPermittedException(Exception):
    """Base class for Read Not PermittedException -- The attribute cannot be read."""

    def __init__(self):
        self.code = 0x02
        self.name = "Read Not Permitted"
        self.description = "The attribute cannot be read."


class ATTWriteNotPermittedException(Exception):
    """Base class for Write Not PermittedException -- The attribute cannot be written."""

    def __init__(self):
        self.code = 0x03
        self.name = "Write Not Permitted"
        self.description = "The attribute cannot be written."


class ATTInvalidPDUException(Exception):
    """Base class for Invalid PDUException -- The attribute PDU was invalid."""

    def __init__(self):
        self.code = 0x04
        self.name = "Invalid PDU"
        self.description = "The attribute PDU was invalid."


class ATTInsufficientAuthenticationException(Exception):
    """Base class for Insufficient AuthenticationException -- The attribute requires
    authentication before it can be read or written."""

    def __init__(self):
        self.code = 0x05
        self.name = "Insufficient Authentication"
        self.description = "The attribute requires authentication before it can be read or written."


class ATTRequestNotSupportedException(Exception):
    """Base class for Request Not SupportedException -- Attribute server does not
    support the request received from the client."""

    def __init__(self):
        self.code = 0x06
        self.name = "Request Not Supported"
        self.description = "Attribute server does not support the request received from the client."


class ATTInvalidOffsetException(Exception):
    """Base class for Invalid OffsetException -- Offset specified was past the end of the attribute."""

    def __init__(self):
        self.code = 0x07
        self.name = "Invalid Offset"
        self.description = "Offset specified was past the end of the attribute."


class ATTInsufficientAuthorizationException(Exception):
    """Base class for Insufficient AuthorizationException -- The attribute requires
    authorization before it can be read or written."""

    def __init__(self):
        self.code = 0x08
        self.name = "Insufficient Authorization"
        self.description = "The attribute requires authorization before it can be read or written."


class ATTPrepareQueueFullException(Exception):
    """Base class for Prepare Queue FullException -- Too many prepare writes have been queued."""

    def __init__(self):
        self.code = 0x09
        self.name = "Prepare Queue Full"
        self.description = "Too many prepare writes have been queued."


class ATTAttributeNotFoundException(Exception):
    """Base class for Attribute Not FoundException -- No attribute found within the given attri- bute handle range."""

    def __init__(self):
        self.code = 0x0A
        self.name = "Attribute Not Found"
        self.description = "No attribute found within the given attri- bute handle range."


class ATTAttributeNotLongException(Exception):
    """Base class for Attribute Not LongException -- The attribute cannot be read using the Read Blob Request."""

    def __init__(self):
        self.code = 0x0B
        self.name = "Attribute Not Long"
        self.description = "The attribute cannot be read using the Read Blob Request."


class ATTInsufficientEncryptionKeySizeException(Exception):
    """Base class for Insufficient Encryption Key SizeException -- The Encryption Key Size used
     for encrypting this link is insufficient."""

    def __init__(self):
        self.code = 0x0C
        self.name = "Insufficient Encryption Key Size"
        self.description = "The Encryption Key Size used for encrypting this link is insufficient."


class ATTInvalidAttributeValueLengthException(Exception):
    """Base class for Invalid Attribute Value LengthException -- The attribute value length is
    invalid for the operation."""

    def __init__(self):
        self.code = 0x0D
        self.name = "Invalid Attribute Value Length"
        self.description = "The attribute value length is invalid for the operation."


class ATTUnlikelyErrorException(Exception):
    """Base class for Unlikely ErrorException -- The attribute request that was requested has
    encountered an error that was unlikely, and therefore could not be completed as requested."""

    def __init__(self):
        self.code = 0x0E
        self.name = "Unlikely Error"
        self.description = "The attribute request that was requested has encountered an " \
                           "error that was unlikely, and therefore could not be completed as requested."


class ATTInsufficientEncryptionException(Exception):
    """Base class for Insufficient EncryptionException -- The attribute requires encryption
    before it can be read or written."""

    def __init__(self):
        self.code = 0x0F
        self.name = "Insufficient Encryption"
        self.description = "The attribute requires encryption before it can be read or written."


class ATTUnsupportedGroupTypeException(Exception):
    """Base class for Unsupported Group TypeException -- The attribute type is not a supported
    grouping attribute as defined by a higher layer specification."""

    def __init__(self):
        self.code = 0x10
        self.name = "Unsupported Group Type"
        self.description = "The attribute type is not a supported grouping attribute as " \
                           "defined by a higher layer specification."


class ATTInsufficientResourcesException(Exception):
    """Base class for Insufficient ResourcesException -- Insufficient Resources to complete the request."""

    def __init__(self):
        self.code = 0x11
        self.name = "Insufficient Resources"
        self.description = "Insufficient Resources to complete the request."


class Server:

    def __init__(self, db):
        self.services = []
        self.mtu = 23
        if db is None:
            self.db = AttributeDatabase()
        else:
            self.db = db

    def add_service(self, service):
        self.services.append(service)

    def generate_primary_gatt_service(self, uuid):
        return GATTService(UUID("2800"), uuid)

    def generate_secondary_gatt_service(self, uuid):
        return GATTService(UUID("2801"), uuid)

    def get_services(self):
        return self.services

    def set_service(self, gatt_service_list):
        self.services = gatt_service_list

    def manual_set_attribute_db(self, attribute_dictionary):
        self.db.manually_set_attribute_db_dict(attribute_dictionary)

    def debug_print_db(self):
        self.db.debug_print_db()

    def refresh_database(self, calculate_handles=True):
        '''
        ONLY USE IF WE ARE RELYING ON SERVICE LIST TO SET DB. If we are manually setting AttributeDatabase
        with a supplied dictionary, do not call this method.


        If calculate_handles is true:
        Step 1. Refresh handles for every service, characteristic
            # Refresh characteristic value before characteristic declaration inside gattcharacterisitic
            # If service contains includes, process these last
                # if processing and included service hasn't been refreshed, skip until it has
        Step 2. Build ATT database
            # Loop each service
        :return:
        '''
        self.db.attributes = {}
        service_info_for_includes = {}
        if calculate_handles:
            handle = 0x0001
            max_handle = 0xffff
            for service in self.services:
                service.start = handle
                service.handle = handle
                self.db.attributes[handle] = service.generate_attribute()
                handle += 1
                for incl in service.includes:
                    incl.handle = handle
                    self.db.attributes[handle] = incl.generate_attribute()
                    handle += 1
                for characteristic in service.characteristics:
                    characteristic.declaration.handle = handle
                    characteristic.declaration.value_attribute_handle = handle + 1
                    self.db.attributes[handle] = characteristic.declaration.generate_attribute()
                    handle += 1
                    characteristic.value_declaration.handle = handle
                    self.db.attributes[handle] = characteristic.value_declaration.generate_attribute()
                    handle += 1
                    for descriptor in characteristic.descriptors:
                        descriptor.handle = handle
                        self.db.attributes[handle] = descriptor.generate_attribute()
                        handle += 1
                service.end = handle - 1
                service_info_for_includes[service.uuid.uuid] = (service.handle, service.end)
            # Once all services added, we need to go back to update includes
            # self.value = included_service_att_handle + end_group_handle + service_uuid
            for service in self.services:
                for incl in service.includes:
                    attr = self.db.attributes[incl.handle]
                    service_uuid = incl.service_uuid
                    included_service_att_handle, end_group_handle = service_info_for_includes[service_uuid.uuid]
                    attr.included_service_att_handle = included_service_att_handle
                    attr.end_group_handle = end_group_handle
                    if service_uuid.type == UUID.TYPE_16:
                        attr.value = pack("<H", included_service_att_handle) + pack("<H",
                                                                                    end_group_handle) + attr.service_uuid.packed
                    else:
                        attr.value = pack("<H", included_service_att_handle) + pack("<H", end_group_handle)
        else:
            for service in self.services:
                self.db.attributes[service.handle] = service.generate_attribute()
                for incl in service.includes:
                    self.db.attributes[incl.handle] = incl.generate_attribute()
                for characteristic in service.characteristics:
                    self.db.attributes[
                        characteristic.declaration.handle] = characteristic.declaration.generate_attribute()
                    self.db.attributes[
                        characteristic.value_declaration.handle] = characteristic.value_declaration.generate_attribute()
                    for descriptor in characteristic.descriptors:
                        self.db.attributes[descriptor.handle] = descriptor.generate_attribute()

    def set_mtu(self, mtu):
        self.mtu = mtu

    def read(self, handle, connection_permission, is_connection_encrypted):
        log.debug("Reading value from handle: %s" % hex(handle))
        try:
            value = self.db.read(handle, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        log.debug("Value: %s, len: %d, mtu: %d" % (value, len(value), self.mtu))
        return (True, value[:self.mtu - 1])

    def read_blob(self, handle, offset, connection_permission, is_connection_encrypted):
        log.debug("Reading blob value from handle: %s" % hex(handle))
        try:
            value = self.db.read(handle, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)
        log.debug("Value: %s, len: %d, mtu: %d" % (value, len(value), self.mtu))

        offset_value = value[offset:(offset + (self.mtu - 1))]
        log.debug("Provided offset: %d Value to write: %s" % (offset, offset_value))

        return (True, offset_value)

    def read_multiple(self, handles, connection_permission, is_connection_encrypted):
        log.debug("Reading multiple")
        final_value = ""
        for handle in handles:
            handle = unpack("<H", handle)
            log.debug("Reading value from handle: %s" % hex(handle))
            try:
                value = self.db.read(handle, connection_permission, is_connection_encrypted)
            except (ATTInvalidHandleException, ATTReadNotPermittedException,
                    ATTWriteNotPermittedException, ATTInvalidPDUException,
                    ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                    ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                    ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                    ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                    ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                    ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                    ATTInsufficientResourcesException) as e:
                log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                    e.code, e.name, e.description
                ))
                return (False, e.code, handle)
            final_value += value
        return (True, final_value[:self.mtu - 1])

    def write(self, handle, data, connection_permission, is_connection_encrypted):
        try:
            success = self.db.write(handle, data, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        return True, ""

    def prepare_write(self, handle, offset, value, connection_permission, is_connection_encrypted):
        # TODO: Ensure write queue is wiped on device disconnect
        log.debug("Prepare write request for handle: %s offset: %d value: %s" % (
            hex(handle), offset, value
        ))
        try:
            self.db.prepare_write(handle, offset, value, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)
        resp_body = ""
        print handle
        print offset
        print value
        resp_body += pack('<H', handle)
        resp_body += pack('<H', offset)
        resp_body += value
        print "returning success"
        return (True, resp_body)

    def execute_write(self, flags):
        try:
            self.db.execute_write(flags)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        return (True, "")

    def signed_write_command(self):
        # TODO
        return

    def read_by_type(self, start, end, uuid, connection_permission, is_connection_encrypted):
        try:
            resp = self.db.read_by_type(start, end, uuid, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        value_len = None
        total_len = 2
        response_body = []
        for r in resp:
            (handle, value) = r
            if value_len is not None and len(value) != value_len:
                break
            # TODO handle MTU larger than 256+4 (length is a single byte)
            value_len = min(len(value), self.mtu - 4)  # 4 = 2 + an extra 2 for the handle
            response_body.append(pack('<H', handle))
            response_body.append(value[:value_len])
            total_len += value_len + 2
            if total_len >= self.mtu:
                break
        return (True, ''.join((chr(value_len + 2), ''.join(response_body))))

    def find_information(self, start, end):
        try:
            resp = self.db.find_information(start, end)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        response_body = []
        uuid_type = None
        total_len = 2

        for r in resp:
            (handle, uuid) = r

            if uuid_type is None:
                uuid_type = uuid.type
                # hack: we know that uuid_type is the value the spec expects
                response_body.append(chr(uuid_type))
            if uuid.type != uuid_type:
                break

            if total_len + 2 + len(uuid.packed) > self.mtu:
                break

            response_body.append(pack('<H', handle))
            response_body.append(uuid.packed)
            total_len += 2 + len(uuid.packed)

        return (True, ''.join(response_body))

    def find_by_type_value(self, start, end, uuid, value):
        try:
            resp = self.db.find_by_type_value(start, end, uuid, value)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        response_body = []
        total_len = 1

        for r in resp:
            (handle, end) = r
            if total_len + 4 > self.mtu:
                break
            response_body.append(pack('<H', handle))
            response_body.append(pack('<H', end))
            total_len += 4
        return (True, ''.join(response_body))

    def read_by_group_type(self, start, end, uuid, connection_permission, is_connection_encrypted):
        try:
            resp = self.db.read_by_group_type(start, end, uuid, connection_permission, is_connection_encrypted)
        except (ATTInvalidHandleException, ATTReadNotPermittedException,
                ATTWriteNotPermittedException, ATTInvalidPDUException,
                ATTInsufficientAuthenticationException, ATTRequestNotSupportedException,
                ATTInvalidOffsetException, ATTInsufficientAuthorizationException,
                ATTPrepareQueueFullException, ATTAttributeNotFoundException,
                ATTAttributeNotLongException, ATTInsufficientEncryptionKeySizeException,
                ATTInvalidAttributeValueLengthException, ATTUnlikelyErrorException,
                ATTInsufficientEncryptionException, ATTUnsupportedGroupTypeException,
                ATTInsufficientResourcesException) as e:
            log.debug("Caught ATT operation error. Code: %d Name: %s Description: %s" % (
                e.code, e.name, e.description
            ))
            return (False, e.code)

        response_body = []
        total_len = 0
        value_len = None
        for r in resp:
            (start, end, value) = r
            if value_len is None:
                value_len = min(4 + len(value), self.mtu - 2)
                response_body.append(chr(value_len))
            this_len = min(4 + len(value), self.mtu - 2)
            if this_len != value_len or total_len + value_len > self.mtu:
                break

            response_body.append(pack('<H', start))
            response_body.append(pack('<H', end))
            response_body.append(value[:value_len - 4])
            total_len += value_len

        return (True, ''.join(response_body))


class UUID:
    TYPE_16 = 1
    TYPE_128 = 2

    uuid = None
    packed = None
    type = None

    def __init__(self, uuid):
        if isinstance(uuid, UUID):
            self.uuid = uuid.uuid
            self.packed = uuid.packed
            self.type = uuid.type

        # integer
        elif isinstance(uuid, int):
            if 0 <= uuid <= 65536:
                self.uuid = '%04X' % uuid
                self.packed = pack('<h', uuid)
                self.type = UUID.TYPE_16
            elif 0 <= uuid <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
                self.uuid = '%032X' % uuid
                # modified solution from http://www.codegur.site/6877096/how-to-pack-a-uuid-into-a-struct-in-python
                self.packed = pack('<QQ', uuid & 0xFFFFFFFFFFFFFFFF, (uuid >> 64) & 0xFFFFFFFFFFFFFFFF)
                self.type = UUID.TYPE_128

        elif len(uuid) == 4:
            self.uuid = uuid
            self.packed = uuid.decode("hex")[::-1]
            self.type = UUID.TYPE_16
        elif len(uuid) == 36:
            temp = uuid.translate(None, "-")

            if len(temp) == 32:
                self.uuid = uuid
                self.packed = temp.decode("hex")[::-1]
                self.type = UUID.TYPE_128
        elif len(uuid) == 32 and "-" not in uuid:
            self.uuid = '-'.join((uuid[:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:]))
            self.packed = uuid.decode("hex")[::-1]
            self.type = UUID.TYPE_128
        # binary
        elif len(uuid) == 2:
            self.uuid = '%04X' % unpack('<h', uuid)[0]
            self.packed = uuid
            self.type = UUID.TYPE_16
        elif len(uuid) == 16:
            r = uuid[::-1]
            self.uuid = '-'.join(map(lambda x: hexlify(x), (r[0:4], r[4:6], r[6:8], r[8:10], r[10:])))
            self.packed = uuid
            self.type = UUID.TYPE_128

        if self.uuid is None:
            raise InvalidUUIDException(uuid)

    def __eq__(self, other):
        # TODO expand 16 bit UUIDs
        return self.packed == other.packed

    def __repr__(self):
        return self.uuid


ATT_SECURITY_MODE_NO_ACCESS = SecurityMode(0, 0)
ATT_SECURITY_MODE_OPEN = SecurityMode(1, 1)
ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION = SecurityMode(1, 2)
ATT_SECURITY_MODE_ENCRYPTION_WITH_AUTHENTICATION = SecurityMode(1, 3)
ATT_SECURITY_MODE_ENCRYPTION_WITH_SECURE_CONNECTIONS = SecurityMode(1, 4)


class Attribute:

    def __init__(self, uuid, properties, sec_mode_read, sec_mode_write, require_authorization, value):
        self.uuid = uuid
        self.properties = properties
        self.sec_mode_read = sec_mode_read
        self.sec_mode_write = sec_mode_write
        self.require_authorization = require_authorization
        self.value = value

    def __repr__(self):
        return "%s: '%s'" % (self.uuid, ' '.join(x.encode('hex') for x in self.value))


class GATTService:

    def __init__(self, attribute_type, uuid, attribute_properties=ATT_PROP_READ,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.value = None
        self.start = None
        self.end = None
        self.attribute_type = attribute_type
        self.uuid = uuid
        self.value = uuid
        self.includes = []
        self.characteristics = []
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def add_include(self, include):
        self.includes.append(include)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def generate_and_add_characteristic(self, value, characteristic_value_properties,
                                        characteristic_uuid, characteristic_value_attribute_properties,
                                        characteristic_value_attribute_read_permission,
                                        characteristic_value_attribute_write_permission,
                                        characteristic_value_require_authorization):
        characteristic = GATTCharacteristic(value, characteristic_value_properties, characteristic_uuid,
                                            characteristic_value_attribute_properties,
                                            characteristic_value_attribute_read_permission,
                                            characteristic_value_attribute_write_permission,
                                            characteristic_value_require_authorization)
        self.characteristics.append(characteristic)
        return characteristic

    def generate_and_add_include(self, service):
        include = GATTInclude(0x00, 0x00, service.uuid)  # We update these values when we add services to the DB
        self.includes.append(include)
        return include

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.uuid.packed)


class GATTInclude:

    def __init__(self, included_service_att_handle, end_group_handle, service_uuid,
                 attribute_properties=ATT_PROP_READ,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.included_service_att_handle = included_service_att_handle
        self.end_group_handle = end_group_handle
        self.service_uuid = service_uuid
        self.handle = None
        self.attribute_type = UUID("2802")
        self.attribute_properties = attribute_properties  # ATT_PERM_READ_ONLY
        self.attribute_read_permission = attribute_read_permission  # ATT_PERM_NO_AUTHENTICATION | ATT_PERM_NO_AUTHORIZATION
        self.attribute_write_permission = attribute_write_permission  # Not writeable
        self.value = None
        self.require_authorization = require_authorization
        # only include service UUID in value if it's a 16-bit UUID
        if self.service_uuid.type == UUID.TYPE_16:
            self.value = pack("<H", self.included_service_att_handle) + pack("<H",
                                                                             self.end_group_handle) + self.service_uuid.packed
        else:
            self.value = pack("<H", self.included_service_att_handle) + pack("<H", self.end_group_handle)

    def generate_attribute(self):
        if self.service_uuid.type == UUID.TYPE_16:
            self.value = pack("<H", self.included_service_att_handle) + pack("<H",
                                                                             self.end_group_handle) + self.service_uuid.packed
        else:
            self.value = pack("<H", self.included_service_att_handle) + pack("<H", self.end_group_handle)
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristic:

    def __init__(self, value, characteristic_properties, characteristic_uuid, characteristic_value_attribute_properties,
                 characteristic_value_attribute_read_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 characteristic_value_attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.descriptors = []
        # ex: GATT_PROP_READ (these are properties set by the user for the server, ATT enforces whether the value
        # can be read or written to by using the attribute properties. The GATT characteristic properties are
        # just a way to inform the client connected to us of how they can expect to access the value (the operations)
        self.characteristic_properties = characteristic_properties
        self.characteristic_uuid = characteristic_uuid
        self.characteristic_value_attribute_properties = characteristic_value_attribute_properties
        self.characteristic_value_attribute_read_permission = characteristic_value_attribute_read_permission
        self.characteristic_value_attribute_write_permission = characteristic_value_attribute_write_permission
        self.require_authorization = require_authorization
        self.declaration = GATTCharacteristicDeclaration(characteristic_properties, 0x00, characteristic_uuid)
        self.value_declaration = GATTCharacteristicValueDeclaration(characteristic_uuid, value,
                                                                    characteristic_value_attribute_properties,
                                                                    characteristic_value_attribute_read_permission,
                                                                    characteristic_value_attribute_write_permission,
                                                                    require_authorization)

    def generate_and_add_user_description_descriptor(self, name):
        descriptor = GATTCharacteristicUserDescription(name, ATT_PROP_READ,
                                                       ATT_SECURITY_MODE_OPEN, ATT_SECURITY_MODE_NO_ACCESS, False)
        self.descriptors.append(descriptor)
        return descriptor

    def generate_and_add_client_characteristic_configuration_descriptor(self, value="\x00\x00"):
        descriptor = GATTCharacteristicClientCharacteristicConfiguration(value)
        self.descriptors.append(descriptor)
        return descriptor

    def generate_and_add_server_characteristic_configuration_descriptor(self, value="\x00"):
        descriptor = GATTCharacteristicServerCharacteristicConfiguration(value)
        self.descriptors.append(descriptor)
        return descriptor

    def generate_and_add_exented_properties_descriptor(self, value):
        descriptor = GATTCharacteristicExtendedProperties(value)
        self.descriptors.append(descriptor)
        return descriptor

    def generate_and_add_descriptor(self, attribute_type, value, attribute_properties,
                                    attribute_read_permissions, attribute_write_permissions, require_authorization,):
        descriptor = GATTCharacteristicDescriptorDeclaration(attribute_type, value, attribute_properties,
                                                             attribute_read_permissions, attribute_write_permissions,
                                                             require_authorization)
        self.descriptors.append(descriptor)
        return descriptor

    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)


class GATTCharacteristicDeclaration:

    def __init__(self, characteristic_properties, value_attribute_handle, characteristic_uuid,
                 attribute_properties=ATT_PROP_READ,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = UUID("2803")
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization
        self.characteristic_properties = characteristic_properties
        self.value_attribute_handle = value_attribute_handle
        self.characteristic_uuid = characteristic_uuid
        # properties (8 bits) + value handle (16 bits) + uuid (16 bits or 128 bit)
        self.value = pack("<B", self.characteristic_properties) + pack("<H",
                                                                       self.value_attribute_handle) + self.characteristic_uuid.packed

    def generate_attribute(self):
        self.value = pack("<B", self.characteristic_properties) + pack("<H",
                                                                       self.value_attribute_handle) + self.characteristic_uuid.packed
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristicValueDeclaration:

    def __init__(self, attribute_type, value, attribute_properties,
                 attribute_read_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = attribute_type
        if value is None:
            value = ""
        self.value = value
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


# Generic descriptor class, can be used to create any descriptor
class GATTCharacteristicDescriptorDeclaration:

    def __init__(self, attribute_type, value, attribute_properties, attribute_read_permission,
                 attribute_write_permission, require_authorization):
        self.handle = None
        self.attribute_type = attribute_type
        if value is None:
            value = ""
        self.value = value
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristicExtendedProperties:

    def __init__(self, value, attribute_properties=ATT_PROP_READ,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = UUID("2900")
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization
        if value is None:
            value = ""
        self.value = value

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristicUserDescription:

    def __init__(self, value, attribute_properties,
                 attribute_read_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = UUID("2901")
        if value is None:
            value = ""
        self.value = value
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristicClientCharacteristicConfiguration:

    def __init__(self, value, attribute_properties=ATT_PROP_READ | ATT_PROP_WRITE,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_OPEN,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = UUID("2902")
        if value is None:
            value = ""
        self.value = value
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class GATTCharacteristicServerCharacteristicConfiguration:

    def __init__(self, value, attribute_properties=ATT_PROP_READ | ATT_PROP_WRITE,
                 attribute_read_permission=ATT_SECURITY_MODE_OPEN,
                 attribute_write_permission=ATT_SECURITY_MODE_NO_ACCESS,
                 require_authorization=False):
        self.handle = None
        self.attribute_type = UUID("2903")
        if value is None:
            value = "\x00"
        self.value = value  # 0x0001 - to enable broadcasting
        self.attribute_properties = attribute_properties
        self.attribute_read_permission = attribute_read_permission
        self.attribute_write_permission = attribute_write_permission
        self.require_authorization = require_authorization

    def generate_attribute(self):
        return Attribute(self.attribute_type, self.attribute_properties, self.attribute_read_permission,
                         self.attribute_write_permission, self.require_authorization, self.value)


class AttributeDatabase:

    # we use an ordered dictionary here so we can guarantee our
    # attributes that are inserted maintain the order we placed them in
    # The idea is that we order the attribute db as: service1 | char1 | desc1 | service2 | etc..
    def __init__(self, event_handler=None):
        self.attributes = OrderedDict()
        # handle:<string>, handle2:<string2>
        self.prepared_write_queue = {}
        self.att_security_hooks = event_handler

    def set_att_security_hook(self, att_security_hook_class):
        self.att_security_hooks = att_security_hook_class

    def att_authorization_check(self, att_opcode, uuid, att_property,
                                att_read_permission, att_write_permission,
                                connection_permission, require_authorization):
        if self.att_security_hooks is None:
            check_passed = True
        else:
            check_passed = self.att_security_hooks.att_authorization_check_hook(att_opcode, uuid,
                                                                                att_property,
                                                                                att_read_permission,
                                                                                att_write_permission,
                                                                                connection_permission,
                                                                                require_authorization)
        return check_passed

    def att_authentication_check(self, att_opcode, uuid, att_property, att_read_permission,
                                 att_write_permission, connection_permission):
        check_passed = True
        if att_opcode & ATT_PROP_READ == ATT_PROP_READ:
            # Client is requesting a read operation
            if att_read_permission.security_mode == 1 and att_read_permission.security_level == 4:
                # Attribute requires LE Secure Connections pairing, so connection MUST have
                # Security Mode 1 Level 4
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() != 4:
                    check_passed = False
            elif att_read_permission.security_mode == 1 and att_read_permission.security_level == 3:
                # Attribute requires authentication
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() < 3:
                    # Connection must be security Mode 1 with level 3 or greater (authenticated or secure connections)
                    check_passed = False
            elif att_read_permission.security_mode == 0:
                check_passed = False
                log.debug("Read security mode of attribute set to 0, meaning no access")
            elif att_read_permission.security_mode == 2:
                check_passed = False
                log.debug("Read security mode of attribute set to 2, data signing not currently supported")

        if att_opcode & ATT_PROP_WRITE == ATT_PROP_WRITE:
            # Client is requesting a write operation
            if att_write_permission.security_mode == 1 and att_write_permission.security_level == 4:
                # Attribute requires LE Secure Connections pairing, so connection MUST have
                # Security Mode 1 Level 4
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() != 4:
                    check_passed = False
            elif att_write_permission.security_mode == 1 and att_write_permission.security_level == 3:
                # Attribute requires authentication
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() < 3:
                    # Connection must be security Mode 1 with level 3 or greater (authenticated or secure connections)
                    check_passed = False
            elif att_write_permission.security_mode == 0:
                check_passed = False
                log.debug("Write security mode of attribute set to 0, meaning no access")
            elif att_write_permission.security_mode == 2:
                check_passed = False
                log.debug("Write security mode of attribute set to 2, data signing not currently supported")

        if self.att_security_hooks is not None:
            check_passed = self.att_security_hooks.att_authentication_check_hook(check_passed,
                                                                                 att_opcode, uuid,
                                                                                 att_property,
                                                                                 att_read_permission,
                                                                                 att_write_permission,
                                                                                 connection_permission)
        return check_passed

    def att_encryption_check(self, att_opcode, uuid, att_property, att_read_permission,
                             att_write_permission, connection_permission, is_connection_encrypted):
        log.debug("ATT Encryption Check. Att_opcode: %d UUID: %s ATT_Property: %d ATT Read Permissions Mode: "
                  "%d Level: %d ATT Write Permission Mode: %d Level: %d Connection Security Mode: %d "
                  "Level: %d Is Connection Encrypted?: %s" % (att_opcode, uuid, att_property,
                                                              att_read_permission.security_mode,
                                                              att_read_permission.security_level,
                                                              att_write_permission.security_mode,
                                                              att_write_permission.security_level,
                                                              connection_permission.get_security_mode_mode(),
                                                              connection_permission.get_security_mode_level(),
                                                              is_connection_encrypted))
        check_passed = True

        if att_opcode & ATT_PROP_READ == ATT_PROP_READ:
            # Client is requesting a read operation
            if att_read_permission.security_mode == 1 and att_read_permission.security_level > 1:
                # Attribute requires encryption
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() < 2:
                    # Connection is not security mode 1 or has security mode 1, but less than level 2
                    check_passed = False
                if not is_connection_encrypted:
                    check_passed = False

        if att_opcode & ATT_PROP_WRITE == ATT_PROP_WRITE:
            # Client is requesting a write operation
            if att_write_permission.security_mode == 1 and att_write_permission.security_level > 1:
                # Attribute requires encryption
                if connection_permission.get_security_mode_mode() != 1 or \
                        connection_permission.get_security_mode_level() < 2:
                    # Connection is not security mode 1 or has security mode 1, but less than level 2
                    check_passed = False
                if not is_connection_encrypted:
                    check_passed = False

        if self.att_security_hooks is not None:
            check_passed = self.att_security_hooks.att_authentication_check_hook(check_passed,
                                                                                 att_opcode, uuid,
                                                                                 att_property,
                                                                                 att_read_permission,
                                                                                 att_write_permission,
                                                                                 connection_permission)
        return check_passed

    def att_operation_supported_check(self, att_opcode, uuid, att_property):
        check_passed = True
        log.debug("ATT Operation supported by attribute check initialized. ATT Opcode: %d, UUID: %s, att_property: %d"%
                  (att_opcode, uuid, att_property))
        if att_opcode & ATT_PROP_READ == ATT_PROP_READ:
            # Client is requesting a read operation
            if att_property & ATT_PROP_READ != ATT_PROP_READ:
                # Attribute does not have read property set
                check_passed = False

        if att_opcode & ATT_PROP_WRITE == ATT_PROP_WRITE:
            # Client is requesting a write operation
            if att_property & ATT_PROP_WRITE != ATT_PROP_WRITE:
                # Attribute does not have read property set
                check_passed = False

        if self.att_security_hooks is not None:
            check_passed = self.att_security_hooks.att_operation_supported_check_hook(check_passed,
                                                                                      att_opcode,
                                                                                      uuid,
                                                                                      att_property)

        return check_passed

    # Client is requesting a write operation

    def att_security_checks(self, att_opcode, uuid, att_property,
                            att_read_permission, att_write_permission,
                            connection_permission, require_authorization, is_connection_encrypted):
        operation_supported_check_passed_result = self.att_operation_supported_check(att_opcode, uuid,
                                                                                     att_property)

        authz_check_passed_result = self.att_authorization_check(att_opcode, uuid,
                                                                 att_property,
                                                                 att_read_permission, att_write_permission,
                                                                 connection_permission, require_authorization)
        # TODO: Insufficient encryption key size check
        encryption_check_passed_result = self.att_encryption_check(att_opcode, uuid,
                                                                   att_property,
                                                                   att_read_permission, att_write_permission,
                                                                   connection_permission, is_connection_encrypted)
        authn_check_passed_result = self.att_authentication_check(att_opcode, uuid,
                                                                  att_property,
                                                                  att_read_permission, att_write_permission,
                                                                  connection_permission)
        if self.att_security_hooks is not None:
            operation_supported_check_passed_result, \
            authz_check_passed_result, \
            encryption_check_passed_result, \
            authn_check_passed_result = self.att_security_hooks.att_security_check_hook(
                operation_supported_check_passed_result,
                authz_check_passed_result,
                encryption_check_passed_result,
                authn_check_passed_result,
                att_opcode, uuid, att_property,
                att_read_permission,
                att_write_permission,
                connection_permission, require_authorization, is_connection_encrypted)
        if not operation_supported_check_passed_result:
            if att_opcode & ATT_PROP_READ == ATT_PROP_READ:
                raise ATTReadNotPermittedException
            else:
                raise ATTWriteNotPermittedException
        elif not authz_check_passed_result:
            raise ATTInsufficientAuthorizationException
        elif not encryption_check_passed_result:
            raise ATTInsufficientEncryptionException
        elif not authn_check_passed_result:
            raise ATTInsufficientAuthenticationException
        return True

    def attribute(self, uuid_str, permissions, value):
        uuid = UUID(uuid_str)
        attr = Attribute(uuid, permissions, value)
        self.attributes.append(attr)

    def add_attribute(self, attribute, handle):
        self.attributes[handle] = attribute

    def manually_set_attribute_db_dict(self, attribute_dictionary):
        self.attributes = attribute_dictionary

    def __repr__(self):
        a = []
        for i in range(0, len(self.attributes)):
            a.append('%x - %s' % (i + 1, self.attributes[i]))
        return '\n'.join(a)

    def read(self, handle, connection_permission, is_connection_encrypted):
        attr = None
        if handle in self.attributes.keys():
            attr = self.attributes[handle]
            self.att_security_checks(ATT_PROP_READ, handle, attr.properties,
                                     attr.sec_mode_read, attr.sec_mode_write,
                                     connection_permission, attr.require_authorization, is_connection_encrypted)
            return attr.value
        raise ATTInvalidHandleException

    # TODO: Allow user controlled maximum value for queued data to prevent resource exhaustion
    def prepare_write(self, handle, offset, data, connection_permission, is_connection_encrypted):
        # need authn and authz checks here
        if handle in self.attributes.keys():
            attr = self.attributes[handle]
            self.att_security_checks(ATT_PROP_WRITE, handle, attr.properties,
                                     attr.sec_mode_read, attr.sec_mode_write,
                                     connection_permission, attr.require_authorization, is_connection_encrypted)
            if handle in self.prepared_write_queue.keys():
                value = self.prepared_write_queue[handle]
                if offset > len(value):
                    raise ATTInvalidOffsetException
                # allows writes based on offset to existing values. We also allow overwriting
                # of data existing at offset.
                new_value = value[:offset] + data + value[offset + len(data):]
                self.prepared_write_queue[handle] = new_value
            else:
                self.prepared_write_queue[handle] = data
        else:
            raise ATTInvalidHandleException
        return None

    def execute_write(self, action):
        # in the spec there are some checks here to make sure the attribute value (if there's
        # one set), it needs to be validated, but I don't want to limit it.
        if action == 0x00:
            self.prepared_write_queue = {}
        elif action == 0x01:
            for handle in self.prepared_write_queue.keys():
                self.attributes[handle].value = self.prepared_write_queue[handle]
            self.prepared_write_queue = {}

    def write(self, handle, data, connection_permission, is_connection_encrypted):
        # TODO: Allow user to set maximum value size for attributes?
        success = True
        if handle in self.attributes.keys():
            attr = self.attributes[handle]
            self.att_security_checks(ATT_PROP_WRITE, handle, attr.properties,
                                     attr.sec_mode_read, attr.sec_mode_write,
                                     connection_permission, attr.require_authorization, is_connection_encrypted)
            self.attributes[handle].value = data
            return success
        else:
            raise ATTInvalidHandleException

    def read_by_type(self, start, end, uuid_str, connection_permission, is_connection_encrypted):
        if start > end or start == 0x0000:
            raise ATTInvalidHandleException
        resp = []
        uuid = UUID(uuid_str)
        attr_handles = self.attributes.keys()
        for i in range(start, end + 1):
            if i in attr_handles:
                attr = self.attributes[i]
                if attr.uuid == uuid:
                    self.att_security_checks(ATT_PROP_READ, uuid, attr.properties,
                                             attr.sec_mode_read, attr.sec_mode_write,
                                             connection_permission, attr.require_authorization, is_connection_encrypted)
                    resp.append((i, attr.value))
        if len(resp) == 0:
            raise ATTAttributeNotFoundException
        return resp

    def find_information(self, start, end):
        if start > end or start == 0x0000:
            raise ATTInvalidHandleException
        resp = []
        attr_handles = self.attributes.keys()
        for i in range(start, end + 1):
            if i in attr_handles:
                resp.append((i, self.attributes[i].uuid))
        if len(resp) == 0:
            raise ATTAttributeNotFoundException
        return resp

    def find_by_type_value(self, start, end, uuid_str, value):
        if start > end or start == 0x0000:
            raise ATTInvalidHandleException
        resp = []
        uuid = UUID(uuid_str)
        attr_handles = self.attributes.keys()
        for i in range(start, end + 1):
            if i in attr_handles:
                attr = self.attributes[i]
                if attr.uuid == uuid and attr.value == value:
                    max_handle = i
                    end_of_service = None
                    previous_item = None
                    for j in range(i + 1, end + 1):
                        if j in attr_handles:
                            if self.attributes[j].uuid == uuid:
                                end_of_service = previous_item
                                break
                            previous_item = j
                    if end_of_service is None:
                        end_of_service = 0xffff
                    resp.append((i, end_of_service))
        if len(resp) == 0:
            raise ATTAttributeNotFoundException
        return resp

    def read_by_group_type(self, start, end, uuid_str, connection_permission, is_connection_encrypted):
        if start > end or start == 0x0000:
            raise ATTInvalidHandleException
        resp = []
        uuid = UUID(uuid_str)
        log.debug("AttributeDB - Received read by group type request. start: %d, end: %d, uuid: %s" %
                  (start, end, pack(">H", uuid_str).encode('hex')))
        attr_handles = self.attributes.keys()
        for i in range(start, end + 1):
            if i in attr_handles:
                attr = self.attributes[i]
                if attr.uuid == uuid:
                    self.att_security_checks(ATT_PROP_READ, uuid, attr.properties,
                                             attr.sec_mode_read, attr.sec_mode_write,
                                             connection_permission, attr.require_authorization, is_connection_encrypted)
                    max_handle = i
                    end_of_service = None
                    previous_item = None
                    for j in range(i + 1, end + 1):
                        if j in attr_handles:
                            if self.attributes[j].uuid == uuid:
                                end_of_service = previous_item
                                break
                            previous_item = j
                    if end_of_service is None:
                        end_of_service = 0xffff
                    resp.append((i, end_of_service, self.attributes[i].value))
        if len(resp) == 0:
            raise ATTAttributeNotFoundException
        return resp

    def debug_print_db(self):

        print "Attribute Database"
        print "Handle\t| Attribute Data"
        print "=================="
        for key in self.attributes.keys():
            att = self.attributes[key]
            print str(key) + "\t " + str(att.uuid.uuid) + str(att.uuid.packed).encode('hex')
            print "\t " + "properties: " + hex(att.properties)
            print "\t " + "read security mode: ", att.sec_mode_read.security_mode, " level: ", att.sec_mode_read.security_level
            print "\t " + "write security mode: ", att.sec_mode_write.security_mode, " level: ", att.sec_mode_write.security_level
            print "\t " + "authz required: ", att.require_authorization
            print "\t " + "value: ", repr(att.value), "hex encoded: ", str(att.value).encode('hex')
